"use strict";
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CODES_FILE = path.join(DATA_DIR, 'promocodes.json');
const SESSION_TTL = 30 * 24 * 3600 * 1000; // 30 дней
const ADMIN_KEY = process.env.ADMIN_KEY || 'IVANFAZMA2026!';

/* ===== ХРАНИЛИЩЕ В /data ===== */
fs.mkdirSync(DATA_DIR, { recursive: true });

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}
// атомарная запись: temp + rename, чтобы обрыв не портил файл
function writeJson(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}

const users = readJson(USERS_FILE, { nextId: 1, list: [], sessions: {} });
let codes = readJson(CODES_FILE, { list: [] });
if (!Array.isArray(codes.list)) codes = { list: [] };

function saveUsers() { writeJson(USERS_FILE, users); }
function saveCodes() { writeJson(CODES_FILE, codes); }

/* ===== ХЕШИРОВАНИЕ / ТОКЕНЫ ===== */
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}
function createSession(userId) {
  const token = genToken();
  const now = Date.now();
  users.sessions[token] = { userId, createdAt: now, expiresAt: now + SESSION_TTL };
  for (const t of Object.keys(users.sessions)) {
    if (users.sessions[t].expiresAt <= now) delete users.sessions[t];
  }
  saveUsers();
  return token;
}
function getUserByToken(token) {
  if (!token) return null;
  const s = users.sessions[token];
  if (!s || s.expiresAt <= Date.now()) return null;
  return users.list.find(u => u.id === s.userId) || null;
}
function getUserByUsername(username) {
  const n = String(username || '').toLowerCase();
  return users.list.find(u => u.username.toLowerCase() === n) || null;
}
function publicUser(u) {
  return { id: u.id, username: u.username, canCheat: !!u.canCheat, isAdmin: !!u.isAdmin, money: Number(u.money) || 0 };
}

/* ===== ПРОМОКОДЫ ===== */
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // без похожих 0/O, 1/I
function genPromoCode(len) {
  const n = len || 8;
  let out = '';
  const bytes = crypto.randomBytes(n);
  for (let i = 0; i < n; i++) out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return out;
}
function normalizeCode(s) {
  return String(s || '').trim().toUpperCase();
}

/* ===== HTTP ===== */
const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) { res.writeHead(500); res.end('index.html not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
  } else { res.writeHead(404); res.end('Not found'); }
});

/* ===== WEBSOCKET ===== */
const wss = new WebSocketServer({ server });
const rooms = new Map();

function genCode() {
  let c;
  do { c = Math.random().toString(36).substring(2, 7).toUpperCase(); } while (rooms.has(c));
  return c;
}
function sendRaw(ws, obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }
function broadcast(room, obj, exceptId) {
  const data = JSON.stringify(obj);
  for (const p of room.players) {
    if (p.id === exceptId) continue;
    for (const c of wss.clients) {
      if (c.id === p.id && c.readyState === 1) { c.send(data); break; }
    }
  }
}

wss.on('connection', (ws) => {
  ws.id = Math.random().toString(36).substring(2, 10);
  ws.roomCode = null;
  ws.userId = null;
  ws.username = null;
  ws.canCheat = false;
  ws.isAdmin = false;
  sendRaw(ws, { type: 'auth-required' });

  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch (e) { return; }
    const t = msg.type;

    /* ===== AUTH ===== */
    if (t === 'auth') {
      const u = getUserByToken(msg.token);
      if (u) {
        ws.userId = u.id; ws.username = u.username;
        ws.canCheat = !!u.canCheat; ws.isAdmin = !!u.isAdmin;
        sendRaw(ws, { type: 'auth-ok', user: publicUser(u) });
      } else {
        sendRaw(ws, { type: 'auth-fail' });
      }
      return;
    }

    if (t === 'register') {
      const username = (msg.username || '').trim();
      const password = msg.password || '';
      if (username.length < 3 || username.length > 20) return sendRaw(ws, { type: 'register-fail', msg: 'Имя: 3–20 символов' });
      if (!/^[a-zA-Zа-яА-Я0-9_\-]+$/.test(username)) return sendRaw(ws, { type: 'register-fail', msg: 'Только буквы, цифры, _ -' });
      if (password.length < 4) return sendRaw(ws, { type: 'register-fail', msg: 'Пароль: минимум 4' });
      if (getUserByUsername(username)) return sendRaw(ws, { type: 'register-fail', msg: 'Имя занято' });
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword(password, salt);
      const isFirst = String(msg.adminKey || '') === ADMIN_KEY;
      const u = {
        id: users.nextId++,
        username,
        passwordHash: hash,
        salt,
        canCheat: isFirst ? 1 : 0,
        isAdmin: isFirst ? 1 : 0,
        money: 0,
        usedCodes: [],
        createdAt: Date.now()
      };
      users.list.push(u);
      saveUsers();
      const token = createSession(u.id);
      ws.userId = u.id; ws.username = u.username; ws.canCheat = !!u.canCheat; ws.isAdmin = !!u.isAdmin;
      sendRaw(ws, { type: 'auth-ok', token, user: publicUser(u), isFirst });
      return;
    }

    if (t === 'login') {
      const username = (msg.username || '').trim();
      const password = msg.password || '';
      const u = getUserByUsername(username);
      if (!u) return sendRaw(ws, { type: 'login-fail', msg: 'Неверные имя или пароль' });
      if (hashPassword(password, u.salt) !== u.passwordHash) return sendRaw(ws, { type: 'login-fail', msg: 'Неверные имя или пароль' });
      const token = createSession(u.id);
      ws.userId = u.id; ws.username = u.username; ws.canCheat = !!u.canCheat; ws.isAdmin = !!u.isAdmin;
      sendRaw(ws, { type: 'auth-ok', token, user: publicUser(u) });
      return;
    }

    if (t === 'logout') {
      if (msg.token && users.sessions[msg.token]) { delete users.sessions[msg.token]; saveUsers(); }
      ws.userId = null; ws.username = null; ws.canCheat = false; ws.isAdmin = false;
      sendRaw(ws, { type: 'logged-out' });
      return;
    }

    if (t === 'check-cheat') {
      if (!ws.userId) return sendRaw(ws, { type: 'cheat-denied', reason: 'Требуется вход' });
      if (!ws.canCheat) return sendRaw(ws, { type: 'cheat-denied', reason: 'Нет прав на читы' });
      sendRaw(ws, { type: 'cheat-allowed' });
      return;
    }

    /* ===== ДЕНЬГИ (сервер — источник истины) ===== */
    if (t === 'spend-money') {
      const u = ws.userId ? users.list.find(x => x.id === ws.userId) : null;
      if (!u) return sendRaw(ws, { type: 'money-fail', msg: 'Требуется вход' });
      const cost = Math.max(0, Math.floor(Number(msg.cost) || 0));
      if ((Number(u.money) || 0) < cost) return sendRaw(ws, { type: 'money-fail', msg: 'Не хватает денег', money: Number(u.money) || 0 });
      u.money = (Number(u.money) || 0) - cost;
      saveUsers();
      sendRaw(ws, { type: 'money-ok', money: u.money });
      return;
    }

    /* ===== ПРОМОКОДЫ ===== */
    if (t === 'redeem-promo') {
      const u = ws.userId ? users.list.find(x => x.id === ws.userId) : null;
      if (!u) return sendRaw(ws, { type: 'promo-fail', msg: 'Требуется вход' });
      const code = normalizeCode(msg.code);
      const entry = codes.list.find(c => c.code === code);
      if (!entry) return sendRaw(ws, { type: 'promo-fail', msg: 'Такого промокода нет' });
      if (entry.uses >= entry.limit) return sendRaw(ws, { type: 'promo-fail', msg: 'Промокод уже полностью использован' });
      if (!Array.isArray(u.usedCodes)) u.usedCodes = [];
      if (u.usedCodes.includes(code)) return sendRaw(ws, { type: 'promo-fail', msg: 'Вы уже использовали этот промокод' });
      entry.uses += 1;
      u.usedCodes.push(code);
      u.money = (Number(u.money) || 0) + Number(entry.amount);
      saveCodes();
      saveUsers();
      sendRaw(ws, { type: 'promo-ok', amount: entry.amount, money: u.money });
      return;
    }

    /* ===== АДМИН ===== */
    if (t === 'admin-grant') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'admin-fail', msg: 'Только админ' });
      const target = getUserByUsername(msg.targetUsername);
      if (!target) return sendRaw(ws, { type: 'admin-fail', msg: 'Пользователь не найден' });
      target.canCheat = msg.canCheat ? 1 : 0;
      saveUsers();
      sendRaw(ws, { type: 'admin-ok', msg: target.username + ': читы ' + (target.canCheat ? 'РАЗРЕШЕНЫ' : 'ЗАПРЕЩЕНЫ') });
      return;
    }

    if (t === 'admin-list') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'admin-fail', msg: 'Только админ' });
      const list = users.list.map(u => ({ id: u.id, username: u.username, canCheat: !!u.canCheat, isAdmin: !!u.isAdmin, money: Number(u.money) || 0 }));
      sendRaw(ws, { type: 'admin-list', users: list });
      return;
    }

    if (t === 'promo-generate') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'promo-admin-fail', msg: 'Только админ' });
      const amount = Math.floor(Number(msg.amount));
      const count = Math.max(1, Math.min(100, Math.floor(Number(msg.count) || 1)));
      const limit = Math.max(1, Math.min(100000, Math.floor(Number(msg.limit) || 1)));
      if (!isFinite(amount) || amount <= 0) return sendRaw(ws, { type: 'promo-admin-fail', msg: 'Сумма должна быть больше 0' });
      const created = [];
      for (let i = 0; i < count; i++) {
        let code;
        do { code = genPromoCode(8); } while (codes.list.some(c => c.code === code));
        const entry = { code, amount, limit, uses: 0, createdBy: ws.username, createdAt: Date.now() };
        codes.list.push(entry);
        created.push(entry);
      }
      saveCodes();
      sendRaw(ws, { type: 'promo-created', codes: created });
      return;
    }

    if (t === 'promo-list') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'promo-admin-fail', msg: 'Только админ' });
      const list = codes.list.slice().sort((a, b) => b.createdAt - a.createdAt).slice(0, 200);
      sendRaw(ws, { type: 'promo-list', codes: list });
      return;
    }

    if (t === 'promo-delete') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'promo-admin-fail', msg: 'Только админ' });
      const code = normalizeCode(msg.code);
      const before = codes.list.length;
      codes.list = codes.list.filter(c => c.code !== code);
      if (codes.list.length === before) return sendRaw(ws, { type: 'promo-admin-fail', msg: 'Промокод не найден' });
      saveCodes();
      sendRaw(ws, { type: 'promo-deleted', code });
      return;
    }

    /* ===== ROOMS (требуется вход) ===== */
    if (!ws.userId) return sendRaw(ws, { type: 'error', msg: 'Требуется вход' });

    if (t === 'create-room') {
      const code = genCode();
      ws.roomCode = code;
      const room = {
        code, mode: msg.mode, hostId: ws.id,
        players: [{ id: ws.id, name: ws.username, isHost: true }],
        gameStarted: false
      };
      rooms.set(code, room);
      sendRaw(ws, { type: 'room-created', code, id: ws.id });
      return;
    }

    if (t === 'join-room') {
      const room = rooms.get(msg.code);
      if (!room) return sendRaw(ws, { type: 'error', msg: 'Комната не найдена' });
      if (room.gameStarted) return sendRaw(ws, { type: 'error', msg: 'Игра уже началась' });
      if (room.players.length >= 7) return sendRaw(ws, { type: 'error', msg: 'Комната полна' });
      ws.roomCode = msg.code;
      const player = { id: ws.id, name: ws.username, isHost: false };
      room.players.push(player);
      broadcast(room, { type: 'player-joined', id: ws.id, name: player.name, players: room.players }, ws.id);
      sendRaw(ws, { type: 'joined', code: msg.code, id: ws.id, mode: room.mode, players: room.players, hostId: room.hostId });
      return;
    }

    if (t === 'start-game') {
      const room = rooms.get(ws.roomCode);
      if (!room || room.hostId !== ws.id) return;
      room.gameStarted = true;
      broadcast(room, { type: 'game-started', state: msg.state || null });
      return;
    }

    /* ===== RELAY ===== */
    const room = rooms.get(ws.roomCode);
    if (!room) return;
    if (t === 'chat') {
      msg.name = ws.username || 'Player';
      broadcast(room, msg);
    } else {
      broadcast(room, Object.assign({ id: ws.id }, msg), ws.id);
    }
  });

  ws.on('close', () => {
    const room = rooms.get(ws.roomCode);
    if (!room) return;
    room.players = room.players.filter(p => p.id !== ws.id);
    if (room.players.length === 0) { rooms.delete(room.code); return; }
    if (room.hostId === ws.id) {
      room.hostId = room.players[0].id;
      room.players[0].isHost = true;
      broadcast(room, { type: 'host-changed', newHost: room.hostId });
    }
    broadcast(room, { type: 'player-left', id: ws.id, players: room.players });
  });
});

server.listen(PORT, () => console.log(`Phasmophobia 2D MP: http://localhost:${PORT} (данные: ${DATA_DIR})`));
