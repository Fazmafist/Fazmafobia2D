"use strict";
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'users.db');
const SESSION_TTL = 30 * 24 * 3600 * 1000; // 30 дней

/* ===== БАЗА ДАННЫХ ===== */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  can_cheat INTEGER DEFAULT 0,
  is_admin INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`);

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
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .run(token, userId, now, now + SESSION_TTL);
  return token;
}
function getUserByToken(token) {
  if (!token) return null;
  return db.prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'
  ).get(token, Date.now()) || null;
}
function getUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null;
}
function publicUser(u) {
  return { id: u.id, username: u.username, can_cheat: !!u.can_cheat, is_admin: !!u.is_admin };
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
        ws.canCheat = !!u.can_cheat; ws.isAdmin = !!u.is_admin;
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
      const isFirst = db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0;
      const now = Date.now();
      try {
        const info = db.prepare(
          'INSERT INTO users (username, password_hash, salt, can_cheat, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(username, hash, salt, isFirst ? 1 : 0, isFirst ? 1 : 0, now);
        const userId = info.lastInsertRowid;
        const token = createSession(userId);
        const u = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        ws.userId = u.id; ws.username = u.username; ws.canCheat = !!u.can_cheat; ws.isAdmin = !!u.is_admin;
        sendRaw(ws, { type: 'auth-ok', token, user: publicUser(u), isFirst });
      } catch (e) {
        console.error('register error:', e.message);
        sendRaw(ws, { type: 'register-fail', msg: 'Ошибка БД' });
      }
      return;
    }

    if (t === 'login') {
      const username = (msg.username || '').trim();
      const password = msg.password || '';
      const u = getUserByUsername(username);
      if (!u) return sendRaw(ws, { type: 'login-fail', msg: 'Неверные имя или пароль' });
      const hash = hashPassword(password, u.salt);
      if (hash !== u.password_hash) return sendRaw(ws, { type: 'login-fail', msg: 'Неверные имя или пароль' });
      const token = createSession(u.id);
      ws.userId = u.id; ws.username = u.username; ws.canCheat = !!u.can_cheat; ws.isAdmin = !!u.is_admin;
      sendRaw(ws, { type: 'auth-ok', token, user: publicUser(u) });
      return;
    }

    if (t === 'logout') {
      if (msg.token) db.prepare('DELETE FROM sessions WHERE token = ?').run(msg.token);
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

    if (t === 'admin-grant') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'admin-fail', msg: 'Только админ' });
      const target = getUserByUsername(msg.targetUsername);
      if (!target) return sendRaw(ws, { type: 'admin-fail', msg: 'Пользователь не найден' });
      const newVal = msg.canCheat ? 1 : 0;
      db.prepare('UPDATE users SET can_cheat = ? WHERE id = ?').run(newVal, target.id);
      sendRaw(ws, { type: 'admin-ok', msg: target.username + ': читы ' + (newVal ? 'РАЗРЕШЕНЫ' : 'ЗАПРЕЩЕНЫ') });
      return;
    }

    if (t === 'admin-list') {
      if (!ws.isAdmin) return sendRaw(ws, { type: 'admin-fail', msg: 'Только админ' });
      const users = db.prepare('SELECT id, username, can_cheat, is_admin FROM users ORDER BY id').all();
      sendRaw(ws, { type: 'admin-list', users });
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

server.listen(PORT, () => console.log(`Phasmophobia 2D MP: http://localhost:${PORT}`));
