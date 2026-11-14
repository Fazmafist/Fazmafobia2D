"use strict";
const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const rooms = new Map();

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) { res.writeHead(500); res.end('index.html not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
  } else { res.writeHead(404); res.end('Not found'); }
});

const wss = new WebSocketServer({ server });

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
  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch (e) { return; }
    const t = msg.type;
    if (t === 'create-room') {
      const code = genCode();
      ws.roomCode = code;
      const room = { code, mode: msg.mode, hostId: ws.id, players: [{ id: ws.id, name: msg.name || 'Host', isHost: true }], gameStarted: false };
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
      const player = { id: ws.id, name: msg.name || 'Player', isHost: false };
      room.players.push(player);
      broadcast(room, { type: 'player-joined', id: ws.id, name: player.name, players: room.players }, ws.id);
      sendRaw(ws, { type: 'joined', code: msg.code, id: ws.id, mode: room.mode, players: room.players, hostId: room.hostId });
      return;
    }
    if (t === 'start-game') {
      const room = rooms.get(ws.roomCode);
      if (!room || room.hostId !== ws.id) return;
      room.gameStarted = true;
      broadcast(room, { type: 'game-started' });
      return;
    }
    if (t === 'player-move' || t === 'ghost-move' || t === 'evidence' || t === 'event' || t === 'chat') {
      const room = rooms.get(ws.roomCode);
      if (!room) return;
      if (t === 'chat') {
        const p = room.players.find(x => x.id === ws.id);
        msg.name = p ? p.name : 'Player';
        broadcast(room, msg);
      } else {
        broadcast(room, Object.assign({ id: ws.id }, msg), ws.id);
      }
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