'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ROOT = path.resolve(__dirname, '..');
const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml'
};

const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
    const file = path.join(ROOT, rel);
    if (file !== path.join(ROOT, 'index.html') && !file.startsWith(ROOT + path.sep)) {
        res.writeHead(403);
        res.end('Prohibido');
        return;
    }
    fs.readFile(file, (err, buf) => {
        if (err) {
            res.writeHead(404);
            res.end('No encontrado');
            return;
        }
        res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
        res.end(buf);
    });
});

const wss = new WebSocketServer({ server, maxPayload: 512 * 1024 });
const rooms = new Map();
let nextId = 1;

function code4() {
    const ABC = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let s = '';
    for (let i = 0; i < 4; i++) s += ABC[Math.floor(Math.random() * ABC.length)];
    return rooms.has(s) ? code4() : s;
}

function send(ws, obj) {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}

function broadcast(room, obj, except) {
    for (const p of room.players) {
        if (p !== except) send(p, obj);
    }
}

wss.on('connection', ws => {
    ws.id = nextId++;
    ws.room = null;
    ws.isHost = false;
    ws.msgCount = 0;
    ws.windowStart = Date.now();

    ws.on('message', raw => {
        const now = Date.now();
        if (now - ws.windowStart > 1000) {
            ws.windowStart = now;
            ws.msgCount = 0;
        }
        if (++ws.msgCount > 80) return;

        let msg;
        try { msg = JSON.parse(raw); } catch (e) { return; }
        if (!msg || typeof msg.type !== 'string') return;

        if (msg.type === 'create') {
            if (ws.room) return;
            const code = code4();
            const room = { code, host: ws, players: [ws], started: false };
            rooms.set(code, room);
            ws.room = room;
            ws.isHost = true;
            send(ws, { type: 'room', code, host: true, players: 1, id: ws.id });
            return;
        }

        if (msg.type === 'join') {
            if (ws.room) return;
            const code = String(msg.code || '').toUpperCase().trim();
            const room = rooms.get(code);
            if (!room) {
                send(ws, { type: 'error', message: 'Sala no encontrada' });
                return;
            }
            if (room.players.length >= 4) {
                send(ws, { type: 'error', message: 'Sala llena (maximo 4)' });
                return;
            }
            if (room.started) {
                send(ws, { type: 'error', message: 'La partida ya comenzo' });
                return;
            }
            room.players.push(ws);
            ws.room = room;
            send(ws, { type: 'room', code, host: false, players: room.players.length, id: ws.id });
            broadcast(room, { type: 'peer', players: room.players.length }, ws);
            send(ws, { type: 'peer', players: room.players.length });
            return;
        }

        if (!ws.room) return;

        if (msg.type === 'start') {
            if (!ws.isHost) return;
            ws.room.started = true;
            broadcast(ws.room, { type: 'started', players: ws.room.players.length });
            return;
        }

        if (msg.type === 'state') {
            if (!ws.isHost) return;
            broadcast(ws.room, { type: 'state', data: msg.data }, ws);
            return;
        }

        if (msg.type === 'cmd') {
            send(ws.room.host, { type: 'cmd', from: ws.id, data: msg.data });
        }
    });

    ws.on('close', () => {
        const room = ws.room;
        if (!room) return;
        if (ws.isHost) {
            for (const p of room.players) {
                if (p !== ws) {
                    send(p, { type: 'closed', message: 'El anfitrion abandono la sala' });
                    p.room = null;
                }
            }
            rooms.delete(room.code);
            return;
        }
        room.players = room.players.filter(p => p !== ws);
        if (room.players.length === 0) {
            rooms.delete(room.code);
            return;
        }
        broadcast(room, { type: 'peer', players: room.players.length });
    });
});

server.listen(PORT, () => {
    console.log('Juego:    http://localhost:' + PORT);
    console.log('WebSocket: ws://localhost:' + PORT);
});
