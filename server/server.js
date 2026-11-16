'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ROOT = path.resolve(__dirname, '..');

/* ---------------- Cuentas y ranking ---------------- */
const DATA_DIR = process.env.AEC_DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
let db = { users: {}, tokens: {} };
let saveTimer = null;

function loadDb() {
    try {
        const raw = fs.readFileSync(USERS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
            db.users = parsed.users && typeof parsed.users === 'object' ? parsed.users : {};
            db.tokens = parsed.tokens && typeof parsed.tokens === 'object' ? parsed.tokens : {};
        }
    } catch (e) {
        db = { users: {}, tokens: {} };
    }
}

function saveDbNow() {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        const tmp = USERS_FILE + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify(db));
        fs.renameSync(tmp, USERS_FILE);
    } catch (e) {
        console.error('No se pudo guardar la base de cuentas:', e.message);
    }
}

function saveDb() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => { saveTimer = null; saveDbNow(); }, 250);
}

function hashPass(pass, salt) {
    return crypto.scryptSync(String(pass), salt, 48).toString('hex');
}

function newToken() {
    return crypto.randomBytes(32).toString('hex');
}

function rankOf(nameKey) {
    const list = Object.entries(db.users)
        .filter(([, u]) => (u.bestWave || 0) > 0)
        .sort((a, b) => (b[1].bestWave || 0) - (a[1].bestWave || 0) || (a[1].created || 0) - (b[1].created || 0));
    const i = list.findIndex(([k]) => k === nameKey);
    return i === -1 ? 0 : i + 1;
}

function userPayload(key) {
    const u = db.users[key];
    if (!u) return null;
    return { user: u.user, bestWave: u.bestWave || 0, rank: rankOf(key), created: u.created || 0 };
}

function readBody(req) {
    return new Promise(resolve => {
        let raw = '';
        let size = 0;
        req.on('data', chunk => {
            size += chunk.length;
            if (size > 8192) { raw = ''; req.destroy(); resolve(null); return; }
            raw += chunk;
        });
        req.on('end', () => {
            if (!raw) { resolve(null); return; }
            try { resolve(JSON.parse(raw)); } catch (e) { resolve(null); }
        });
        req.on('error', () => resolve(null));
    });
}

function jsonResponse(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Cache-Control': 'no-store'
    });
    res.end(body);
}

const authHits = new Map();
function authRateLimited(ip) {
    const now = Date.now();
    const rec = authHits.get(ip);
    if (!rec || now - rec.start > 60000) {
        authHits.set(ip, { start: now, count: 1 });
        return false;
    }
    rec.count++;
    return rec.count > 30;
}

function tokenUser(token) {
    if (!token || typeof token !== 'string') return null;
    const rec = db.tokens[token];
    if (!rec) return null;
    if (Date.now() - (rec.created || 0) > 90 * 24 * 3600 * 1000) {
        delete db.tokens[token];
        saveDb();
        return null;
    }
    return db.users[rec.key] ? rec.key : null;
}

async function handleApi(req, res, urlPath) {
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400'
        });
        res.end();
        return;
    }

    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'x';
    const isPost = req.method === 'POST';

    if (urlPath === '/api/register' && isPost) {
        if (authRateLimited(ip)) { jsonResponse(res, 429, { error: 'Demasiados intentos, espera un minuto' }); return; }
        const body = await readBody(req);
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const user = String(body.user || '').trim();
        const pass = String(body.pass || '');
        if (!/^[A-Za-z0-9_]{3,16}$/.test(user)) {
            jsonResponse(res, 400, { error: 'El usuario debe tener de 3 a 16 letras, numeros o guion bajo' });
            return;
        }
        if (pass.length < 4 || pass.length > 64) {
            jsonResponse(res, 400, { error: 'La contrasena debe tener entre 4 y 64 caracteres' });
            return;
        }
        const key = user.toLowerCase();
        if (db.users[key]) {
            jsonResponse(res, 409, { error: 'Ese nombre de usuario ya esta en uso' });
            return;
        }
        const salt = crypto.randomBytes(16).toString('hex');
        db.users[key] = {
            user, salt, hash: hashPass(pass, salt),
            created: Date.now(), bestWave: 0, bestAt: 0, bestMode: 'normal'
        };
        const token = newToken();
        db.tokens[token] = { key, created: Date.now() };
        saveDb();
        console.log('Cuenta creada:', user);
        jsonResponse(res, 200, { token, profile: userPayload(key) });
        return;
    }

    if (urlPath === '/api/login' && isPost) {
        if (authRateLimited(ip)) { jsonResponse(res, 429, { error: 'Demasiados intentos, espera un minuto' }); return; }
        const body = await readBody(req);
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const key = String(body.user || '').trim().toLowerCase();
        const pass = String(body.pass || '');
        const u = db.users[key];
        if (!u || !pass) {
            jsonResponse(res, 401, { error: 'Usuario o contrasena incorrectos' });
            return;
        }
        const attempt = Buffer.from(hashPass(pass, u.salt), 'hex');
        const stored = Buffer.from(u.hash, 'hex');
        if (attempt.length !== stored.length || !crypto.timingSafeEqual(attempt, stored)) {
            jsonResponse(res, 401, { error: 'Usuario o contrasena incorrectos' });
            return;
        }
        const token = newToken();
        db.tokens[token] = { key, created: Date.now() };
        saveDb();
        jsonResponse(res, 200, { token, profile: userPayload(key) });
        return;
    }

    if (urlPath === '/api/me') {
        const token = String((req.headers.authorization || '').replace(/^Bearer\s+/i, '') || (new URL(req.url, 'http://x')).searchParams.get('token') || '');
        const key = tokenUser(token);
        if (!key) { jsonResponse(res, 401, { error: 'Sesion no valida' }); return; }
        jsonResponse(res, 200, { profile: userPayload(key) });
        return;
    }

    if (urlPath === '/api/score' && isPost) {
        const body = await readBody(req);
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const key = tokenUser(String(body.token || ''));
        if (!key) { jsonResponse(res, 401, { error: 'Sesion no valida' }); return; }
        const wave = Math.max(0, Math.min(500, Math.floor(Number(body.wave) || 0)));
        const mode = String(body.mode || 'normal').slice(0, 12);
        const u = db.users[key];
        let improved = false;
        if (mode === 'normal' && wave > (u.bestWave || 0)) {
            u.bestWave = wave;
            u.bestAt = Date.now();
            u.bestMode = mode;
            improved = true;
            saveDb();
        }
        jsonResponse(res, 200, { profile: userPayload(key), improved });
        return;
    }

    if (urlPath === '/api/leaderboard') {
        const list = Object.entries(db.users)
            .filter(([, u]) => (u.bestWave || 0) > 0)
            .sort((a, b) => (b[1].bestWave || 0) - (a[1].bestWave || 0) || (a[1].created || 0) - (b[1].created || 0))
            .slice(0, 50)
            .map(([k, u], i) => ({ pos: i + 1, user: u.user, bestWave: u.bestWave || 0 }));
        jsonResponse(res, 200, { top: list });
        return;
    }

    if (urlPath === '/api/logout' && isPost) {
        const body = await readBody(req);
        if (body && body.token) {
            delete db.tokens[String(body.token)];
            saveDb();
        }
        jsonResponse(res, 200, { ok: true });
        return;
    }

    jsonResponse(res, 404, { error: 'Ruta no encontrada' });
}

loadDb();
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
    if (urlPath.startsWith('/api/')) {
        handleApi(req, res, urlPath).catch(err => {
            console.error('Error en API:', err);
            jsonResponse(res, 500, { error: 'Error interno' });
        });
        return;
    }
    if (urlPath.startsWith('/server/') || urlPath.startsWith('/data/') || urlPath === '/users.json') {
        res.writeHead(403);
        res.end('Prohibido');
        return;
    }
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
            ws.slot = 0;
            send(ws, { type: 'room', code, host: true, players: 1, slot: 0, id: ws.id });
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
            if (room.players.length >= 3) {
                send(ws, { type: 'error', message: 'Sala llena (maximo 3 jugadores)' });
                return;
            }
            if (room.started) {
                send(ws, { type: 'error', message: 'La partida ya comenzo' });
                return;
            }
            ws.slot = room.players.length;
            room.players.push(ws);
            ws.room = room;
            send(ws, { type: 'room', code, host: false, players: room.players.length, slot: ws.slot, id: ws.id });
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
            send(ws.room.host, { type: 'cmd', from: ws.id, slot: ws.slot || 0, data: msg.data });
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
    console.log('API:      http://localhost:' + PORT + '/api/leaderboard');
});

process.on('SIGTERM', () => { saveDbNow(); process.exit(0); });
process.on('SIGINT', () => { saveDbNow(); process.exit(0); });
