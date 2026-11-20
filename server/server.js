'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ROOT = path.resolve(__dirname, '..');
const AEC_ADMIN_KEY = process.env.AEC_ADMIN_KEY || 'aec-admin-2026';
const AEC_ADMIN_USERS = ['ohio'];
const BAN_SALT = process.env.AEC_BAN_SALT || 'aec-salt-2026';

/* ---------------- Cuentas y ranking ---------------- */
const DATA_DIR = process.env.AEC_DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
let db = { users: {}, tokens: {}, bans: [], identities: {} };
let saveTimer = null;

function loadDb() {
    try {
        const raw = fs.readFileSync(USERS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
            db.users = parsed.users && typeof parsed.users === 'object' ? parsed.users : {};
            db.tokens = parsed.tokens && typeof parsed.tokens === 'object' ? parsed.tokens : {};
            db.bans = Array.isArray(parsed.bans) ? parsed.bans : [];
            db.identities = parsed.identities && typeof parsed.identities === 'object' ? parsed.identities : {};
        }
    } catch (e) {
        db = { users: {}, tokens: {}, bans: [], identities: {} };
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

/* ---- Bans por identidad ----
   Ademas del nombre de usuario se guarda un hash del dispositivo, la IP y el
   email. Asi banear una cuenta tambien alcanza a cuentas nuevas creadas desde
   el mismo navegador o red. Los valores nunca se guardan en claro. */
function hashIdentity(value) {
    return crypto.createHash('sha256').update(BAN_SALT + '|' + String(value)).digest('hex');
}
function clientIp(req) {
    const xf = String(req.headers['x-forwarded-for'] || '');
    return xf.split(',')[0].trim() || String(req.socket.remoteAddress || 'x');
}
function deviceOf(req, body) {
    return String((req.headers['x-device-id'] || '') || (body && body.device) || '').slice(0, 128);
}
function identitySignals(req, body) {
    const out = [];
    if (body && body.user) out.push(['user', String(body.user).trim().toLowerCase()]);
    if (body && body.email) out.push(['email', String(body.email).trim().toLowerCase()]);
    const did = deviceOf(req, body);
    if (did) out.push(['device', did]);
    const ip = clientIp(req);
    if (ip) out.push(['ip', ip]);
    return out;
}

async function identityBanHit(req, body) {
    for (const [kind, value] of identitySignals(req, body)) {
        const hash = hashIdentity(value);
        if (usingSupabase()) {
            const r = await sbRequest('aec_bans?kind=eq.' + kind + '&value_hash=eq.' + hash +
                '&expires_at=gt.' + Date.now() + '&select=id&limit=1');
            if (r.status === 200 && Array.isArray(r.data) && r.data.length) return kind;
        } else if ((db.bans || []).some(b => b.kind === kind && b.value_hash === hash && Number(b.expires_at) > Date.now())) {
            return kind;
        }
    }
    return null;
}

async function addIdentityBanHash(kind, hash, minutes, reason) {
    if (!['user', 'device', 'email', 'ip'].includes(kind) || !hash) return false;
    const row = {
        kind,
        value_hash: hash,
        expires_at: Date.now() + Math.max(1, Math.min(525600, Math.floor(minutes || 0))) * 60000,
        created_at: Date.now(),
        reason: String(reason || '').slice(0, 120)
    };
    if (usingSupabase()) {
        const r = await sbRequest('aec_bans', {
            method: 'POST',
            headers: { Prefer: 'resolution=merge-duplicates, return=minimal' },
            body: row
        });
        return r.status >= 200 && r.status < 300;
    }
    db.bans = (db.bans || []).filter(b => !(b.kind === kind && b.value_hash === hash));
    db.bans.push(row);
    saveDb();
    return true;
}
function addIdentityBan(kind, value, minutes, reason) {
    return addIdentityBanHash(kind, hashIdentity(value), minutes, reason);
}

async function removeIdentityBanHash(kind, hash) {
    if (usingSupabase()) {
        await sbRequest('aec_bans?kind=eq.' + kind + '&value_hash=eq.' + hash, { method: 'DELETE' });
    } else {
        db.bans = (db.bans || []).filter(b => !(b.kind === kind && b.value_hash === hash));
        saveDb();
    }
}
function removeIdentityBan(kind, value) {
    return removeIdentityBanHash(kind, hashIdentity(value));
}

async function rememberIdentity(key, req, body) {
    if (!key) return;
    const did = deviceOf(req, body);
    const row = {
        user_key: key,
        device_hash: did ? hashIdentity(did) : null,
        ip_hash: hashIdentity(clientIp(req)),
        email_hash: body && body.email ? hashIdentity(String(body.email).trim().toLowerCase()) : null,
        updated_at: Date.now()
    };
    if (usingSupabase()) {
        await sbRequest('aec_identities', {
            method: 'POST',
            headers: { Prefer: 'resolution=merge-duplicates, return=minimal' },
            body: row
        });
    } else {
        db.identities = db.identities || {};
        db.identities[key] = row;
        saveDb();
    }
}

async function identityRecord(key) {
    if (usingSupabase()) {
        const r = await sbRequest('aec_identities?user_key=eq.' + encodeURIComponent(key) + '&select=*&limit=1');
        return (r.status === 200 && Array.isArray(r.data) && r.data[0]) || null;
    }
    return (db.identities || {})[key] || null;
}
async function banIdentityOf(key, minutes, reason) {
    const rec = await identityRecord(key);
    if (!rec) return;
    if (rec.device_hash) await addIdentityBanHash('device', rec.device_hash, minutes, reason);
    if (rec.ip_hash) await addIdentityBanHash('ip', rec.ip_hash, minutes, reason);
    if (rec.email_hash) await addIdentityBanHash('email', rec.email_hash, minutes, reason);
}
async function unbanIdentityOf(key) {
    const rec = await identityRecord(key);
    if (!rec) return;
    if (rec.device_hash) await removeIdentityBanHash('device', rec.device_hash);
    if (rec.ip_hash) await removeIdentityBanHash('ip', rec.ip_hash);
    if (rec.email_hash) await removeIdentityBanHash('email', rec.email_hash);
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

/* ---- Bans de administrador ----
   Un usuario baneado tiene best_wave=0 y best_at=futuro. No hace falta
   anadir columnas: best_at guarda el instante en que termina el castigo. */
function banUntil(u) {
    if (!u) return 0;
    const until = Number((u.best_at !== undefined ? u.best_at : u.bestAt) || 0);
    if (!(until > Date.now())) return 0;
    if ((u.best_wave || u.bestWave || 0) !== 0) return 0;
    return until;
}
function isBanned(u) { return banUntil(u) > 0; }
async function adminAuthorized(req, body) {
    const url = new URL(req.url, 'http://x');
    const h = String(req.headers['x-admin-key'] || '');
    const b = body ? String(body.adminKey || '') : '';
    const q = url.searchParams.get('adminKey') || '';
    if (h === AEC_ADMIN_KEY || b === AEC_ADMIN_KEY || q === AEC_ADMIN_KEY) return true;

    const token = String((req.headers['x-admin-token'] || '')
        || (body && body.token) || url.searchParams.get('token') || '');
    if (!token) return false;
    let key = null;
    if (usingSupabase()) {
        const u = await sbTokenUser(token);
        if (u) key = u.key || u.username;
    } else {
        key = tokenUser(token);
    }
    return key ? AEC_ADMIN_USERS.includes(String(key).toLowerCase()) : false;
}

/* ---- Almacenamiento en Supabase (opcional, sobrevive a redeploys) ----
   Con SUPABASE_URL y SUPABASE_SERVICE_KEY en el entorno, las cuentas y el
   ranking viven en Supabase. Sin esas variables se usa el archivo local. */
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
function usingSupabase() { return !!(SUPABASE_URL && SUPABASE_KEY); }

async function sbRequest(pathAndQuery, options = {}) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 15000);
    try {
        const resp = await fetch(SUPABASE_URL + '/rest/v1/' + pathAndQuery, {
            method: options.method || 'GET',
            headers: {
                apikey: SUPABASE_KEY,
                Authorization: 'Bearer ' + SUPABASE_KEY,
                'Content-Type': 'application/json',
                Accept: 'application/json',
                ...(options.headers || {})
            },
            body: options.body === undefined ? undefined : JSON.stringify(options.body),
            signal: ctl.signal
        });
        const text = await resp.text();
        let data = null;
        if (text) { try { data = JSON.parse(text); } catch (e) { data = null; } }
        return { status: resp.status, data };
    } catch (e) {
        console.error('Supabase no responde:', e.message);
        return { status: 0, data: null };
    } finally {
        clearTimeout(timer);
    }
}

async function sbFindUser(key) {
    const r = await sbRequest('aec_users?key=eq.' + encodeURIComponent(key) + '&select=*&limit=1');
    return (r.status === 200 && Array.isArray(r.data) && r.data[0]) || null;
}

async function sbCreateToken(key) {
    const token = newToken();
    await sbRequest('aec_tokens', { method: 'POST', body: { token, user_key: key, created: Date.now() } });
    return token;
}

async function sbTokenUser(token) {
    const r = await sbRequest('aec_tokens?token=eq.' + encodeURIComponent(token) + '&select=*,user:aec_users(*)&limit=1');
    if (r.status !== 200 || !Array.isArray(r.data) || !r.data[0]) return null;
    const rec = r.data[0];
    if (Date.now() - (rec.created || 0) > 90 * 24 * 3600 * 1000) {
        await sbRequest('aec_tokens?token=eq.' + encodeURIComponent(token), { method: 'DELETE' });
        return null;
    }
    return rec.user || null;
}

async function sbProfile(user) {
    if (!user) return null;
    let rank = 0;
    const bw = user.best_wave || 0;
    if (bw > 0) {
        const r = await sbRequest('aec_users?and=(best_wave.gte.' + bw + ',created.lte.' + (user.created || 0) + ')&select=key');
        if (r.status === 200 && Array.isArray(r.data)) rank = r.data.length;
    }
    return { user: user.username, bestWave: bw, rank, created: user.created || 0 };
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
        'Access-Control-Allow-Headers': 'Content-Type, x-admin-key, x-admin-token, x-device-id',
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
            'Access-Control-Allow-Headers': 'Content-Type, x-admin-key, x-admin-token, x-device-id',
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
        const hit = await identityBanHit(req, body);
        if (hit) { jsonResponse(res, 403, { error: 'Esta identidad esta baneada (' + hit + ')' }); return; }
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
        if (usingSupabase()) {
            if (await sbFindUser(key)) { jsonResponse(res, 409, { error: 'Ese nombre de usuario ya esta en uso' }); return; }
            const created = Date.now();
            const salt = crypto.randomBytes(16).toString('hex');
            const r = await sbRequest('aec_users', {
                method: 'POST',
                headers: { Prefer: 'return=minimal' },
                body: { key, username: user, salt, hash: hashPass(pass, salt), created, best_wave: 0, best_at: 0, best_mode: 'normal' }
            });
            if (r.status === 0 || r.status >= 400) { jsonResponse(res, 500, { error: 'No se pudo crear la cuenta, intentalo de nuevo' }); return; }
            await sbRequest('aec_tokens?created=lt.' + (created - 90 * 24 * 3600 * 1000), { method: 'DELETE' });
            const token = await sbCreateToken(key);
            await rememberIdentity(key, req, body);
            console.log('Cuenta creada (Supabase):', user);
            jsonResponse(res, 200, { token, profile: { user, bestWave: 0, rank: 0, created } });
            return;
        }
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
        await rememberIdentity(key, req, body);
        saveDb();
        console.log('Cuenta creada:', user);
        jsonResponse(res, 200, { token, profile: userPayload(key) });
        return;
    }

    if (urlPath === '/api/login' && isPost) {
        if (authRateLimited(ip)) { jsonResponse(res, 429, { error: 'Demasiados intentos, espera un minuto' }); return; }
        const body = await readBody(req);
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const hit = await identityBanHit(req, body);
        if (hit) { jsonResponse(res, 403, { error: 'Esta identidad esta baneada (' + hit + ')' }); return; }
        const key = String(body.user || '').trim().toLowerCase();
        const pass = String(body.pass || '');
        if (usingSupabase()) {
            const u = await sbFindUser(key);
            if (!u || !pass) { jsonResponse(res, 401, { error: 'Usuario o contrasena incorrectos' }); return; }
            const attempt = Buffer.from(hashPass(pass, u.salt), 'hex');
            const stored = Buffer.from(u.hash, 'hex');
            if (attempt.length !== stored.length || !crypto.timingSafeEqual(attempt, stored)) {
                jsonResponse(res, 401, { error: 'Usuario o contrasena incorrectos' });
                return;
            }
            if (isBanned(u)) {
                jsonResponse(res, 403, { error: 'Este usuario esta baneado. Intentalo cuando termine el castigo.' });
                return;
            }
            await rememberIdentity(key, req, body);
            const token = await sbCreateToken(key);
            jsonResponse(res, 200, { token, profile: await sbProfile(u) });
            return;
        }
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
        if (isBanned(u)) {
            jsonResponse(res, 403, { error: 'Este usuario esta baneado. Intentalo cuando termine el castigo.' });
            return;
        }
        await rememberIdentity(key, req, body);
        const token = newToken();
        db.tokens[token] = { key, created: Date.now() };
        saveDb();
        jsonResponse(res, 200, { token, profile: userPayload(key) });
        return;
    }

    if (urlPath === '/api/me') {
        const token = String((req.headers.authorization || '').replace(/^Bearer\s+/i, '') || (new URL(req.url, 'http://x')).searchParams.get('token') || '');
        if (usingSupabase()) {
            const u = await sbTokenUser(token);
            if (!u) { jsonResponse(res, 401, { error: 'Sesion no valida' }); return; }
            const hit = await identityBanHit(req, null);
            if (hit) { jsonResponse(res, 403, { error: 'Identidad baneada (' + hit + ')' }); return; }
            if (isBanned(u)) { jsonResponse(res, 403, { error: 'Usuario baneado' }); return; }
            jsonResponse(res, 200, { profile: await sbProfile(u) });
            return;
        }
        const key = tokenUser(token);
        if (!key) { jsonResponse(res, 401, { error: 'Sesion no valida' }); return; }
        const hit = await identityBanHit(req, null);
        if (hit) { jsonResponse(res, 403, { error: 'Identidad baneada (' + hit + ')' }); return; }
        if (isBanned(db.users[key])) { jsonResponse(res, 403, { error: 'Usuario baneado' }); return; }
        jsonResponse(res, 200, { profile: userPayload(key) });
        return;
    }

    if (urlPath === '/api/score' && isPost) {
        const body = await readBody(req);
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        if (usingSupabase()) {
            const u = await sbTokenUser(String(body.token || ''));
            if (!u) { jsonResponse(res, 401, { error: 'Sesion no valida' }); return; }
            const hit = await identityBanHit(req, body);
            if (hit) { jsonResponse(res, 403, { error: 'Identidad baneada: no se guardan puntajes (' + hit + ')' }); return; }
            if (isBanned(u)) { jsonResponse(res, 403, { error: 'Usuario baneado: no se guardan puntajes' }); return; }
            const wave = Math.max(0, Math.min(500, Math.floor(Number(body.wave) || 0)));
            const mode = String(body.mode || 'normal').slice(0, 12);
            let improved = false;
            if (mode === 'normal' && wave > (u.best_wave || 0)) {
                await sbRequest('aec_users?key=eq.' + encodeURIComponent(u.key), {
                    method: 'PATCH',
                    headers: { Prefer: 'return=minimal' },
                    body: { best_wave: wave, best_at: Date.now(), best_mode: mode }
                });
                u.best_wave = wave;
                improved = true;
            }
            jsonResponse(res, 200, { profile: await sbProfile(u), improved });
            return;
        }
        const key = tokenUser(String(body.token || ''));
        if (!key) { jsonResponse(res, 401, { error: 'Sesion no valida' }); return; }
        const hit = await identityBanHit(req, body);
        if (hit) { jsonResponse(res, 403, { error: 'Identidad baneada: no se guardan puntajes (' + hit + ')' }); return; }
        if (isBanned(db.users[key])) { jsonResponse(res, 403, { error: 'Usuario baneado: no se guardan puntajes' }); return; }
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
        if (usingSupabase()) {
            const r = await sbRequest('aec_users?best_wave=gte.1&select=username,best_wave&order=best_wave.desc,created.asc&limit=50');
            const list = (r.status === 200 && Array.isArray(r.data))
                ? r.data.map((u, i) => ({ pos: i + 1, user: u.username, bestWave: u.best_wave || 0 }))
                : [];
            jsonResponse(res, 200, { top: list });
            return;
        }
        const list = Object.entries(db.users)
            .filter(([, u]) => (u.bestWave || 0) > 0)
            .sort((a, b) => (b[1].bestWave || 0) - (a[1].bestWave || 0) || (a[1].created || 0) - (b[1].created || 0))
            .slice(0, 50)
            .map(([k, u], i) => ({ pos: i + 1, user: u.user, bestWave: u.bestWave || 0 }));
        jsonResponse(res, 200, { top: list });
        return;
    }

    if (urlPath === '/api/admin/ban' && isPost) {
        const body = await readBody(req);
        if (!(await adminAuthorized(req, body))) { jsonResponse(res, 403, { error: 'No tienes permiso de administrador' }); return; }
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const key = String(body.user || '').trim().toLowerCase();
        if (!/^[a-z0-9_]{3,16}$/.test(key)) { jsonResponse(res, 400, { error: 'Usuario invalido' }); return; }
        const minutes = Math.max(1, Math.min(525600, Math.floor(Number(body.minutes) || 0)));
        const until = Date.now() + minutes * 60000;
        if (usingSupabase()) {
            const u = await sbFindUser(key);
            if (!u) { jsonResponse(res, 404, { error: 'Usuario no encontrado' }); return; }
            const r = await sbRequest('aec_users?key=eq.' + encodeURIComponent(key), {
                method: 'PATCH',
                headers: { Prefer: 'return=minimal' },
                body: { best_wave: 0, best_at: until }
            });
            if (r.status === 0 || r.status >= 400) { jsonResponse(res, 500, { error: 'No se pudo banear al usuario' }); return; }
            await sbRequest('aec_tokens?user_key=eq.' + encodeURIComponent(key), { method: 'DELETE' });
        } else {
            const u = db.users[key];
            if (!u) { jsonResponse(res, 404, { error: 'Usuario no encontrado' }); return; }
            u.bestWave = 0;
            u.bestAt = until;
            for (const [t, rec] of Object.entries(db.tokens)) {
                if (rec.key === key) delete db.tokens[t];
            }
            saveDb();
        }
        await addIdentityBan('user', key, minutes, 'ban de usuario');
        await banIdentityOf(key, minutes, 'ban de usuario');
        console.log('Admin ban:', key, minutes, 'min');
        jsonResponse(res, 200, { ok: true, user: key, minutes, until });
        return;
    }

    if (urlPath === '/api/admin/unban' && isPost) {
        const body = await readBody(req);
        if (!(await adminAuthorized(req, body))) { jsonResponse(res, 403, { error: 'No tienes permiso de administrador' }); return; }
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const key = String(body.user || '').trim().toLowerCase();
        if (!/^[a-z0-9_]{3,16}$/.test(key)) { jsonResponse(res, 400, { error: 'Usuario invalido' }); return; }
        if (usingSupabase()) {
            const u = await sbFindUser(key);
            if (!u) { jsonResponse(res, 404, { error: 'Usuario no encontrado' }); return; }
            const r = await sbRequest('aec_users?key=eq.' + encodeURIComponent(key), {
                method: 'PATCH',
                headers: { Prefer: 'return=minimal' },
                body: { best_at: 0 }
            });
            if (r.status === 0 || r.status >= 400) { jsonResponse(res, 500, { error: 'No se pudo desbanear al usuario' }); return; }
        } else {
            const u = db.users[key];
            if (!u) { jsonResponse(res, 404, { error: 'Usuario no encontrado' }); return; }
            u.bestAt = 0;
            saveDb();
        }
        await removeIdentityBan('user', key);
        await unbanIdentityOf(key);
        console.log('Admin unban:', key);
        jsonResponse(res, 200, { ok: true, user: key });
        return;
    }

    if (urlPath === '/api/admin/bans') {
        if (!(await adminAuthorized(req, null))) { jsonResponse(res, 403, { error: 'No tienes permiso de administrador' }); return; }
        const now = Date.now();
        let list = [];
        let identities = [];
        if (usingSupabase()) {
            const r = await sbRequest('aec_users?select=username,best_wave,best_at&limit=1000');
            if (r.status === 200 && Array.isArray(r.data)) {
                list = r.data.filter(u => banUntil(u) > 0)
                    .map(u => ({ user: u.username, until: Number(u.best_at) || 0 }));
            }
            const r2 = await sbRequest('aec_bans?expires_at=gt.' + now +
                '&select=kind,value_hash,expires_at,reason&order=expires_at.asc&limit=500');
            if (r2.status === 200 && Array.isArray(r2.data)) {
                identities = r2.data.map(b => ({
                    kind: b.kind,
                    value: String(b.value_hash || '').slice(0, 12),
                    until: Number(b.expires_at) || 0,
                    reason: String(b.reason || '')
                }));
            }
        } else {
            list = Object.entries(db.users)
                .filter(([, u]) => banUntil(u) > 0)
                .map(([k, u]) => ({ user: u.user || k, until: Number(u.bestAt || u.best_at || 0) }));
            identities = (db.bans || [])
                .filter(b => Number(b.expires_at) > now)
                .map(b => ({
                    kind: b.kind,
                    value: String(b.value_hash || '').slice(0, 12),
                    until: Number(b.expires_at) || 0,
                    reason: String(b.reason || '')
                }));
        }
        list.sort((a, b) => a.until - b.until);
        identities.sort((a, b) => a.until - b.until);
        jsonResponse(res, 200, { bans: list, identities });
        return;
    }

    if (urlPath === '/api/admin/ban-identity' && isPost) {
        const body = await readBody(req);
        if (!(await adminAuthorized(req, body))) { jsonResponse(res, 403, { error: 'No tienes permiso de administrador' }); return; }
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const kind = String(body.kind || '').toLowerCase();
        if (!['user', 'device', 'email', 'ip'].includes(kind)) { jsonResponse(res, 400, { error: 'Tipo de identidad invalido' }); return; }
        let value = String(body.value || '').trim();
        if (!value || value.length > 256) { jsonResponse(res, 400, { error: 'Valor invalido' }); return; }
        if (kind === 'user') value = value.toLowerCase();
        const minutes = Math.max(1, Math.min(525600, Math.floor(Number(body.minutes) || 0)));
        const ok = await addIdentityBan(kind, value, minutes, String(body.reason || 'ban manual'));
        if (!ok) { jsonResponse(res, 500, { error: 'No se pudo guardar el ban de identidad' }); return; }
        console.log('Admin ban identidad:', kind, minutes, 'min');
        jsonResponse(res, 200, { ok: true, kind, minutes });
        return;
    }

    if (urlPath === '/api/admin/unban-identity' && isPost) {
        const body = await readBody(req);
        if (!(await adminAuthorized(req, body))) { jsonResponse(res, 403, { error: 'No tienes permiso de administrador' }); return; }
        if (!body) { jsonResponse(res, 400, { error: 'Datos invalidos' }); return; }
        const kind = String(body.kind || '').toLowerCase();
        if (!['user', 'device', 'email', 'ip'].includes(kind)) { jsonResponse(res, 400, { error: 'Tipo de identidad invalido' }); return; }
        let value = String(body.value || '').trim();
        if (!value || value.length > 256) { jsonResponse(res, 400, { error: 'Valor invalido' }); return; }
        if (kind === 'user') value = value.toLowerCase();
        await removeIdentityBan(kind, value);
        console.log('Admin unban identidad:', kind);
        jsonResponse(res, 200, { ok: true, kind });
        return;
    }

    if (urlPath === '/api/logout' && isPost) {
        const body = await readBody(req);
        if (usingSupabase()) {
            if (body && body.token) {
                await sbRequest('aec_tokens?token=eq.' + encodeURIComponent(String(body.token)), { method: 'DELETE' });
            }
            jsonResponse(res, 200, { ok: true });
            return;
        }
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
    console.log('Cuentas:  ' + (usingSupabase() ? 'Supabase (' + SUPABASE_URL + ')' : 'archivo local'));
});

process.on('SIGTERM', () => { saveDbNow(); process.exit(0); });
process.on('SIGINT', () => { saveDbNow(); process.exit(0); });
