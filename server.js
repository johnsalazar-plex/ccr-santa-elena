const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const app = express();
const server = http.createServer(app);

// ---------- Configuración (variables de entorno en Render) ----------
// PASS_GERENTE, PASS_AVE, PASS_TWR : contraseñas iniciales (obligatorias)
// DEVICE_TOKEN                     : clave del ESP32 (obligatoria)
// DATA_DIR                         : carpeta de un disco persistente (opcional, para conservar cambios de contraseña)
const DEVICE_TOKEN = process.env.DEVICE_TOKEN || '';
const PERSISTENT = !!process.env.DATA_DIR;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const ROLES = { gerente: 'Gerente General', AVE: 'Operador Pista', TWR: 'Torre Control' };
const ENV_PASS = { gerente: 'PASS_GERENTE', AVE: 'PASS_AVE', TWR: 'PASS_TWR' };

server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
app.disable('x-powered-by');

// ---------- Cabeceras de seguridad ----------
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: ws:; frame-ancestors 'none'");
  next();
});

app.get('/health', (req, res) => res.type('text').send('ok'));

app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (/\.(jpg|jpeg|png|svg)$/i.test(filePath)) res.setHeader('Cache-Control', 'public, max-age=604800');
  }
}));

// Cualquier otra ruta devuelve la página (compatible con Express 4 y 5)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- Usuarios (contraseñas con scrypt, nunca en texto plano) ----------
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 32);
  return salt.toString('hex') + ':' + key.toString('hex');
}

async function verifyPassword(pw, stored) {
  const [saltHex, keyHex] = stored.split(':');
  const key = await scrypt(pw, Buffer.from(saltHex, 'hex'), 32);
  const expected = Buffer.from(keyHex, 'hex');
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

function safeEq(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

const userDb = new Map();   // usuario -> { hash, role }
let overrides = {};         // contraseñas cambiadas desde el panel (se guardan en USERS_FILE)
let DUMMY_HASH = '';

async function initUsers() {
  try { overrides = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { overrides = {}; }
  for (const [name, role] of Object.entries(ROLES)) {
    const envPw = process.env[ENV_PASS[name]];
    if (typeof overrides[name] === 'string') {
      userDb.set(name, { hash: overrides[name], role });
    } else if (envPw) {
      userDb.set(name, { hash: await hashPassword(envPw), role });
    } else {
      console.warn(`[AVISO] Falta la variable ${ENV_PASS[name]}: "${name}" no podrá iniciar sesión.`);
    }
  }
  if (!DEVICE_TOKEN) console.warn('[AVISO] Falta DEVICE_TOKEN: el ESP32 será rechazado.');
  DUMMY_HASH = await hashPassword(crypto.randomBytes(8).toString('hex'));
}

function saveOverrides() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(USERS_FILE, JSON.stringify(overrides), { mode: 0o600 });
    return true;
  } catch (e) {
    console.error('No se pudo guardar users.json:', e.message);
    return false;
  }
}

// ---------- Sesiones ----------
const SESSION_MS = 12 * 60 * 60 * 1000;
const sessions = new Map(); // token -> { user, expires }

function newSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { user, expires: Date.now() + SESSION_MS });
  return token;
}

function sessionUser(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expires < Date.now()) { sessions.delete(token); return null; }
  return s.user;
}

function dropSessions(user, keepToken) {
  for (const [t, s] of sessions) if (s.user === user && t !== keepToken) sessions.delete(t);
}

setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions) if (s.expires < now) sessions.delete(t);
  for (const [k, f] of loginFails) if (f.until < now && f.count === 0) loginFails.delete(k);
}, 60 * 60 * 1000).unref();

// ---------- Anti fuerza bruta ----------
const loginFails = new Map(); // "ip|usuario" -> { count, until }

function isLocked(key) {
  const f = loginFails.get(key);
  return !!f && f.until > Date.now();
}
function noteFail(key) {
  const f = loginFails.get(key) || { count: 0, until: 0 };
  f.count++;
  if (f.count >= 5) { f.until = Date.now() + 60000; f.count = 0; }
  loginFails.set(key, f);
}

function clientIp(req) {
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String(cf);
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',').pop().trim();
  return req.socket.remoteAddress || 'unknown';
}

// ---------- WebSocket ----------
const wss = new WebSocket.Server({
  server,
  path: '/ws',
  perMessageDeflate: false,
  maxPayload: 4096,
  // Bloquea páginas de otros sitios. El ESP32 no manda Origin, pero igual debe autenticarse.
  verifyClient: ({ origin, req }) => {
    if (!origin) return true;
    try { return new URL(origin).host === req.headers.host; } catch (e) { return false; }
  }
});

const aglState = {
  1: { masterOn: false, state: 0 },
  2: { masterOn: false, state: 0 },
  3: { masterOn: false, state: 0 },
  4: { beacon: false }
};

const activeUsers = new Map(); // socket -> usuario
const ipConns = new Map();

function safeSend(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload));
}

function broadcast(payload, filterFn) {
  const msg = typeof payload === 'string' ? payload : JSON.stringify(payload);
  wss.clients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN && (!filterFn || filterFn(c))) c.send(msg);
  });
}

const isBrowser = (c) => !c.isDevice && !!c.user;   // navegador con sesión iniciada
const isDevice = (c) => c.isDevice;

function usersPayload() {
  const seen = new Map();
  for (const name of activeUsers.values()) seen.set(name, ROLES[name] || 'Operador');
  return { type: 'SYNC_USERS', users: Array.from(seen, ([user, role]) => ({ user, role })) };
}
const broadcastUsers = () => broadcast(usersPayload(), isBrowser);

function devicePayload() {
  let count = 0;
  wss.clients.forEach((c) => { if (c.isDevice && c.readyState === WebSocket.OPEN) count++; });
  return { type: 'DEVICE_STATUS', online: count > 0, count };
}
const broadcastDeviceStatus = () => broadcast(devicePayload(), isBrowser);

function startSession(ws, name, token) {
  ws.user = name;
  ws.token = token || newSession(name);
  activeUsers.set(ws, name);
  safeSend(ws, { type: 'LOGIN_OK', user: name, role: userDb.get(name).role, token: ws.token });
  safeSend(ws, { type: 'SYNC_FULL_STATE', data: aglState });
  safeSend(ws, devicePayload());
  broadcastUsers();
}

wss.on('connection', (ws, req) => {
  ws.ip = clientIp(req);
  ws.isAlive = true;
  ws.isDevice = false;
  ws.user = null;
  ws.token = null;
  ws.msgCount = 0;
  ws.winStart = Date.now();
  req.socket.setNoDelay(true);

  const n = (ipConns.get(ws.ip) || 0) + 1;
  ipConns.set(ws.ip, n);
  if (n > 15) { ws.close(1008, 'demasiadas conexiones'); return; }

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (message) => {
    const now = Date.now();
    if (now - ws.winStart > 10000) { ws.winStart = now; ws.msgCount = 0; }
    if (++ws.msgCount > 80) { ws.close(1008, 'demasiados mensajes'); return; }
    ws.isAlive = true;

    let data;
    try { data = JSON.parse(message); } catch (e) { return; }
    if (!data || typeof data.type !== 'string') return;

    // ----- Mensajes permitidos sin sesión -----
    if (data.type === 'PING') { safeSend(ws, { type: 'PONG' }); return; }

    if (data.type === 'HELLO') {
      if (ws.user || data.role !== 'ESP32') return;
      if (!DEVICE_TOKEN || !safeEq(data.token || '', DEVICE_TOKEN)) { ws.close(4001, 'token invalido'); return; }
      ws.isDevice = true;
      safeSend(ws, { type: 'SYNC_FULL_STATE', data: aglState });
      broadcastDeviceStatus();
      return;
    }

    if (ws.isDevice) return; // el ESP32 solo recibe órdenes

    if (data.type === 'LOGIN') {
      const name = String(data.user || '').slice(0, 32);
      const pass = String(data.pass || '').slice(0, 128);
      const key = ws.ip + '|' + name;
      if (isLocked(key)) { safeSend(ws, { type: 'LOGIN_FAIL', reason: 'Demasiados intentos. Espera 1 minuto.' }); return; }

      const rec = userDb.get(name);
      const ok = rec ? await verifyPassword(pass, rec.hash)
                     : (await verifyPassword(pass, DUMMY_HASH), false); // iguala tiempos de respuesta
      if (!ok) { noteFail(key); safeSend(ws, { type: 'LOGIN_FAIL', reason: 'Usuario o contraseña incorrectos' }); return; }

      loginFails.delete(key);
      startSession(ws, name);
      return;
    }

    if (data.type === 'RESUME') {
      const name = sessionUser(String(data.token || ''));
      if (!name || !userDb.has(name)) { safeSend(ws, { type: 'RESUME_FAIL' }); return; }
      startSession(ws, name, data.token);
      return;
    }

    // ----- Todo lo demás exige sesión iniciada -----
    if (!ws.user) return;

    switch (data.type) {
      case 'LOGOUT': {
        if (ws.token) sessions.delete(ws.token);
        activeUsers.delete(ws);
        ws.user = null;
        ws.token = null;
        broadcastUsers();
        break;
      }

      case 'CONTROL_AGL': {
        const group = Number(data.group);
        const state = Number(data.state);
        if (!Number.isInteger(group) || group < 1 || group > 4) return;
        if (!Number.isInteger(state) || state < 0 || state > 5) return;

        if (group <= 3) {
          aglState[group].state = state;
          aglState[group].masterOn = state > 0;
        } else {
          aglState[4].beacon = state === 1;
        }
        broadcast({ type: 'CONTROL_AGL', group, state, aglState }, (c) => isBrowser(c) && c !== ws);
        broadcast({ type: 'CONTROL_AGL', group, state }, isDevice);
        break;
      }

      case 'KICK_USER': {
        if (ws.user !== 'gerente') return;
        const target = String(data.user || '');
        if (!userDb.has(target) || target === 'gerente') return;
        dropSessions(target);
        for (const [clientWs, name] of Array.from(activeUsers)) {
          if (name === target) {
            safeSend(clientWs, { type: 'KICK_USER', user: target });
            clientWs.user = null;
            clientWs.token = null;
            activeUsers.delete(clientWs);
          }
        }
        broadcastUsers();
        break;
      }

      case 'CHANGE_PASSWORD': {
        if (ws.user !== 'gerente') return;
        const target = String(data.user || '');
        const newPass = String(data.newPass || '');
        if (!userDb.has(target)) { safeSend(ws, { type: 'ERROR', message: 'Usuario no válido' }); return; }
        if (newPass.length < 8 || newPass.length > 128) {
          safeSend(ws, { type: 'ERROR', message: 'La contraseña debe tener entre 8 y 128 caracteres' });
          return;
        }

        const hash = await hashPassword(newPass);
        userDb.get(target).hash = hash;
        overrides[target] = hash;
        saveOverrides();

        // Cierra las demás sesiones de ese usuario (la del gerente que cambia la suya se conserva)
        dropSessions(target, target === 'gerente' ? ws.token : undefined);
        for (const [clientWs, name] of Array.from(activeUsers)) {
          if (name === target && clientWs !== ws) {
            safeSend(clientWs, { type: 'KICK_USER', user: target });
            clientWs.user = null;
            clientWs.token = null;
            activeUsers.delete(clientWs);
          }
        }
        broadcastUsers();
        safeSend(ws, { type: 'PASSWORD_CHANGED', user: target, persistent: PERSISTENT });
        break;
      }
    }
  });

  ws.on('close', () => {
    const left = (ipConns.get(ws.ip) || 1) - 1;
    if (left <= 0) ipConns.delete(ws.ip); else ipConns.set(ws.ip, left);
    if (activeUsers.delete(ws)) broadcastUsers();
    if (ws.isDevice) broadcastDeviceStatus();
  });

  ws.on('error', () => ws.terminate());
});

// Heartbeat: elimina conexiones zombi (ESP32 que perdió el WiFi sin cerrar el socket)
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) { ws.terminate(); return; }
    ws.isAlive = false;
    ws.ping();
  });
}, 20000);
wss.on('close', () => clearInterval(heartbeat));

const PORT = process.env.PORT || 3000;
initUsers().then(() => {
  server.listen(PORT, () => console.log(`Servidor CCR activo en puerto ${PORT}`));
});
