'use strict';

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const WebSocket = require('ws');

// ============================================================
// CONFIGURACIÓN GENERAL
// ============================================================

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;

const DEVICE_TOKEN = process.env.DEVICE_TOKEN || '';

const PERSISTENT = !!process.env.DATA_DIR;

const DATA_DIR =
  process.env.DATA_DIR ||
  path.join(__dirname, 'data');

const USERS_FILE =
  path.join(DATA_DIR, 'users.json');

// ============================================================
// ROLES
// ============================================================

const ROLES = {
  gerente: 'Gerente General',
  AVE: 'Operador Pista',
  TWR: 'Torre Control'
};

const ENV_PASS = {
  gerente: 'PASS_GERENTE',
  AVE: 'PASS_AVE',
  TWR: 'PASS_TWR'
};

// ============================================================
// EXPRESS
// ============================================================

app.use(express.json({
  limit: '1mb'
}));

app.use(express.urlencoded({
  extended: true
}));

// ============================================================
// ESTADO AGL
// ============================================================
//
// 0 = apagado
// 1..5 = niveles de iluminación
//
// Estos nombres deben coincidir con el ESP32.
// ============================================================

const aglState = {
  pista: 0,
  taxeo: 0,
  papi: 0,
  faro: false
};

// ============================================================
// ESTADO DEL ESP32
// ============================================================

let deviceSocket = null;

let deviceConnected = false;

let deviceLastSeen = null;

// ============================================================
// SESIONES WEB
// ============================================================

const sessions = new Map();

// ============================================================
// CONTROL DE INTENTOS DE LOGIN
// ============================================================

const loginAttempts = new Map();

const LOGIN_WINDOW_MS = 10 * 60 * 1000;

const MAX_LOGIN_ATTEMPTS = 8;

// ============================================================
// FUNCIONES GENERALES
// ============================================================

function safeSend(ws, object) {

  if (!ws) return false;

  if (ws.readyState !== WebSocket.OPEN) {
    return false;
  }

  try {

    ws.send(JSON.stringify(object));

    return true;

  } catch (err) {

    console.error(
      '[WS] Error enviando mensaje:',
      err.message
    );

    return false;
  }
}

// ============================================================
// COMPARACIÓN SEGURA
// ============================================================

function safeEq(a, b) {

  const aa = Buffer.from(
    String(a || ''),
    'utf8'
  );

  const bb = Buffer.from(
    String(b || ''),
    'utf8'
  );

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(aa, bb);
}

// ============================================================
// HASH DE CONTRASEÑAS
// ============================================================

function hashPassword(password) {

  return new Promise((resolve, reject) => {

    const salt = crypto.randomBytes(16).toString('hex');

    crypto.scrypt(
      String(password),
      salt,
      64,
      (err, derivedKey) => {

        if (err) {
          reject(err);
          return;
        }

        resolve(
          `scrypt:${salt}:${derivedKey.toString('hex')}`
        );
      }
    );
  });
}

// ============================================================
// VERIFICAR CONTRASEÑA
// ============================================================

function verifyPassword(password, stored) {

  return new Promise((resolve) => {

    try {

      const parts = String(stored || '').split(':');

      if (
        parts.length !== 3 ||
        parts[0] !== 'scrypt'
      ) {
        resolve(false);
        return;
      }

      const salt = parts[1];

      const expected = Buffer.from(
        parts[2],
        'hex'
      );

      crypto.scrypt(
        String(password),
        salt,
        expected.length,
        (err, derivedKey) => {

          if (err) {
            resolve(false);
            return;
          }

          if (
            derivedKey.length !==
            expected.length
          ) {
            resolve(false);
            return;
          }

          resolve(
            crypto.timingSafeEqual(
              derivedKey,
              expected
            )
          );
        }
      );

    } catch (err) {

      resolve(false);
    }
  });
}

// ============================================================
// CREAR DATA DIR
// ============================================================

function ensureDataDir() {

  if (!PERSISTENT) {
    return;
  }

  try {

    fs.mkdirSync(
      DATA_DIR,
      {
        recursive: true
      }
    );

  } catch (err) {

    console.error(
      '[DATA] No se pudo crear DATA_DIR:',
      err.message
    );
  }
}

// ============================================================
// GUARDAR USUARIOS
// ============================================================

function saveUsers(users) {

  if (!PERSISTENT) {
    return;
  }

  try {

    ensureDataDir();

    fs.writeFileSync(
      USERS_FILE,
      JSON.stringify(
        users,
        null,
        2
      ),
      'utf8'
    );

  } catch (err) {

    console.error(
      '[DATA] Error guardando usuarios:',
      err.message
    );
  }
}

// ============================================================
// CARGAR USUARIOS
// ============================================================

function loadUsers() {

  if (!PERSISTENT) {
    return {};
  }

  try {

    if (!fs.existsSync(USERS_FILE)) {
      return {};
    }

    const raw =
      fs.readFileSync(
        USERS_FILE,
        'utf8'
      );

    const parsed =
      JSON.parse(raw);

    if (
      !parsed ||
      typeof parsed !== 'object'
    ) {
      return {};
    }

    return parsed;

  } catch (err) {

    console.error(
      '[DATA] Error leyendo users.json:',
      err.message
    );

    return {};
  }
}

let users = loadUsers();

// ============================================================
// INICIALIZAR USUARIOS DESDE VARIABLES DE RENDER
// ============================================================

async function initializeUsers() {

  for (const role of Object.keys(ROLES)) {

    const envName = ENV_PASS[role];

    const password =
      process.env[envName];

    if (!password) {

      console.warn(
        `[AVISO] Falta la variable ${envName}: "${role}" no podrá iniciar sesión.`
      );

      continue;
    }

    if (
      typeof password !== 'string' ||
      password.length < 1
    ) {
      continue;
    }

    // Si no existe el usuario, se crea.
    if (!users[role]) {

      users[role] = {
        username: role,
        role: role,
        displayName: ROLES[role],
        passwordHash:
          await hashPassword(password),
        createdAt:
          new Date().toISOString()
      };

      console.log(
        `[AUTH] Usuario "${role}" inicializado.`
      );

    }
  }

  saveUsers(users);
}

// ============================================================
// SESIONES
// ============================================================

function createSession(username, role) {

  const sessionId =
    crypto.randomBytes(32).toString('hex');

  const session = {
    sessionId,
    username,
    role,
    createdAt: Date.now(),
    lastSeen: Date.now()
  };

  sessions.set(
    sessionId,
    session
  );

  return session;
}

function getSession(sessionId) {

  if (!sessionId) {
    return null;
  }

  const session =
    sessions.get(sessionId);

  if (!session) {
    return null;
  }

  session.lastSeen = Date.now();

  return session;
}

function destroySession(sessionId) {

  if (!sessionId) {
    return;
  }

  sessions.delete(sessionId);
}

// ============================================================
// LIMPIAR SESIONES ANTIGUAS
// ============================================================

setInterval(() => {

  const maxAge =
    24 * 60 * 60 * 1000;

  const now = Date.now();

  for (const [
    sessionId,
    session
  ] of sessions.entries()) {

    if (
      now - session.lastSeen >
      maxAge
    ) {

      sessions.delete(
        sessionId
      );
    }
  }

}, 60 * 60 * 1000);

// ============================================================
// LOGIN RATE LIMIT
// ============================================================

function loginAllowed(ip) {

  const now = Date.now();

  const item =
    loginAttempts.get(ip);

  if (!item) {
    return true;
  }

  if (
    now - item.firstAttempt >
    LOGIN_WINDOW_MS
  ) {

    loginAttempts.delete(ip);

    return true;
  }

  return (
    item.count <
    MAX_LOGIN_ATTEMPTS
  );
}

function registerFailedLogin(ip) {

  const now = Date.now();

  let item =
    loginAttempts.get(ip);

  if (!item) {

    item = {
      firstAttempt: now,
      count: 0
    };
  }

  item.count++;

  loginAttempts.set(
    ip,
    item
  );
}

function clearLoginAttempts(ip) {

  loginAttempts.delete(ip);
}

// ============================================================
// INFO PÚBLICA DEL SISTEMA
// ============================================================

function getDeviceStatus() {

  return {
    connected:
      deviceConnected,

    lastSeen:
      deviceLastSeen
  };
}

// ============================================================
// ENVIAR ESTADO DEL ESP32 A LOS NAVEGADORES
// ============================================================

function broadcastDeviceStatus() {

  const message = {

    type: 'DEVICE_STATUS',

    data: getDeviceStatus()
  };

  for (const client of wss.clients) {

    if (
      client.user &&
      client.readyState ===
        WebSocket.OPEN
    ) {

      safeSend(
        client,
        message
      );
    }
  }
}

// ============================================================
// ENVIAR ESTADO AGL A UN CLIENTE
// ============================================================

function sendFullState(ws) {

  safeSend(
    ws,
    {
      type: 'SYNC_FULL_STATE',
      data: {
        ...aglState
      }
    }
  );
}

// ============================================================
// ENVIAR ESTADO A TODOS LOS USUARIOS
// ============================================================

function broadcastAGLState() {

  const message = {

    type: 'AGL_STATE',

    data: {
      ...aglState
    }
  };

  for (const client of wss.clients) {

    if (
      client.user &&
      client.readyState ===
        WebSocket.OPEN
    ) {

      safeSend(
        client,
        message
      );
    }
  }
}

// ============================================================
// ENVIAR CONTROL AL ESP32
// ============================================================

function sendControlToDevice() {

  if (
    !deviceSocket ||
    deviceSocket.readyState !==
      WebSocket.OPEN
  ) {

    console.warn(
      '[AGL] No se puede enviar al ESP32: dispositivo desconectado.'
    );

    return false;
  }

  const message = {

    type: 'CONTROL_AGL',

    data: {
      ...aglState
    }
  };

  const ok =
    safeSend(
      deviceSocket,
      message
    );

  if (ok) {

    console.log(
      '[AGL] CONTROL_AGL enviado al ESP32:',
      JSON.stringify(
        aglState
      )
    );
  }

  return ok;
}

// ============================================================
// ACTUALIZAR AGL
// ============================================================

function updateAGL(data) {

  if (
    !data ||
    typeof data !== 'object'
  ) {
    return false;
  }

  // ----------------------------------------------------------
  // PISTA
  // ----------------------------------------------------------

  if (
    data.pista !== undefined
  ) {

    const value =
      Number(data.pista);

    if (
      Number.isInteger(value) &&
      value >= 0 &&
      value <= 5
    ) {

      aglState.pista = value;
    }
  }

  // ----------------------------------------------------------
  // TAXEO
  // ----------------------------------------------------------

  if (
    data.taxeo !== undefined
  ) {

    const value =
      Number(data.taxeo);

    if (
      Number.isInteger(value) &&
      value >= 0 &&
      value <= 5
    ) {

      aglState.taxeo = value;
    }
  }

  // ----------------------------------------------------------
  // PAPI
  // ----------------------------------------------------------

  if (
    data.papi !== undefined
  ) {

    const value =
      Number(data.papi);

    if (
      Number.isInteger(value) &&
      value >= 0 &&
      value <= 5
    ) {

      aglState.papi = value;
    }
  }

  // ----------------------------------------------------------
  // FARO
  // ----------------------------------------------------------

  if (
    data.faro !== undefined
  ) {

    if (
      data.faro === true ||
      data.faro === false
    ) {

      aglState.faro =
        data.faro;
    }
  }

  return true;
}

// ============================================================
// VALIDAR PERMISOS
// ============================================================

function canControlAGL(role) {

  return (
    role === 'gerente' ||
    role === 'AVE' ||
    role === 'TWR'
  );
}

// ============================================================
// EXPRESS HEALTH
// ============================================================

app.get(
  '/health',
  (req, res) => {

    res.json({
      ok: true,
      service: 'CCR',
      device:
        getDeviceStatus(),
      time:
        new Date().toISOString()
    });
  }
);

// ============================================================
// ESTADO PÚBLICO
// ============================================================

app.get(
  '/api/status',
  (req, res) => {

    res.json({

      ok: true,

      device:
        getDeviceStatus(),

      agl: {
        ...aglState
      }
    });
  }
);

// ============================================================
// ARCHIVOS DEL FRONTEND
// ============================================================

const PUBLIC_DIR =
  path.join(
    __dirname,
    'public'
  );

if (fs.existsSync(PUBLIC_DIR)) {

  app.use(
    express.static(
      PUBLIC_DIR
    )
  );
}

// ============================================================
// WEBSOCKET SERVER
// ============================================================

const wss =
  new WebSocket.Server({

    server,

    path: '/ws',

    // --------------------------------------------------------
    // VALIDACIÓN DEL ORIGIN
    // --------------------------------------------------------

    verifyClient: (
      info,
      done
    ) => {

      const origin =
        info.origin || '';

      // ESP32 normalmente no manda Origin.
      if (!origin) {

        done(true);

        return;
      }

      try {

        const url =
          new URL(origin);

        const host =
          url.hostname;

        const requestHost =
          String(
            info.req.headers.host ||
            ''
          ).split(':')[0];

        if (
          host ===
          requestHost
        ) {

          done(true);

          return;
        }

        // Render puede poner el host público.
        if (
          host.endsWith(
            '.onrender.com'
          )
        ) {

          done(true);

          return;
        }

        console.warn(
          '[WS] Origin rechazado:',
          origin
        );

        done(false, 403, 'Origin no permitido');

      } catch (err) {

        console.warn(
          '[WS] Origin inválido:',
          origin
        );

        done(false, 403, 'Origin inválido');
      }
    }
  });

// ============================================================
// CONEXIÓN WEBSOCKET
// ============================================================

wss.on(
  'connection',
  (ws, req) => {

    const remoteAddress =
      req.socket?.remoteAddress ||
      'desconocida';

    console.log();
    console.log(
      '[WS] ========================================'
    );

    console.log(
      '[WS] NUEVA CONEXIÓN WEBSOCKET'
    );

    console.log(
      '[WS] IP:',
      remoteAddress
    );

    console.log(
      '[WS] URL:',
      req.url
    );

    console.log(
      '[WS] User-Agent:',
      req.headers['user-agent'] ||
      '(ninguno)'
    );

    console.log(
      '[WS] Origin:',
      req.headers.origin ||
      '(ninguno)'
    );

    console.log(
      '[WS] ========================================'
    );

    ws.user = null;
    ws.isDevice = false;

    // --------------------------------------------------------
    // MENSAJES
    // --------------------------------------------------------

    ws.on(
      'message',
      async (raw) => {

        let data;

        try {

          data =
            JSON.parse(
              raw.toString()
            );

        } catch (err) {

          console.warn(
            '[WS] Mensaje recibido no es JSON.'
          );

          safeSend(
            ws,
            {
              type: 'ERROR',
              message: 'JSON inválido'
            }
          );

          return;
        }

        if (
          !data ||
          typeof data !== 'object'
        ) {

          return;
        }

        const type =
          data.type;

        console.log(
          '[WS] Mensaje:',
          type || '(sin type)'
        );

        // ====================================================
        // HELLO DEL ESP32
        // ====================================================

        if (type === 'HELLO') {

          console.log(
            '[WS] HELLO recibido.'
          );

          console.log(
            '[WS] Role:',
            data.role || '(sin role)'
          );

          console.log(
            '[WS] Token recibido:',
            data.token
              ? 'SI'
              : 'NO'
          );

          console.log(
            '[WS] Longitud token recibido:',
            String(
              data.token || ''
            ).length
          );

          // ----------------------------------------------
          // Debe ser ESP32
          // ----------------------------------------------

          if (
            ws.user ||
            data.role !== 'ESP32'
          ) {

            console.warn(
              '[WS] HELLO rechazado: role incorrecto o socket ya autenticado.'
            );

            ws.close(
              4003,
              'role inválido'
            );

            return;
          }

          // ----------------------------------------------
          // Verificar que exista DEVICE_TOKEN
          // ----------------------------------------------

          if (!DEVICE_TOKEN) {

            console.error(
              '[WS] ❌ DEVICE_TOKEN NO está configurado en Render.'
            );

            ws.close(
              4001,
              'device token no configurado'
            );

            return;
          }

          // ----------------------------------------------
          // Comparar token
          // ----------------------------------------------

          const tokenOK =
            safeEq(
              data.token || '',
              DEVICE_TOKEN
            );

          if (!tokenOK) {

            console.warn(
              '[WS] ❌ TOKEN DEL ESP32 INVÁLIDO.'
            );

            // IMPORTANTE:
            // Nunca imprimimos el token real.

            ws.close(
              4001,
              'token invalido'
            );

            return;
          }

          // ----------------------------------------------
          // ESP32 AUTENTICADO
          // ----------------------------------------------

          console.log(
            '[WS] ✅ TOKEN DEL ESP32 VÁLIDO.'
          );

          // Si había otro ESP32 conectado,
          // cerramos el anterior.

          if (
            deviceSocket &&
            deviceSocket !== ws
          ) {

            console.warn(
              '[WS] Ya había un ESP32 conectado. Cerrando conexión anterior.'
            );

            try {

              deviceSocket.close(
                4000,
                'reemplazado'
              );

            } catch (_) {}
          }

          deviceSocket = ws;

          ws.isDevice = true;

          deviceConnected = true;

          deviceLastSeen =
            new Date().toISOString();

          console.log(
            '[WS] ========================================'
          );

          console.log(
            '[WS] ✅ ESP32 AUTENTICADO Y CONECTADO'
          );

          console.log(
            '[WS] ========================================'
          );

          // ----------------------------------------------
          // Enviar estado completo
          // ----------------------------------------------

          safeSend(
            ws,
            {
              type:
                'SYNC_FULL_STATE',

              data: {
                ...aglState
              }
            }
          );

          console.log(
            '[WS] SYNC_FULL_STATE enviado al ESP32.'
          );

          broadcastDeviceStatus();

          return;
        }

        // ====================================================
        // PING
        // ====================================================

        if (type === 'PING') {

          if (ws.isDevice) {

            deviceLastSeen =
              new Date().toISOString();
          }

          safeSend(
            ws,
            {
              type: 'PONG'
            }
          );

          return;
        }

        // ====================================================
        // LOGIN
        // ====================================================

        if (type === 'LOGIN') {

          const ip =
            remoteAddress;

          if (
            !loginAllowed(ip)
          ) {

            console.warn(
              '[AUTH] Demasiados intentos de login desde:',
              ip
            );

            safeSend(
              ws,
              {
                type:
                  'LOGIN_FAIL',

                message:
                  'Demasiados intentos. Espere unos minutos.'
              }
            );

            return;
          }

          const username =
            String(
              data.username ||
              data.user ||
              ''
            ).trim();

          const password =
            String(
              data.password ||
              ''
            );

          console.log(
            '[AUTH] Intento de login:',
            username || '(vacío)'
          );

          // --------------------------------------------------
          // Usuario válido
          // --------------------------------------------------

          const account =
            users[username];

          if (
            !account ||
            !ROLES[username]
          ) {

            registerFailedLogin(ip);

            console.warn(
              '[AUTH] Usuario no válido.'
            );

            safeSend(
              ws,
              {
                type:
                  'LOGIN_FAIL',

                message:
                  'Usuario o contraseña incorrectos.'
              }
            );

            return;
          }

          // --------------------------------------------------
          // Verificar password
          // --------------------------------------------------

          const passwordOK =
            await verifyPassword(
              password,
              account.passwordHash
            );

          if (!passwordOK) {

            registerFailedLogin(ip);

            console.warn(
              '[AUTH] Contraseña incorrecta para:',
              username
            );

            safeSend(
              ws,
              {
                type:
                  'LOGIN_FAIL',

                message:
                  'Usuario o contraseña incorrectos.'
              }
            );

            return;
          }

          // --------------------------------------------------
          // LOGIN CORRECTO
          // --------------------------------------------------

          clearLoginAttempts(ip);

          const session =
            createSession(
              username,
              account.role
            );

          ws.user = {
            username,
            role:
              account.role,
            sessionId:
              session.sessionId
          };

          console.log(
            '[AUTH] ✅ Login correcto:',
            username,
            '(' +
              ROLES[
                account.role
              ] +
              ')'
          );

          safeSend(
            ws,
            {
              type:
                'LOGIN_OK',

              user: {
                username,
                role:
                  account.role,

                displayName:
                  ROLES[
                    account.role
                  ]
              },

              sessionId:
                session.sessionId,

              device:
                getDeviceStatus(),

              agl: {
                ...aglState
              }
            }
          );

          // También mandamos el formato
          // de sincronización que usa el sistema.

          sendFullState(ws);

          return;
        }

        // ====================================================
        // RESUME
        // ====================================================

        if (type === 'RESUME') {

          const sessionId =
            String(
              data.sessionId ||
              data.token ||
              ''
            );

          const session =
            getSession(
              sessionId
            );

          if (!session) {

            console.warn(
              '[AUTH] RESUME rechazado.'
            );

            safeSend(
              ws,
              {
                type:
                  'RESUME_FAIL',

                message:
                  'Sesión inválida o expirada.'
              }
            );

            return;
          }

          ws.user = {
            username:
              session.username,

            role:
              session.role,

            sessionId:
              session.sessionId
          };

          console.log(
            '[AUTH] Sesión restaurada:',
            session.username
          );

          safeSend(
            ws,
            {
              type:
                'RESUME_OK',

              user: {
                username:
                  session.username,

                role:
                  session.role,

                displayName:
                  ROLES[
                    session.role
                  ]
              },

              sessionId:
                session.sessionId,

              device:
                getDeviceStatus(),

              agl: {
                ...aglState
              }
            }
          );

          sendFullState(ws);

          return;
        }

        // ====================================================
        // LOGOUT
        // ====================================================

        if (type === 'LOGOUT') {

          if (ws.user) {

            console.log(
              '[AUTH] Logout:',
              ws.user.username
            );

            destroySession(
              ws.user.sessionId
            );

            ws.user = null;
          }

          safeSend(
            ws,
            {
              type:
                'LOGOUT_OK'
            }
          );

          return;
        }

        // ====================================================
        // CONTROL AGL
        // ====================================================

        if (type === 'CONTROL_AGL') {

          if (
            !ws.user
          ) {

            console.warn(
              '[AGL] CONTROL_AGL rechazado: usuario no autenticado.'
            );

            safeSend(
              ws,
              {
                type:
                  'ERROR',

                message:
                  'No autenticado.'
              }
            );

            return;
          }

          if (
            !canControlAGL(
              ws.user.role
            )
          ) {

            console.warn(
              '[AGL] CONTROL_AGL rechazado: sin permisos.'
            );

            safeSend(
              ws,
              {
                type:
                  'ERROR',

                message:
                  'Sin permisos para controlar AGL.'
              }
            );

            return;
          }

          let incoming =
            data.data;

          if (
            !incoming ||
            typeof incoming !==
              'object'
          ) {

            incoming = data;
          }

          updateAGL(
            incoming
          );

          console.log(
            '[AGL] Cambio realizado por:',
            ws.user.username
          );

          console.log(
            '[AGL] Estado:',
            JSON.stringify(
              aglState
            )
          );

          // ------------------------------------------------
          // Enviar al ESP32
          // ------------------------------------------------

          sendControlToDevice();

          // ------------------------------------------------
          // Informar a navegadores
          // ------------------------------------------------

          broadcastAGLState();

          // ------------------------------------------------
          // Confirmación
          // ------------------------------------------------

          safeSend(
            ws,
            {
              type:
                'CONTROL_AGL_OK',

              data: {
                ...aglState
              }
            }
          );

          return;
        }

        // ====================================================
        // SOLICITAR ESTADO
        // ====================================================

        if (
          type === 'GET_STATE' ||
          type === 'SYNC_REQUEST'
        ) {

          if (!ws.user) {

            safeSend(
              ws,
              {
                type:
                  'ERROR',

                message:
                  'No autenticado.'
              }
            );

            return;
          }

          safeSend(
            ws,
            {
              type:
                'SYNC_FULL_STATE',

              data: {
                ...aglState
              }
            }
          );

          safeSend(
            ws,
            {
              type:
                'DEVICE_STATUS',

              data:
                getDeviceStatus()
            }
          );

          return;
        }

        // ====================================================
        // KICK USER
        // ====================================================

        if (
          type === 'KICK_USER'
        ) {

          if (
            !ws.user ||
            ws.user.role !==
              'gerente'
          ) {

            safeSend(
              ws,
              {
                type:
                  'ERROR',

                message:
                  'Solo Gerente General puede expulsar usuarios.'
              }
            );

            return;
          }

          const target =
            String(
              data.username ||
              data.user ||
              ''
            ).trim();

          if (!target) {

            return;
          }

          for (
            const client
            of wss.clients
          ) {

            if (
              client.user &&
              client.user.username ===
                target
            ) {

              safeSend(
                client,
                {
                  type:
                    'KICKED',

                  message:
                    'Sesión cerrada por el administrador.'
                }
              );

              destroySession(
                client.user.sessionId
              );

              try {

                client.close(
                  4005,
                  'kicked'
                );

              } catch (_) {}
            }
          }

          console.log(
            '[AUTH] Usuario expulsado:',
            target
          );

          return;
        }

        // ====================================================
        // CHANGE PASSWORD
        // ====================================================

        if (
          type ===
          'CHANGE_PASSWORD'
        ) {

          if (!ws.user) {

            safeSend(
              ws,
              {
                type:
                  'ERROR',

                message:
                  'No autenticado.'
              }
            );

            return;
          }

          const username =
            ws.user.username;

          const currentPassword =
            String(
              data.currentPassword ||
              ''
            );

          const newPassword =
            String(
              data.newPassword ||
              ''
            );

          if (
            newPassword.length <
            8
          ) {

            safeSend(
              ws,
              {
                type:
                  'PASSWORD_FAIL',

                message:
                  'La nueva contraseña debe tener al menos 8 caracteres.'
              }
            );

            return;
          }

          const account =
            users[username];

          if (!account) {

            return;
          }

          const currentOK =
            await verifyPassword(
              currentPassword,
              account.passwordHash
            );

          if (!currentOK) {

            safeSend(
              ws,
              {
                type:
                  'PASSWORD_FAIL',

                message:
                  'Contraseña actual incorrecta.'
              }
            );

            return;
          }

          account.passwordHash =
            await hashPassword(
              newPassword
            );

          account.updatedAt =
            new Date().toISOString();

          saveUsers(users);

          console.log(
            '[AUTH] Contraseña cambiada:',
            username
          );

          safeSend(
            ws,
            {
              type:
                'PASSWORD_OK'
            }
          );

          return;
        }

        // ====================================================
        // MENSAJE DESCONOCIDO
        // ====================================================

        console.warn(
          '[WS] Tipo de mensaje no reconocido:',
          type
        );

        safeSend(
          ws,
          {
            type:
              'ERROR',

            message:
              'Tipo de mensaje no reconocido.'
          }
        );
      }
    );

    // ========================================================
    // CERRAR CONEXIÓN
    // ========================================================

    ws.on(
      'close',
      (code, reason) => {

        console.log();
        console.log(
          '[WS] ----------------------------------------'
        );

        console.log(
          '[WS] CONEXIÓN CERRADA'
        );

        console.log(
          '[WS] Código:',
          code
        );

        console.log(
          '[WS] Razón:',
          reason
            ? reason.toString()
            : '(ninguna)'
        );

        if (ws.isDevice) {

          if (
            deviceSocket === ws
          ) {

            deviceSocket =
              null;

            deviceConnected =
              false;

            deviceLastSeen =
              new Date().toISOString();

            console.log(
              '[WS] ❌ ESP32 desconectado.'
            );

            broadcastDeviceStatus();
          }
        }

        if (ws.user) {

          console.log(
            '[WS] Usuario desconectado:',
            ws.user.username
          );
        }

        console.log(
          '[WS] ----------------------------------------'
        );
        console.log();
      }
    );

    // ========================================================
    // ERROR
    // ========================================================

    ws.on(
      'error',
      (err) => {

        console.error(
          '[WS] ❌ ERROR:',
          err.message
        );

        if (ws.isDevice) {

          console.error(
            '[WS] El error corresponde al ESP32.'
          );
        }
      }
    );

    // ========================================================
    // PING/PONG DEL SOCKET
    // ========================================================

    ws.on(
      'pong',
      () => {

        if (ws.isDevice) {

          deviceLastSeen =
            new Date().toISOString();
        }
      }
    );
  }
);

// ============================================================
// DETECTAR ERROR DEL WEBSOCKET SERVER
// ============================================================

wss.on(
  'error',
  (err) => {

    console.error(
      '[WSS SERVER] ❌ ERROR:',
      err.message
    );
  }
);

// ============================================================
// FALLBACK FRONTEND
// ============================================================

if (
  fs.existsSync(
    path.join(
      PUBLIC_DIR,
      'index.html'
    )
  )
) {

  app.get(
    '*',
    (req, res) => {

      // No interferir con API.
      if (
        req.path.startsWith(
          '/api/'
        ) ||
        req.path ===
          '/health'
      ) {

        res.status(404).json({
          ok: false,
          error: 'Not found'
        });

        return;
      }

      res.sendFile(
        path.join(
          PUBLIC_DIR,
          'index.html'
        )
      );
    }
  );
}

// ============================================================
// INICIAR SERVIDOR
// ============================================================

async function start() {

  ensureDataDir();

  await initializeUsers();

  server.listen(
    PORT,
    '0.0.0.0',
    () => {

      console.log();
      console.log(
        '=========================================='
      );

      console.log(
        '     SERVIDOR CCR / AGL'
      );

      console.log(
        '=========================================='
      );

      console.log(
        'Servidor CCR activo en puerto',
        PORT
      );

      console.log(
        'WebSocket: /ws'
      );

      console.log(
        'DEVICE_TOKEN configurado:',
        DEVICE_TOKEN
          ? 'SI'
          : 'NO'
      );

      console.log(
        'Persistencia:',
        PERSISTENT
          ? 'SI'
          : 'NO'
      );

      console.log(
        'Usuarios configurados:',
        Object.keys(users)
          .join(', ') ||
          '(ninguno)'
      );

      console.log(
        '=========================================='
      );

      console.log();
    }
  );
}

// ============================================================
// MANEJO DE ERRORES
// ============================================================

process.on(
  'uncaughtException',
  (err) => {

    console.error(
      '[PROCESS] uncaughtException:',
      err
    );
  }
);

process.on(
  'unhandledRejection',
  (err) => {

    console.error(
      '[PROCESS] unhandledRejection:',
      err
    );
  }
);

// ============================================================
// ARRANCAR
// ============================================================

start();
