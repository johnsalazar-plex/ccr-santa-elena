// ============================================================
// SERVIDOR CCR / AGL
// ESP32 <-> WebSocket <-> Panel Web
// Compatible con Render
// ============================================================

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============================================================
// CONFIGURACIÓN
// ============================================================

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;

const DEVICE_TOKEN = process.env.DEVICE_TOKEN || '';

const PERSISTENT = !!process.env.DATA_DIR;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

const USERS_FILE = path.join(DATA_DIR, 'users.json');

const WS_PATH = '/ws';

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
// ESTADO DEL SISTEMA AGL
// ============================================================

let aglState = {
  pista: 0,
  taxeo: 0,
  papi: 0,
  faro: false
};

// Corregimos nombre internamente para evitar problemas
aglState = {
  pista: 0,
  taxeo: 0,
  papi: 0,
  faro: false
};

// ============================================================
// USUARIOS
// ============================================================

let users = {};

// ============================================================
// FUNCIONES AUXILIARES
// ============================================================

function safeSend(ws, data) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
    }
  } catch (err) {
    console.error('[WS] Error enviando mensaje:', err.message);
  }
}


// Comparación segura de strings
function safeEq(a, b) {
  try {
    const aa = Buffer.from(String(a || ''));
    const bb = Buffer.from(String(b || ''));

    if (aa.length !== bb.length) {
      return false;
    }

    return crypto.timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}


// Hash de contraseña
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


// Verificar contraseña
function verifyPassword(password, stored) {
  return new Promise((resolve) => {
    try {
      if (!stored || !stored.startsWith('scrypt:')) {
        resolve(false);
        return;
      }

      const parts = stored.split(':');

      if (parts.length !== 3) {
        resolve(false);
        return;
      }

      const salt = parts[1];
      const storedHex = parts[2];

      crypto.scrypt(
        String(password),
        salt,
        64,
        (err, derivedKey) => {
          if (err) {
            resolve(false);
            return;
          }

          const a = Buffer.from(storedHex, 'hex');
          const b = derivedKey;

          if (a.length !== b.length) {
            resolve(false);
            return;
          }

          resolve(crypto.timingSafeEqual(a, b));
        }
      );
    } catch {
      resolve(false);
    }
  });
}


// ============================================================
// CARGAR USUARIOS
// ============================================================

function loadUsers() {
  users = {};

  // Si no existe DATA_DIR, usamos solamente las variables
  // PASS_GERENTE, PASS_AVE y PASS_TWR.
  if (!PERSISTENT) {
    console.log('[AUTH] Persistencia desactivada.');
    return;
  }

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, {
        recursive: true
      });
    }

    if (fs.existsSync(USERS_FILE)) {
      users = JSON.parse(
        fs.readFileSync(USERS_FILE, 'utf8')
      );

      console.log(
        '[AUTH] Usuarios cargados desde users.json'
      );
    }
  } catch (err) {
    console.error(
      '[AUTH] Error leyendo users.json:',
      err.message
    );

    users = {};
  }
}


// ============================================================
// CREAR USUARIOS DESDE VARIABLES DE RENDER
// ============================================================

async function initializeUsers() {

  const roleNames = Object.keys(ROLES);

  for (const role of roleNames) {

    const envName = ENV_PASS[role];
    const password = process.env[envName];

    if (!password) {
      console.warn(
        `[AVISO] Falta la variable ${envName}: "${role}" no podrá iniciar sesión.`
      );

      continue;
    }

    try {
      users[role] = {
        role,
        name: ROLES[role],
        passwordHash: await hashPassword(password)
      };

      console.log(
        `[AUTH] Usuario '${role}' inicializado.`
      );

    } catch (err) {

      console.error(
        `[AUTH] Error creando usuario ${role}:`,
        err.message
      );
    }
  }
}


// ============================================================
// GUARDAR USUARIOS
// ============================================================

function saveUsers() {

  if (!PERSISTENT) {
    return;
  }

  try {

    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, {
        recursive: true
      });
    }

    fs.writeFileSync(
      USERS_FILE,
      JSON.stringify(users, null, 2),
      'utf8'
    );

  } catch (err) {

    console.error(
      '[AUTH] Error guardando usuarios:',
      err.message
    );
  }
}


// ============================================================
// ESTADO DE DISPOSITIVOS
// ============================================================

let deviceSocket = null;

function isDeviceConnected() {

  return (
    deviceSocket &&
    deviceSocket.readyState === WebSocket.OPEN
  );
}


// ============================================================
// ENVIAR ESTADO DEL ESP32
// ============================================================

function broadcastDeviceStatus() {

  const connected = isDeviceConnected();

  broadcastToBrowsers({
    type: 'DEVICE_STATUS',
    connected
  });
}


// ============================================================
// ENVIAR A TODOS LOS NAVEGADORES
// ============================================================

function broadcastToBrowsers(message) {

  const text = JSON.stringify(message);

  wss.clients.forEach((client) => {

    if (
      client.readyState === WebSocket.OPEN &&
      client.user
    ) {

      try {
        client.send(text);
      } catch (err) {
        console.error(
          '[WS] Error enviando a navegador:',
          err.message
        );
      }
    }
  });
}


// ============================================================
// HTTP
// ============================================================

app.use(express.json());


// ------------------------------------------------------------
// HEALTH CHECK
// ------------------------------------------------------------

app.get('/health', (req, res) => {

  res.status(200).json({
    ok: true,
    service: 'CCR / AGL',
    websocket: WS_PATH,
    deviceConnected: isDeviceConnected(),
    time: new Date().toISOString()
  });

});


// ------------------------------------------------------------
// ESTADO
// ------------------------------------------------------------

app.get('/api/state', (req, res) => {

  res.json({
    ok: true,
    data: aglState,
    deviceConnected: isDeviceConnected()
  });

});


// ------------------------------------------------------------
// INFORMACIÓN
// ------------------------------------------------------------

app.get('/api/info', (req, res) => {

  res.json({
    service: 'Servidor CCR / AGL',
    websocket: WS_PATH,
    deviceTokenConfigured: !!DEVICE_TOKEN,
    persistent: PERSISTENT,
    users: Object.keys(users),
    deviceConnected: isDeviceConnected()
  });

});


// ============================================================
// WEBSOCKET
// ============================================================

const wss = new WebSocket.Server({
  server,
  path: WS_PATH,

  // IMPORTANTE:
  // Permitimos:
  // - conexiones del ESP32 sin Origin
  // - file:// para el panel abierto localmente
  // - http://localhost
  // - https://rcc-aimm-by-ave.onrender.com
  // - otros orígenes HTTPS
  verifyClient: (info) => {

    const origin = info.origin || '';

    console.log(
      `[WS] Intento de conexión. Origin: ${origin || '(sin Origin)'}`
    );

    // ESP32 normalmente no manda Origin
    if (!origin) {
      return true;
    }

    // Panel abierto directamente desde un archivo
    if (origin === 'file://') {
      console.log(
        '[WS] Origin file:// permitido.'
      );

      return true;
    }

    // Navegación local
    if (
      origin.startsWith('http://localhost') ||
      origin.startsWith('http://127.0.0.1')
    ) {

      return true;
    }

    // Render / HTTPS
    if (origin.startsWith('https://')) {
      return true;
    }

    // HTTP
    if (origin.startsWith('http://')) {
      return true;
    }

    console.warn(
      `[WS] Origin rechazado: ${origin}`
    );

    return false;
  }
});


// ============================================================
// CONEXIÓN WEBSOCKET
// ============================================================

wss.on('connection', (ws, req) => {

  const remoteAddress =
    req.socket?.remoteAddress || 'desconocida';

  const origin =
    req.headers.origin || '(sin Origin)';

  console.log('');
  console.log('==========================================');
  console.log('[WS] NUEVA CONEXIÓN');
  console.log(`IP: ${remoteAddress}`);
  console.log(`Origin: ${origin}`);
  console.log('==========================================');


  ws.user = null;
  ws.isDevice = false;


  // ----------------------------------------------------------
  // MENSAJES
  // ----------------------------------------------------------

  ws.on('message', async (raw) => {

    let data;

    try {

      data = JSON.parse(
        raw.toString()
      );

    } catch (err) {

      console.warn(
        '[WS] Mensaje JSON inválido.'
      );

      safeSend(ws, {
        type: 'ERROR',
        message: 'JSON inválido'
      });

      return;
    }


    console.log(
      '[WS] Mensaje recibido:',
      data.type
    );


    // ========================================================
    // HELLO DEL ESP32
    // ========================================================

    if (data.type === 'HELLO') {

      if (ws.user || ws.isDevice) {

        console.warn(
          '[WS] HELLO duplicado.'
        );

        return;
      }


      // Debe ser ESP32
      if (data.role !== 'ESP32') {

        console.warn(
          `[WS] HELLO rechazado. role=${data.role}`
        );

        safeSend(ws, {
          type: 'ERROR',
          message: 'Rol inválido'
        });

        return;
      }


      // Verificar token
      const receivedToken =
        String(data.token || '');

      console.log(
        `[WS] HELLO ESP32 recibido. Token length=${receivedToken.length}`
      );


      if (!DEVICE_TOKEN) {

        console.error(
          '[WS] DEVICE_TOKEN NO está configurado en Render.'
        );

        safeSend(ws, {
          type: 'ERROR',
          message: 'DEVICE_TOKEN no configurado'
        });

        ws.close(
          4001,
          'token no configurado'
        );

        return;
      }


      if (
        !safeEq(
          receivedToken,
          DEVICE_TOKEN
        )
      ) {

        console.warn(
          '[WS] ❌ TOKEN ESP32 INVÁLIDO'
        );

        safeSend(ws, {
          type: 'ERROR',
          message: 'Token inválido'
        });

        ws.close(
          4001,
          'token invalido'
        );

        return;
      }


      // ======================================================
      // ESP32 AUTENTICADO
      // ======================================================

      ws.isDevice = true;

      deviceSocket = ws;

      console.log(
        '[WS] ✅ ESP32 AUTENTICADO CORRECTAMENTE'
      );


      // Enviar estado actual al ESP32
      safeSend(ws, {
        type: 'SYNC_FULL_STATE',
        data: aglState
      });


      // Avisar al panel
      broadcastDeviceStatus();

      return;
    }


    // ========================================================
    // LOGIN DE USUARIO
    // ========================================================

    if (data.type === 'LOGIN') {

      if (ws.isDevice) {

        safeSend(ws, {
          type: 'LOGIN_ERROR',
          message: 'ESP32 no puede iniciar sesión como usuario'
        });

        return;
      }


      const role =
        String(data.role || '');

      const password =
        String(data.password || '');


      if (!ROLES[role]) {

        console.warn(
          `[AUTH] Rol desconocido: ${role}`
        );

        safeSend(ws, {
          type: 'LOGIN_ERROR',
          message: 'Usuario o contraseña incorrectos'
        });

        return;
      }


      const user = users[role];


      if (!user) {

        console.warn(
          `[AUTH] Usuario ${role} no configurado`
        );

        safeSend(ws, {
          type: 'LOGIN_ERROR',
          message: 'Usuario no configurado'
        });

        return;
      }


      const valid =
        await verifyPassword(
          password,
          user.passwordHash
        );


      if (!valid) {

        console.warn(
          `[AUTH] ❌ Login rechazado para ${role}`
        );

        safeSend(ws, {
          type: 'LOGIN_ERROR',
          message: 'Usuario o contraseña incorrectos'
        });

        return;
      }


      // Login correcto
      ws.user = {
        role,
        name: ROLES[role]
      };


      console.log(
        `[AUTH] ✅ Usuario conectado: ${role}`
      );


      safeSend(ws, {
        type: 'LOGIN_OK',
        user: {
          role,
          name: ROLES[role]
        },
        data: aglState,
        deviceConnected: isDeviceConnected()
      });


      return;
    }


    // ========================================================
    // CONTROL AGL
    // ========================================================

    if (data.type === 'CONTROL_AGL') {

      // Solo usuarios autenticados
      if (!ws.user) {

        console.warn(
          '[WS] CONTROL_AGL rechazado: usuario no autenticado.'
        );

        safeSend(ws, {
          type: 'ERROR',
          message: 'No autenticado'
        });

        return;
      }


      const control =
        data.data || data.state || {};


      // ------------------------------------------------------
      // PISTA
      // ------------------------------------------------------

      if (control.pista !== undefined) {

        const value =
          Number(control.pista);

        if (
          Number.isFinite(value) &&
          value >= 0 &&
          value <= 5
        ) {

          aglState.pista = Math.round(value);
        }
      }


      // ------------------------------------------------------
      // TAXEO
      // ------------------------------------------------------

      if (control.taxeo !== undefined) {

        const value =
          Number(control.taxeo);

        if (
          Number.isFinite(value) &&
          value >= 0 &&
          value <= 5
        ) {

          aglState.taxeo = Math.round(value);
        }
      }


      // ------------------------------------------------------
      // PAPI
      // ------------------------------------------------------

      if (control.papi !== undefined) {

        const value =
          Number(control.papi);

        if (
          Number.isFinite(value) &&
          value >= 0 &&
          value <= 5
        ) {

          aglState.papi = Math.round(value);
        }
      }


      // ------------------------------------------------------
      // FARO
      // ------------------------------------------------------

      if (control.faro !== undefined) {

        aglState.faro =
          Boolean(control.faro);
      }


      console.log(
        `[AGL] Cambio por ${ws.user.role}:`,
        aglState
      );


      // ------------------------------------------------------
      // ENVIAR AL ESP32
      // ------------------------------------------------------

      if (isDeviceConnected()) {

        safeSend(deviceSocket, {
          type: 'CONTROL_AGL',
          data: aglState
        });

        console.log(
          '[AGL] Estado enviado al ESP32.'
        );

      } else {

        console.warn(
          '[AGL] ESP32 desconectado. Estado guardado en servidor.'
        );
      }


      // ------------------------------------------------------
      // ACTUALIZAR TODOS LOS NAVEGADORES
      // ------------------------------------------------------

      broadcastToBrowsers({
        type: 'STATE_UPDATE',
        data: aglState,
        deviceConnected: isDeviceConnected()
      });


      return;
    }


    // ========================================================
    // SOLICITAR ESTADO
    // ========================================================

    if (data.type === 'GET_STATE') {

      safeSend(ws, {
        type: 'STATE_UPDATE',
        data: aglState,
        deviceConnected: isDeviceConnected()
      });

      return;
    }


    // ========================================================
    // PING
    // ========================================================

    if (data.type === 'PING') {

      safeSend(ws, {
        type: 'PONG',
        time: Date.now()
      });

      return;
    }


    // ========================================================
    // MENSAJE DESCONOCIDO
    // ========================================================

    console.warn(
      `[WS] Tipo de mensaje desconocido: ${data.type}`
    );

    safeSend(ws, {
      type: 'ERROR',
      message: `Tipo de mensaje desconocido: ${data.type}`
    });

  });


  // ----------------------------------------------------------
  // CIERRE
  // ----------------------------------------------------------

  ws.on('close', (code, reason) => {

    console.log('');
    console.log(
      `[WS] Conexión cerrada. code=${code} reason=${reason || ''}`
    );


    // Si era el ESP32
    if (ws.isDevice) {

      if (deviceSocket === ws) {
        deviceSocket = null;
      }

      console.log(
        '[WS] ❌ ESP32 desconectado.'
      );

      broadcastDeviceStatus();
    }


    // Si era usuario
    if (ws.user) {

      console.log(
        `[AUTH] Usuario desconectado: ${ws.user.role}`
      );
    }

  });


  // ----------------------------------------------------------
  // ERROR
  // ----------------------------------------------------------

  ws.on('error', (err) => {

    console.error(
      '[WS] Error:',
      err.message
    );

  });


  // ----------------------------------------------------------
  // MENSAJE INICIAL
  // ----------------------------------------------------------

  safeSend(ws, {
    type: 'SERVER_READY',
    websocket: WS_PATH,
    time: Date.now()
  });

});


// ============================================================
// ERROR DEL SERVIDOR WEBSOCKET
// ============================================================

wss.on('error', (err) => {

  console.error(
    '[WS] Error del servidor:',
    err.message
  );

});


// ============================================================
// INICIO
// ============================================================

async function startServer() {

  console.log('');
  console.log('==========================================');
  console.log('        SERVIDOR CCR / AGL');
  console.log('==========================================');


  loadUsers();

  await initializeUsers();

  saveUsers();


  console.log('');
  console.log(
    `Servidor CCR activo en puerto ${PORT}`
  );

  console.log(
    `WebSocket: ${WS_PATH}`
  );

  console.log(
    `DEVICE_TOKEN configurado: ${DEVICE_TOKEN ? 'SI' : 'NO'}`
  );

  console.log(
    `Persistencia: ${PERSISTENT ? 'SI' : 'NO'}`
  );

  console.log(
    `Usuarios configurados: ${Object.keys(users).join(', ') || 'ninguno'}`
  );

  console.log('');
  console.log('==========================================');


  server.listen(
    PORT,
    '0.0.0.0',
    () => {

      console.log(
        `[HTTP] Escuchando en 0.0.0.0:${PORT}`
      );

    }
  );
}


// ============================================================
// ARRANCAR
// ============================================================

startServer().catch((err) => {

  console.error(
    '[FATAL] No se pudo iniciar el servidor:',
    err
  );

  process.exit(1);

});


// ============================================================
// MANEJO DE CIERRE
// ============================================================

process.on('SIGTERM', () => {

  console.log(
    '[SERVER] SIGTERM recibido. Cerrando...'
  );

  server.close(() => {

    console.log(
      '[SERVER] Servidor cerrado.'
    );

    process.exit(0);
  });

});


process.on('SIGINT', () => {

  console.log(
    '[SERVER] SIGINT recibido. Cerrando...'
  );

  server.close(() => {

    console.log(
      '[SERVER] Servidor cerrado.'
    );

    process.exit(0);
  });

});
