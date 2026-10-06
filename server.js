// ============================================================
// SERVIDOR CCR / AGL
// ESP32 <-> Render <-> Panel Web
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
const WS_PATH = '/ws';

const DEVICE_TOKEN = process.env.DEVICE_TOKEN || '';

const PERSISTENT = !!process.env.DATA_DIR;
const DATA_DIR =
  process.env.DATA_DIR || path.join(__dirname, 'data');

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
// ESTADO CCR / AGL
//
// El panel web utiliza:
// 1 = Pista
// 2 = Taxeo
// 3 = PAPI
// 4 = Faro
//
// Cada circuito 1-3 tiene state de 0 a 5.
// El faro utiliza beacon true/false.
// ============================================================

let aglState = {
  1: {
    state: 0
  },

  2: {
    state: 0
  },

  3: {
    state: 0
  },

  4: {
    beacon: false
  }
};

// ============================================================
// USUARIOS
// ============================================================

let users = {};

// ============================================================
// CONEXIÓN DEL ESP32
// ============================================================

let deviceSocket = null;

// ============================================================
// SESIONES
// ============================================================

const sessions = new Map();

// ============================================================
// FUNCIONES AUXILIARES
// ============================================================

function safeSend(ws, data) {
  try {
    if (
      ws &&
      ws.readyState === WebSocket.OPEN
    ) {
      ws.send(JSON.stringify(data));
      return true;
    }
  } catch (err) {
    console.error(
      '[WS] Error enviando:',
      err.message
    );
  }

  return false;
}

// ============================================================
// COMPARACIÓN SEGURA
// ============================================================

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

// ============================================================
// HASH PASSWORD
// ============================================================

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto
      .randomBytes(16)
      .toString('hex');

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
          `scrypt:${salt}:${derivedKey.toString(
            'hex'
          )}`
        );
      }
    );
  });
}

// ============================================================
// VERIFICAR PASSWORD
// ============================================================

function verifyPassword(password, stored) {
  return new Promise((resolve) => {
    try {
      if (
        !stored ||
        !stored.startsWith('scrypt:')
      ) {
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

          const storedBuffer =
            Buffer.from(
              storedHex,
              'hex'
            );

          if (
            storedBuffer.length !==
            derivedKey.length
          ) {
            resolve(false);
            return;
          }

          resolve(
            crypto.timingSafeEqual(
              storedBuffer,
              derivedKey
            )
          );
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

  if (!PERSISTENT) {
    console.log(
      '[AUTH] Persistencia desactivada.'
    );

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
        fs.readFileSync(
          USERS_FILE,
          'utf8'
        )
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
// CREAR USUARIOS
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

    try {
      users[role] = {
        role,
        name: ROLES[role],
        passwordHash:
          await hashPassword(password)
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
      JSON.stringify(
        users,
        null,
        2
      ),
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
// ESTADO DEL ESP32
// ============================================================

function isDeviceConnected() {
  return (
    deviceSocket &&
    deviceSocket.readyState ===
      WebSocket.OPEN
  );
}

// ============================================================
// USUARIOS CONECTADOS
// ============================================================

function getConnectedUsers() {
  const list = [];

  wss.clients.forEach((client) => {
    if (
      client.readyState ===
        WebSocket.OPEN &&
      client.user
    ) {
      list.push({
        user: client.user.user,
        role: client.user.role
      });
    }
  });

  return list;
}

// ============================================================
// ENVIAR USUARIOS CONECTADOS
// ============================================================

function broadcastConnectedUsers() {
  broadcastToBrowsers({
    type: 'SYNC_USERS',
    users: getConnectedUsers()
  });
}

// ============================================================
// ESTADO DEL ESP32 AL PANEL
// ============================================================

function broadcastDeviceStatus() {
  broadcastToBrowsers({
    type: 'DEVICE_STATUS',
    online: isDeviceConnected()
  });
}

// ============================================================
// ENVIAR A LOS NAVEGADORES
// ============================================================

function broadcastToBrowsers(message) {
  if (!wss) {
    return;
  }

  const text = JSON.stringify(message);

  wss.clients.forEach((client) => {
    if (
      client.readyState ===
        WebSocket.OPEN &&
      client.user
    ) {
      try {
        client.send(text);
      } catch (err) {
        console.error(
          '[WS] Error enviando al navegador:',
          err.message
        );
      }
    }
  });
}

// ============================================================
// SINCRONIZAR ESTADO COMPLETO
// ============================================================

function sendFullState(ws) {
  safeSend(ws, {
    type: 'SYNC_FULL_STATE',
    data: aglState
  });
}

// ============================================================
// ENVIAR ESTADO DEL GRUPO
// ============================================================

function sendGroupToDevice(
  group,
  state
) {
  if (!isDeviceConnected()) {
    console.warn(
      '[AGL] ESP32 no conectado.'
    );

    return false;
  }

  const message = {
    type: 'CONTROL_AGL',
    group: Number(group),
    state: Number(state)
  };

  console.log(
    '[AGL] Enviando al ESP32:',
    message
  );

  return safeSend(
    deviceSocket,
    message
  );
}

// ============================================================
// HTTP
// ============================================================

app.use(express.json());

// ============================================================
// PANEL WEB
// ============================================================

const PUBLIC_DIR =
  path.join(__dirname, 'public');

app.use(
  express.static(PUBLIC_DIR)
);

app.get('/', (req, res) => {
  const indexPath =
    path.join(
      PUBLIC_DIR,
      'index.html'
    );

  if (
    fs.existsSync(indexPath)
  ) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send(
      'No se encontró public/index.html'
    );
  }
});

// ============================================================
// HEALTH
// ============================================================

app.get('/health', (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'CCR / AGL',
    websocket: WS_PATH,
    deviceConnected:
      isDeviceConnected(),
    time: new Date().toISOString()
  });
});

// ============================================================
// API STATE
// ============================================================

app.get(
  '/api/state',
  (req, res) => {
    res.json({
      ok: true,
      data: aglState,
      deviceConnected:
        isDeviceConnected()
    });
  }
);

// ============================================================
// API INFO
// ============================================================

app.get(
  '/api/info',
  (req, res) => {
    res.json({
      service: 'Servidor CCR / AGL',
      websocket: WS_PATH,
      deviceTokenConfigured:
        !!DEVICE_TOKEN,
      persistent: PERSISTENT,
      users:
        Object.keys(users),
      deviceConnected:
        isDeviceConnected()
    });
  }
);

// ============================================================
// WEBSOCKET
// ============================================================

const wss =
  new WebSocket.Server({
    server,
    path: WS_PATH,

    verifyClient: (info) => {
      const origin =
        info.origin || '';

      console.log(
        `[WS] Intento de conexión. Origin: ${
          origin || '(sin Origin)'
        }`
      );

      // ESP32
      if (!origin) {
        return true;
      }

      // Archivo local
      if (
        origin === 'file://'
      ) {
        console.log(
          '[WS] Origin file:// permitido.'
        );

        return true;
      }

      // Localhost
      if (
        origin.startsWith(
          'http://localhost'
        ) ||
        origin.startsWith(
          'http://127.0.0.1'
        )
      ) {
        return true;
      }

      // HTTPS
      if (
        origin.startsWith(
          'https://'
        )
      ) {
        return true;
      }

      // HTTP
      if (
        origin.startsWith(
          'http://'
        )
      ) {
        return true;
      }

      console.warn(
        `[WS] Origin rechazado: ${origin}`
      );

      return false;
    }
  });

// ============================================================
// NUEVA CONEXIÓN
// ============================================================

wss.on(
  'connection',
  (ws, req) => {
    const remoteAddress =
      req.socket?.remoteAddress ||
      'desconocida';

    const origin =
      req.headers.origin ||
      '(sin Origin)';

    console.log('');
    console.log(
      '=========================================='
    );
    console.log(
      '[WS] NUEVA CONEXIÓN'
    );
    console.log(
      `IP: ${remoteAddress}`
    );
    console.log(
      `Origin: ${origin}`
    );
    console.log(
      '=========================================='
    );

    ws.user = null;
    ws.isDevice = false;
    ws.sessionToken = null;

    // ========================================================
    // MENSAJES
    // ========================================================

    ws.on(
      'message',
      async (raw) => {
        let data;

        try {
          data = JSON.parse(
            raw.toString()
          );
        } catch {
          console.warn(
            '[WS] JSON inválido.'
          );

          safeSend(ws, {
            type: 'ERROR',
            message:
              'JSON inválido'
          });

          return;
        }

        console.log(
          '[WS] Mensaje recibido:',
          data.type
        );

        // ====================================================
        // HELLO ESP32
        // ====================================================

        if (
          data.type === 'HELLO'
        ) {
          if (
            ws.user ||
            ws.isDevice
          ) {
            return;
          }

          if (
            data.role !== 'ESP32'
          ) {
            console.warn(
              '[WS] HELLO rechazado: rol inválido.'
            );

            return;
          }

          const token =
            String(
              data.token || ''
            );

          console.log(
            `[WS] HELLO ESP32 recibido. Token length=${token.length}`
          );

          if (!DEVICE_TOKEN) {
            console.error(
              '[WS] DEVICE_TOKEN no configurado.'
            );

            ws.close(
              4001,
              'token no configurado'
            );

            return;
          }

          if (
            !safeEq(
              token,
              DEVICE_TOKEN
            )
          ) {
            console.warn(
              '[WS] ❌ TOKEN ESP32 INVÁLIDO'
            );

            ws.close(
              4001,
              'token invalido'
            );

            return;
          }

          // ------------------------------------------------
          // ESP32 AUTENTICADO
          // ------------------------------------------------

          ws.isDevice = true;

          deviceSocket = ws;

          console.log(
            '[WS] ✅ ESP32 AUTENTICADO CORRECTAMENTE'
          );

          // Enviar estado completo
          sendFullState(ws);

          // Avisar al panel
          broadcastDeviceStatus();

          return;
        }

        // ====================================================
        // LOGIN
        // ====================================================

        if (
          data.type === 'LOGIN'
        ) {
          if (ws.isDevice) {
            return;
          }

          // IMPORTANTE:
          // El index.html manda:
          //
          // user
          // pass

          const username =
            String(
              data.user || ''
            ).trim();

          const password =
            String(
              data.pass || ''
            );

          console.log(
            `[AUTH] Intento de login: ${username}`
          );

          if (
            !ROLES[username]
          ) {
            console.warn(
              `[AUTH] Usuario desconocido: ${username}`
            );

            safeSend(ws, {
              type: 'LOGIN_FAIL',
              reason:
                'Usuario o contraseña incorrectos'
            });

            return;
          }

          const user =
            users[username];

          if (!user) {
            console.warn(
              `[AUTH] Usuario no configurado: ${username}`
            );

            safeSend(ws, {
              type: 'LOGIN_FAIL',
              reason:
                'Usuario no configurado'
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
              `[AUTH] ❌ Contraseña incorrecta para ${username}`
            );

            safeSend(ws, {
              type: 'LOGIN_FAIL',
              reason:
                'Usuario o contraseña incorrectos'
            });

            return;
          }

          // ------------------------------------------------
          // LOGIN CORRECTO
          // ------------------------------------------------

          const sessionToken =
            crypto
              .randomBytes(32)
              .toString('hex');

          ws.user = {
            user: username,
            role: ROLES[username]
          };

          ws.sessionToken =
            sessionToken;

          sessions.set(
            sessionToken,
            ws
          );

          console.log(
            `[AUTH] ✅ LOGIN CORRECTO: ${username}`
          );

          safeSend(ws, {
            type: 'LOGIN_OK',

            // El index.html espera
            user: username,

            // El index.html muestra
            // este valor como rol
            role: ROLES[username],

            // Para RESUME
            token: sessionToken
          });

          // Enviar estado
          sendFullState(ws);

          // Usuarios conectados
          broadcastConnectedUsers();

          // Estado ESP32
          broadcastDeviceStatus();

          return;
        }

        // ====================================================
        // RESUME
        // ====================================================

        if (
          data.type === 'RESUME'
        ) {
          const token =
            String(
              data.token || ''
            );

          const oldWs =
            sessions.get(token);

          if (
            !oldWs ||
            oldWs.readyState !==
              WebSocket.OPEN
          ) {
            safeSend(ws, {
              type: 'RESUME_FAIL'
            });

            return;
          }

          // Recuperar usuario
          ws.user =
            oldWs.user;

          ws.sessionToken =
            token;

          sessions.set(
            token,
            ws
          );

          // Cerrar conexión anterior
          if (
            oldWs !== ws
          ) {
            try {
              oldWs.close(
                1000,
                'sesion reanudada'
              );
            } catch {}
          }

          console.log(
            `[AUTH] Sesión reanudada: ${ws.user.user}`
          );

          safeSend(ws, {
            type: 'LOGIN_OK',
            user:
              ws.user.user,
            role:
              ws.user.role,
            token
          });

          sendFullState(ws);

          broadcastConnectedUsers();

          broadcastDeviceStatus();

          return;
        }

        // ====================================================
        // LOGOUT
        // ====================================================

        if (
          data.type === 'LOGOUT'
        ) {
          const username =
            ws.user?.user;

          if (
            ws.sessionToken
          ) {
            sessions.delete(
              ws.sessionToken
            );
          }

          ws.user = null;
          ws.sessionToken =
            null;

          console.log(
            `[AUTH] Logout: ${
              username || 'desconocido'
            }`
          );

          broadcastConnectedUsers();

          return;
        }

        // ====================================================
        // KICK USER
        // ====================================================

        if (
          data.type ===
          'KICK_USER'
        ) {
          if (
            !ws.user ||
            ws.user.user !==
              'gerente'
          ) {
            safeSend(ws, {
              type: 'ERROR',
              message:
                'Solo el Gerente puede desconectar usuarios.'
            });

            return;
          }

          const target =
            String(
              data.user || ''
            );

          if (
            target ===
            'gerente'
          ) {
            return;
          }

          let found = false;

          wss.clients.forEach(
            (client) => {
              if (
                client.user &&
                client.user.user ===
                  target
              ) {
                found = true;

                safeSend(
                  client,
                  {
                    type:
                      'KICK_USER',
                    user: target
                  }
                );

                if (
                  client.sessionToken
                ) {
                  sessions.delete(
                    client.sessionToken
                  );
                }

                try {
                  client.close(
                    4003,
                    'desconectado por gerente'
                  );
                } catch {}
              }
            }
          );

          console.log(
            `[AUTH] Gerente desconectó: ${target} (${found ? 'encontrado' : 'no conectado'})`
          );

          broadcastConnectedUsers();

          return;
        }

        // ====================================================
        // CAMBIAR PASSWORD
        // ====================================================

        if (
          data.type ===
          'CHANGE_PASSWORD'
        ) {
          if (
            !ws.user ||
            ws.user.user !==
              'gerente'
          ) {
            safeSend(ws, {
              type: 'ERROR',
              message:
                'Solo el Gerente puede cambiar contraseñas.'
            });

            return;
          }

          const target =
            String(
              data.user || ''
            ).trim();

          const newPass =
            String(
              data.newPass || ''
            );

          if (
            !ROLES[target]
          ) {
            safeSend(ws, {
              type: 'ERROR',
              message:
                'Usuario inválido.'
            });

            return;
          }

          if (
            newPass.length < 8
          ) {
            safeSend(ws, {
              type: 'ERROR',
              message:
                'La contraseña debe tener al menos 8 caracteres.'
            });

            return;
          }

          try {
            users[target] = {
              role: target,
              name:
                ROLES[target],
              passwordHash:
                await hashPassword(
                  newPass
                )
            };

            saveUsers();

            console.log(
              `[AUTH] Contraseña cambiada para ${target}`
            );

            safeSend(ws, {
              type:
                'PASSWORD_CHANGED',
              user: target,
              persistent:
                PERSISTENT
            });
          } catch (err) {
            console.error(
              '[AUTH] Error cambiando contraseña:',
              err.message
            );

            safeSend(ws, {
              type: 'ERROR',
              message:
                'No se pudo cambiar la contraseña.'
            });
          }

          return;
        }

        // ====================================================
        // CONTROL AGL
        // ====================================================

        if (
          data.type ===
          'CONTROL_AGL'
        ) {
          if (!ws.user) {
            console.warn(
              '[AGL] Comando rechazado: usuario no autenticado.'
            );

            safeSend(ws, {
              type: 'ERROR',
              message:
                'No autenticado'
            });

            return;
          }

          const group =
            Number(data.group);

          const state =
            Number(data.state);

          // ------------------------------------------------
          // PISTA / TAXEO / PAPI
          // ------------------------------------------------

          if (
            group >= 1 &&
            group <= 3
          ) {
            if (
              !Number.isFinite(
                state
              ) ||
              state < 0 ||
              state > 5
            ) {
              safeSend(ws, {
                type: 'ERROR',
                message:
                  'Intensidad inválida.'
              });

              return;
            }

            aglState[group]
              .state =
              Math.round(state);

            console.log(
              `[AGL] Usuario ${ws.user.user} -> Grupo ${group} -> Paso ${Math.round(state)}`
            );

            // Mandar al ESP32
            sendGroupToDevice(
              group,
              Math.round(state)
            );

            // Actualizar todos los paneles
            broadcastToBrowsers({
              type:
                'CONTROL_AGL',
              group,
              state:
                Math.round(state)
            });

            return;
          }

          // ------------------------------------------------
          // FARO
          // ------------------------------------------------

          if (group === 4) {
            const beacon =
              state === 1;

            aglState[4].beacon =
              beacon;

            console.log(
              `[AGL] Usuario ${ws.user.user} -> FARO -> ${
                beacon
                  ? 'ON'
                  : 'OFF'
              }`
            );

            // ESP32
            sendGroupToDevice(
              4,
              beacon ? 1 : 0
            );

            // Paneles
            broadcastToBrowsers({
              type:
                'CONTROL_AGL',
              group: 4,
              state:
                beacon ? 1 : 0
            });

            return;
          }

          safeSend(ws, {
            type: 'ERROR',
            message:
              'Grupo AGL inválido.'
          });

          return;
        }

        // ====================================================
        // GET STATE
        // ====================================================

        if (
          data.type ===
          'GET_STATE'
        ) {
          sendFullState(ws);

          return;
        }

        // ====================================================
        // PING
        // ====================================================

        if (
          data.type ===
          'PING'
        ) {
          safeSend(ws, {
            type: 'PONG',
            time: Date.now()
          });

          return;
        }

        // ====================================================
        // MENSAJE DESCONOCIDO
        // ====================================================

        console.warn(
          `[WS] Tipo desconocido: ${data.type}`
        );

        safeSend(ws, {
          type: 'ERROR',
          message:
            `Tipo de mensaje desconocido: ${data.type}`
        });
      }
    );

    // ========================================================
    // CERRAR CONEXIÓN
    // ========================================================

    ws.on(
      'close',
      (code, reason) => {
        console.log('');
        console.log(
          `[WS] Conexión cerrada. code=${code} reason=${reason || ''}`
        );

        // ----------------------------------------------------
        // ESP32
        // ----------------------------------------------------

        if (ws.isDevice) {
          if (
            deviceSocket === ws
          ) {
            deviceSocket =
              null;
          }

          console.log(
            '[WS] ❌ ESP32 desconectado.'
          );

          broadcastDeviceStatus();
        }

        // ----------------------------------------------------
        // USUARIO
        // ----------------------------------------------------

        if (ws.user) {
          console.log(
            `[AUTH] Usuario desconectado: ${ws.user.user}`
          );
        }

        if (
          ws.sessionToken
        ) {
          const current =
            sessions.get(
              ws.sessionToken
            );

          if (
            current === ws
          ) {
            sessions.delete(
              ws.sessionToken
            );
          }
        }

        broadcastConnectedUsers();
      }
    );

    // ========================================================
    // ERROR
    // ========================================================

    ws.on(
      'error',
      (err) => {
        console.error(
          '[WS] Error:',
          err.message
        );
      }
    );
  }
);

// ============================================================
// ERROR WEBSOCKET
// ============================================================

wss.on(
  'error',
  (err) => {
    console.error(
      '[WS] Error del servidor WebSocket:',
      err.message
    );
  }
);

// ============================================================
// ARRANCAR SERVIDOR
// ============================================================

async function startServer() {
  console.log('');
  console.log(
    '=========================================='
  );
  console.log(
    '        SERVIDOR CCR / AGL'
  );
  console.log(
    '=========================================='
  );

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
    `DEVICE_TOKEN configurado: ${
      DEVICE_TOKEN
        ? 'SI'
        : 'NO'
    }`
  );

  console.log(
    `Persistencia: ${
      PERSISTENT
        ? 'SI'
        : 'NO'
    }`
  );

  console.log(
    `Usuarios configurados: ${
      Object.keys(users)
        .join(', ') ||
      'ninguno'
    }`
  );

  console.log(
    `Panel web: ${
      fs.existsSync(
        path.join(
          PUBLIC_DIR,
          'index.html'
        )
      )
        ? 'OK'
        : 'NO ENCONTRADO'
    }`
  );

  console.log('');
  console.log(
    '=========================================='
  );

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
// INICIO
// ============================================================

startServer().catch(
  (err) => {
    console.error(
      '[FATAL] Error iniciando servidor:',
      err
    );

    process.exit(1);
  }
);

// ============================================================
// RENDER SIGTERM
// ============================================================

process.on(
  'SIGTERM',
  () => {
    console.log(
      '[SERVER] SIGTERM recibido. Cerrando...'
    );

    if (deviceSocket) {
      try {
        deviceSocket.close();
      } catch {}
    }

    server.close(
      () => {
        console.log(
          '[SERVER] Servidor cerrado.'
        );

        process.exit(0);
      }
    );
  }
);

// ============================================================
// SIGINT
// ============================================================

process.on(
  'SIGINT',
  () => {
    console.log(
      '[SERVER] SIGINT recibido. Cerrando...'
    );

    if (deviceSocket) {
      try {
        deviceSocket.close();
      } catch {}
    }

    server.close(
      () => {
        console.log(
          '[SERVER] Servidor cerrado.'
        );

        process.exit(0);
      }
    );
  }
);
