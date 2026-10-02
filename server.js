const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Estado global sincronizado
const aglState = {
  1: { masterOn: false, state: 0 },
  2: { masterOn: false, state: 0 },
  3: { masterOn: false, state: 0 },
  4: { beacon: false }
};

const activeUsers = new Map(); // socket -> username

wss.on('connection', (ws) => {
  // Sincronizar estado completo y lista de usuarios inmediatamente
  ws.send(JSON.stringify({ type: 'SYNC_FULL_STATE', data: aglState }));
  broadcastUsers();

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'CONTROL_AGL') {
        const { group, state } = data;
        if (group <= 3) {
          aglState[group].state = state;
          aglState[group].masterOn = (state > 0);
        } else if (group === 4) {
          aglState[4].beacon = (state === 1);
        }
        // Retransmitir a TODOS los clientes y ESP32 en vivo
        broadcast(JSON.stringify({ type: 'CONTROL_AGL', group, state, aglState }));
      } 
      else if (data.type === 'USER_JOINED') {
        activeUsers.set(ws, data.user);
        broadcastUsers();
      } 
      else if (data.type === 'USER_LEFT') {
        activeUsers.delete(ws);
        broadcastUsers();
      } 
      else if (data.type === 'KICK_USER') {
        // Expulsar al usuario seleccionado
        for (let [clientWs, username] of activeUsers.entries()) {
          if (username === data.user) {
            clientWs.send(JSON.stringify({ type: 'KICK_USER', user: data.user }));
            activeUsers.delete(clientWs);
            break;
          }
        }
        broadcastUsers();
      }
    } catch (err) {
      console.error("Error procesando mensaje:", err);
    }
  });

  ws.on('close', () => {
    activeUsers.delete(ws);
    broadcastUsers();
  });
});

function broadcast(payload) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

function broadcastUsers() {
  const usersList = Array.from(new Set(activeUsers.values()));
  broadcast(JSON.stringify({ type: 'SYNC_USERS', users: usersList }));
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor CCR activo en puerto ${PORT}`);
});
