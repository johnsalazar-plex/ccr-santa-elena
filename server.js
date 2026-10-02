const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// Servir la carpeta public
app.use(express.static(path.join(__dirname, 'public')));

// Estado inicial global AGL
const aglState = {
  1: { masterOn: false, state: 0, fault: false },
  2: { masterOn: false, state: 0, fault: false },
  3: { masterOn: false, state: 0, fault: false },
  4: { beacon: false }
};

wss.on('connection', (ws) => {
  console.log('Cliente / ESP32 conectado via WebSocket');

  // Enviar estado actual al conectar
  ws.send(JSON.stringify({ type: 'SYNC_FULL_STATE', data: aglState }));

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'CONTROL_AGL') {
        const { group, state } = data;
        
        if (group <= 3) {
          aglState[group].state = state;
          aglState[group].masterOn = state > 0;
        } else if (group === 4) {
          aglState[4].beacon = (state === 1);
        }

        // Reenviar a TODOS los navegadores y al ESP32 conectado
        broadcast(JSON.stringify(data));
      }
    } catch (err) {
      console.error("Error al procesar mensaje JSON:", err);
    }
  });
});

function broadcast(payload) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor CCR escuchando en el puerto ${PORT}`);
});
