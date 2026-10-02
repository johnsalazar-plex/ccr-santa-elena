const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// Servir archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Ruta principal para servir index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Estado global AGL
const aglState = {
  1: { masterOn: false, state: 0, fault: false }, // Pista
  2: { masterOn: false, state: 0, fault: false }, // Taxeo
  3: { masterOn: false, state: 0, fault: false }, // PAPI
  4: { beacon: false }                            // Faro
};

wss.on('connection', (ws) => {
  console.log("Cliente o ESP32 conectado correctamente");

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

        // Retransmitir cambios a todos los dispositivos conectados
        broadcast(JSON.stringify({ type: 'CONTROL_AGL', group, state, aglState }));
      }
    } catch (err) {
      console.error("Error al procesar mensaje JSON:", err);
    }
  });

  ws.on('close', () => {
    console.log("Cliente desconectado");
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
  console.log("Servidor CCR activo en puerto " + PORT);
});
