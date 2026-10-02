const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// Servir la carpeta estática 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Servir siempre index.html en cualquier ruta estática
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Estado inicial global AGL del Aeropuerto Santa Elena
const aglState = {
  1: { masterOn: false, state: 0, fault: false }, // Pista
  2: { masterOn: false, state: 0, fault: false }, // Taxeo
  3: { masterOn: false, state: 0, fault: false }, // PAPI
  4: { beacon: false }                            // Faro
};

wss.on('connection', (ws, req) => {
  console.log(`[WebSocket] Nuevo cliente conectado desde: ${req.socket.remoteAddress}`);

  // 1. Enviar el estado actual inmediatamente al conectar
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

        // 2. Transmitir el nuevo estado a TODOS los clientes y al ESP32
        broadcast(JSON.stringify({ type: 'CONTROL_AGL', group, state, aglState }));
      }
    } catch (err) {
      console.error("[WebSocket] Error al procesar mensaje JSON:", err);
    }
  });

  ws.on('close', () => {
    console.log('[WebSocket] Cliente desconectado');
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
  console.log(`[CCR Server] Servidor activo escuchando en puerto ${PORT}`);
});
