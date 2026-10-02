```javascript
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// Servir la carpeta publica
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Estado inicial global AGL del Aeropuerto Santa Elena
const aglState = {
  1: { masterOn: false, state: 0, fault: false }, // Pista (0-5)
  2: { masterOn: false, state: 0, fault: false }, // Taxeo (0-5)
  3: { masterOn: false, state: 0, fault: false }, // PAPI (0-5)
  4: { beacon: false }                            // Faro (0-1)
};

wss.on('connection', (ws, req) => {
  console.log(`[WebSocket] Nuevo cliente o ESP32 conectado`);

  // Sincronizacion inicial del estado completo al conectar
  ws.send(JSON.stringify({ type: 'SYNC_FULL_STATE', data: aglState }));

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'CONTROL_AGL') {
        const { group, state } = data;

        if (group >= 1 && group <= 3) {
          aglState[group].state = state;
          aglState[group].masterOn = state > 0;
        } else if (group === 4) {
          aglState[4].beacon = (state === 1);
        }

        // Transmision masiva (broadcast) en tiempo real a todos los clientes conectados
        broadcast(JSON.stringify({ 
          type: 'CONTROL_AGL', 
          group: group, 
          state: state, 
          aglState: aglState 
        }));
      }
    } catch (err) {
      console.error("[WebSocket] Error al procesar JSON:", err);
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
  console.log(`[CCR Server] Servidor activo en puerto ${PORT}`);
});
```
