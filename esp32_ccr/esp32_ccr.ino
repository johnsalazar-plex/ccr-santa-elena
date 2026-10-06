#include <WiFi.h>
#include <WebSocketsClient.h>
#include <ArduinoJson.h>
#include "secrets.h"   // WIFI_SSID, WIFI_PASSWORD, DEVICE_TOKEN  (NO subir a GitHub)

const char* CLOUD_SERVER = "rcc-aimm-by-ave.onrender.com";
const int   CLOUD_PORT   = 443;
const char* CLOUD_PATH   = "/ws";

WebSocketsClient webSocket;

const bool RELAY_ACTIVE_LOW = false;

const int PINS_PISTA[5] = {13, 12, 14, 27, 26};
const int PINS_TAXEO[5] = {25, 33, 32, 15, 4};
const int PINS_PAPI[5]  = {16, 17, 5, 18, 19};
const int PIN_FARO      = 21;

int  currentStep[4] = {0, 0, 0, 0};
int  targetStep[4]  = {0, 0, 0, 0};
bool beaconState    = false;

unsigned long lastStepTime[4] = {0, 0, 0, 0};
const unsigned long STEP_INTERVAL = 2000; // mínimo 2 s entre pasos físicos de cada grupo
unsigned long lastWifiTry = 0;

void setRelay(int pin, bool state) {
  digitalWrite(pin, RELAY_ACTIVE_LOW ? (!state) : state);
}

void applyRelaysForGroup(int group, int step) {
  const int* pins = NULL;
  if (group == 1) pins = PINS_PISTA;
  else if (group == 2) pins = PINS_TAXEO;
  else if (group == 3) pins = PINS_PAPI;
  if (pins == NULL) return;

  for (int i = 0; i < 5; i++) {
    setRelay(pins[i], (i + 1) == step);
  }
}

void setTarget(int group, int state) {
  if (group < 1 || group > 3) return;
  targetStep[group] = constrain(state, 0, 5);
}

// Sigue la rampa física aunque se caiga la red: los relés no dependen de la conexión
void processGradualSteps(int group) {
  if (currentStep[group] == targetStep[group]) return;
  if (millis() - lastStepTime[group] < STEP_INTERVAL) return;

  lastStepTime[group] = millis();
  currentStep[group] += (targetStep[group] > currentStep[group]) ? 1 : -1;

  applyRelaysForGroup(group, currentStep[group]);
  Serial.printf("[ESP32] Grupo %d -> Paso fisico %d\n", group, currentStep[group]);
}

void handleMessage(uint8_t* payload, size_t length) {
  StaticJsonDocument<512> doc;
  if (deserializeJson(doc, payload, length)) return;

  const char* msgType = doc["type"] | "";

  if (strcmp(msgType, "SYNC_FULL_STATE") == 0) {
    JsonObject data = doc["data"];
    for (int g = 1; g <= 3; g++) {
      char key[2] = { (char)('0' + g), 0 };
      setTarget(g, data[key]["state"] | 0);
    }
    beaconState = data["4"]["beacon"] | false;
    setRelay(PIN_FARO, beaconState);
  }
  else if (strcmp(msgType, "CONTROL_AGL") == 0) {
    int group = doc["group"] | 0;
    int state = doc["state"] | 0;

    if (group >= 1 && group <= 3) {
      setTarget(group, state);
    } else if (group == 4) {
      beaconState = (state == 1);
      setRelay(PIN_FARO, beaconState);
    }
  }
}

void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
  switch (type) {
    case WStype_DISCONNECTED:
      Serial.println("[ESP32] Desconectado (los relés mantienen su estado)");
      break;

    case WStype_CONNECTED: {
      Serial.println("[ESP32] Conectado al Servidor CCR");
      // Se identifica con la clave del dispositivo; sin ella el servidor lo rechaza
      StaticJsonDocument<200> hello;
      hello["type"]  = "HELLO";
      hello["role"]  = "ESP32";
      hello["token"] = DEVICE_TOKEN;
      String out;
      serializeJson(hello, out);
      webSocket.sendTXT(out);
      break;
    }

    case WStype_TEXT:
      handleMessage(payload, length);
      break;

    default:
      break;
  }
}

void setup() {
  Serial.begin(115200);

  for (int i = 0; i < 5; i++) {
    pinMode(PINS_PISTA[i], OUTPUT); setRelay(PINS_PISTA[i], false);
    pinMode(PINS_TAXEO[i], OUTPUT); setRelay(PINS_TAXEO[i], false);
    pinMode(PINS_PAPI[i], OUTPUT);  setRelay(PINS_PAPI[i], false);
  }
  pinMode(PIN_FARO, OUTPUT); setRelay(PIN_FARO, false);

  for (int g = 1; g <= 3; g++) lastStepTime[g] = millis() - STEP_INTERVAL;

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);          // sin ahorro de energía: menos retraso
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  webSocket.beginSSL(CLOUD_SERVER, CLOUD_PORT, CLOUD_PATH);
  webSocket.onEvent(webSocketEvent);
  webSocket.setReconnectInterval(3000);
  webSocket.enableHeartbeat(15000, 4000, 2); // detecta conexión muerta y reconecta
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    webSocket.loop();
  } else if (millis() - lastWifiTry > 10000) {
    lastWifiTry = millis();
    Serial.println("[WiFi] Reconectando...");
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  }

  for (int g = 1; g <= 3; g++) {
    processGradualSteps(g);
  }
}
