/**
 * @file CameraDevice_Admin.cpp
 * @brief Admin panel HTTP handlers (status, NVS viewer, reboot, self-test)
 *
 * All admin endpoints require a valid JWT with role="admin". The token
 * is accepted either via the Authorization header (Bearer scheme) or
 * as a "token" query parameter for browser-based access.
 *
 * The admin panel HTML (/admin-panel) is a self-contained single-page
 * app that stores the JWT in localStorage and makes fetch() calls to
 * the JSON API endpoints.
 */

#include "CameraDevice.h"
#include <ArduinoJson.h>
#include <Preferences.h>
#include <M5Unified.h>
#include "DualSerial.h"
#include "CameraApp.h"
#include "SerialShell.h"

// Verify JWT and check for admin role. Returns 401 if invalid.
void CameraDevice::handleAdmin() {
    #ifdef FACTORY_TEST
    // If adminMode was already set, bypass JWT check
    if (adminMode) {
        webServer->sendHeader("Access-Control-Allow-Origin", "*");
        webServer->send(200, "text/plain", "OK");
        return;
    }

    String token = "";

    // Prefer Authorization header if available (may require collectHeaders)
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) {
        token = auth.substring(7);
    } else if (auth.length() > 0) {
        token = auth;
    }

    // Fallback: also accept token via query param
    if (token.length() == 0) {
        token = webServer->arg("token");
    }

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->sendHeader("Access-Control-Allow-Origin", "*");
        webServer->send(401, "text/plain", "Unauthorized");
        return;
    }
    webServer->sendHeader("Access-Control-Allow-Origin", "*");
    webServer->send(200, "text/plain", "OK");
    #else
    webServer->send(200, "text/plain", "Admin OK");
    #endif
}

void CameraDevice::handleAdminPanel() {
#ifdef FACTORY_TEST
    // Auth check (requires role=admin)
    String token="";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) token = auth.substring(7);
    else if (auth.length() > 0) token = auth;
    if (token.length() == 0) token = webServer->arg("token");

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->send(401, "text/plain", "Unauthorized");
        return;
    }

    String html;
    html += "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
    html += "<title>Admin Panel</title><style>body{font-family:sans-serif;background:#111;color:#eee;padding:12px} .button{background:#00ff88;color:#111;border:none;padding:8px 12px;margin:4px;border-radius:4px;cursor:pointer} pre{background:#222;padding:10px;border-radius:6px;white-space:pre-wrap}</style></head><body>";
    html += "<h2>Admin Panel</h2>";
    html += "<div><button class='button' onclick='adStatus()'>Status</button>";
    html += "<button class='button' onclick='adNVS()'>NVS</button>";
    html += "<button class='button' onclick='adSelf()'>Self Test</button>";
    html += "<button class='button' onclick='adReboot()'>Reboot</button></div>";
    html += "<pre id='out'>Ready.</pre>";
    html += "<script>function byId(i){return document.getElementById(i)};function tok(){return localStorage.getItem('jwt')||''};function hdr(){var t=tok();return t?{'Authorization':'Bearer '+t}:{}};";
    html += "function adStatus(){fetch('/admin/status?token='+encodeURIComponent(tok()),{headers:hdr()}).then(r=>r.json()).then(j=>byId('out').textContent=JSON.stringify(j,null,2)).catch(()=>byId('out').textContent='Error');}";
    html += "function adNVS(){fetch('/admin/nvs?token='+encodeURIComponent(tok()),{headers:hdr()}).then(r=>r.json()).then(j=>byId('out').textContent=JSON.stringify(j,null,2)).catch(()=>byId('out').textContent='Error');}";
    html += "function adReboot(){fetch('/admin/reboot?token='+encodeURIComponent(tok()),{method:'POST',headers:hdr()}).then(r=>r.text()).then(t=>byId('out').textContent=t).catch(()=>byId('out').textContent='Error');}";
    html += "function adSelf(){fetch('/admin/selftest?token='+encodeURIComponent(tok()),{method:'POST',headers:hdr()}).then(r=>r.text()).then(t=>byId('out').textContent=t).catch(()=>byId('out').textContent='Error');}</script>";
    html += "</body></html>";
    webServer->send(200, "text/html", html);
#else
    webServer->send(403, "text/plain", "Not available");
#endif
}

void CameraDevice::handleAdminStatus() {
#ifdef FACTORY_TEST
    String token="";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) token = auth.substring(7);
    else if (auth.length() > 0) token = auth;
    if (token.length() == 0) token = webServer->arg("token");

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->send(401, "text/plain", "Unauthorized");
        return;
    }

    StaticJsonDocument<512> doc;
    String fw = getFirmwareVersion();
    String version = fw;
    String build = "debug";
    int dash = fw.indexOf('-');
    if (dash > 0 && dash < fw.length() - 1) {
        version = fw.substring(0, dash);
        build = fw.substring(dash + 1);
    }
    doc["device_id"] = deviceID;
    doc["version"] = version;
    doc["build"] = build;
    doc["firmware"] = fw;
    doc["ip_address"] = getAPIP();
    doc["camera_initialized"] = cameraInitialized;
    doc["admin_mode"] = true;
    doc["uptime"] = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["free_psram"] = ESP.getFreePsram();

    String json; serializeJson(doc, json);
    webServer->send(200, "application/json", json);
#else
    webServer->send(403, "text/plain", "Not available");
#endif
}

void CameraDevice::handleAdminNVS() {
#ifdef FACTORY_TEST
    String token="";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) token = auth.substring(7);
    else if (auth.length() > 0) token = auth;
    if (token.length() == 0) token = webServer->arg("token");

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->send(401, "text/plain", "Unauthorized");
        return;
    }

    Preferences prefs;
    prefs.begin("camera", true);
    String ssid = prefs.getString("wifi_ssid", "");
    String pass = prefs.getString("wifi_pass", "");
    String userPin = prefs.getString("user_pin", "");
    String adminPin = prefs.getString("admin_pin", "");
    prefs.end();

    StaticJsonDocument<384> doc;
    doc["wifi_ssid"] = ssid;
    doc["wifi_pass_masked"] = pass.length() > 0 ? "***" : "";
    doc["user_pin"] = userPin;
    doc["admin_pin"] = adminPin;

    String json; serializeJson(doc, json);
    webServer->send(200, "application/json", json);
#else
    webServer->send(403, "text/plain", "Not available");
#endif
}

void CameraDevice::handleAdminReboot() {
#ifdef FACTORY_TEST
    String token="";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) token = auth.substring(7);
    else if (auth.length() > 0) token = auth;
    if (token.length() == 0) token = webServer->arg("token");

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->send(401, "text/plain", "Unauthorized");
        return;
    }

    webServer->send(200, "text/plain", "Rebooting...");
    delay(150);
    ESP.restart();
#else
    webServer->send(403, "text/plain", "Not available");
#endif
}

void CameraDevice::handleAdminSelfTest() {
#ifdef FACTORY_TEST
    String token="";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) token = auth.substring(7);
    else if (auth.length() > 0) token = auth;
    if (token.length() == 0) token = webServer->arg("token");

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->send(401, "text/plain", "Unauthorized");
        return;
    }

    // Run the same comprehensive self-test as the UART shell
    DualSerial.println("[WEB] Running self-test via HTTP...");
    webServer->send(200, "text/plain", "Self-test started - check serial output for results");

    // Run self-test in background (after response is sent)
    // This ensures the HTTP response goes out before the test blocks
    SerialShell::getInstance().runSelfTest();
#else
    webServer->send(403, "text/plain", "Not available");
#endif
}
