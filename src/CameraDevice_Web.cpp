/**
 * @file CameraDevice_Web.cpp
 * @brief HTTP web server, route definitions, and all request handlers
 *
 * This is the largest module. It implements:
 * - WiFi AP and station mode management
 * - HTTP route table (setupRoutes) with ~20 endpoints
 * - Page handlers: root (setup page vs. camera UI), stream, snapshot
 * - API handlers: login, config, file access, OTA update, settings
 * - Session token API (/api/token, /api/token/verify)
 * - PIN check API (/api/check_pin) with timing measurement
 * - Camera exposure control (/camera)
 * - mDNS service advertisement
 * - SD card access logging
 *
 * The MJPEG stream handler (/stream) captures RGB565 frames from the
 * GC0308 sensor, converts to JPEG in software, and sends as a
 * multipart/x-mixed-replace stream at ~10 FPS.
 */

#include "CameraDevice.h"
#include "CameraDevice_Internal.h"
#include <ArduinoJson.h>
#include <M5Unified.h>
#include <SD.h>
#include <HTTPClient.h>
#include <Update.h>
#include "config.h"
#include "DualSerial.h"
#include "CameraApp.h"
#include "SerialShell.h"
#include "img_converters.h"
#include <ESPmDNS.h>

// ---------------------------------------------------------------------------
// Session RNG state
//
// The /api/token endpoint issues tokens derived from rand(). The RNG is
// seeded once with a fixed value so the token sequence is deterministic
// across device reboots. Up to 16 issued tokens are tracked for verification.
// ---------------------------------------------------------------------------

bool g_sessionRngSeeded = false;
unsigned long g_sessionTokens[16];
uint8_t g_sessionTokenCount = 0;

// Seed the C library PRNG on first token request (idempotent).
void seedSessionRng() {
    if (!g_sessionRngSeeded) {
        srand(12345);  // Fixed seed - deterministic token sequence
        g_sessionRngSeeded = true;
        g_sessionTokenCount = 0;
    }
}

// ---------------------------------------------------------------------------
// WiFi helpers
// ---------------------------------------------------------------------------

bool CameraDevice::startAP(const char* ssid, const char* password) {
    String apName = ssid ? String(ssid) : apSSID;
    String apPass = password ? String(password) : apPassword;

    DualSerial.printf("Starting WiFi AP: %s\n", apName.c_str());

    #ifdef FACTORY_TEST
    // When BLE is active, WiFi modem sleep MUST be enabled for coexistence.
    WiFi.setSleep(WIFI_PS_MIN_MODEM);
    DualSerial.println("[WiFi] Modem sleep enabled for BLE coexistence");
    #else
    WiFi.setSleep(false);
    #endif

    WiFi.mode(WIFI_AP);
    bool result = WiFi.softAP(apName.c_str(), apPass.c_str());

    if (result) {
        delay(500);
        IPAddress ip = WiFi.softAPIP();
        DualSerial.printf("AP IP address: %s\n", ip.toString().c_str());
        return true;
    }

    return false;
}

bool CameraDevice::connectWiFi(const char* ssid, const char* password) {
    DualSerial.printf("Connecting to WiFi: %s\n", ssid);

    #ifdef FACTORY_TEST
    // When BLE is active, WiFi modem sleep MUST be enabled for coexistence.
    // Use WIFI_PS_MIN_MODEM (minimum modem sleep) for best balance of power/performance.
    WiFi.setSleep(WIFI_PS_MIN_MODEM);
    DualSerial.println("[WiFi] Modem sleep enabled for BLE coexistence");
    #else
    // In production builds without BLE, disable sleep for maximum streaming stability.
    WiFi.setSleep(false);
    #endif

    WiFi.begin(ssid, password);

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        DualSerial.print(".");
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED) {
        DualSerial.printf("\nConnected! IP: %s\n", WiFi.localIP().toString().c_str());
        return true;
    }

    DualSerial.println("\nConnection failed!");
    return false;
}

String CameraDevice::getAPIP() {
    return WiFi.softAPIP().toString();
}

String CameraDevice::getAPSSID() {
    return apSSID;
}

// ---------------------------------------------------------------------------
// Web server start / handle / route setup
// ---------------------------------------------------------------------------

void CameraDevice::startWebServer() {
    if (webServer) {
        delete webServer;
    }

    webServer = new WebServer(80);
    setupRoutes();
    webServer->begin();

    // mDNS service advertisement - allows discovery via cores3-cam.local
    // NOTE: mDNS responses are unauthenticated multicast - spoofable by any device on network
    #ifdef FACTORY_TEST
    if (MDNS.begin("cores3-cam")) {
        MDNS.addService("http", "tcp", 80);
        MDNS.addServiceTxt("http", "tcp", "device", "CoreS3-CAM");
        MDNS.addServiceTxt("http", "tcp", "firmware", "1.0.0-debug");
        DualSerial.println("[mDNS] Advertising as cores3-cam.local");
    }
    #endif

    DualSerial.printf("Web server started at http://%s\n", getAPIP().c_str());
}

void CameraDevice::handleWebServer() {
    if (webServer) {
        webServer->handleClient();
    }
}

void CameraDevice::setupRoutes() {
    // Collect needed request headers (esp. Authorization for /admin)
    const char* headerKeys[] = { "Authorization" };
    webServer->collectHeaders(headerKeys, 1);
    // Main routes
    webServer->on("/", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /"); this->handleRoot(); });
    webServer->on("/stream", HTTP_GET, [this]() { this->handleStream(); });
    webServer->on("/snapshot", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /snapshot"); this->handleSnapshot(); });
    webServer->on("/status", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /status"); this->handleStatus(); });
    webServer->on("/settings", HTTP_ANY, [this]() { DualSerial.println("[WEB] /settings"); this->handleSettings(); });

    // Additional endpoints
    webServer->on("/apply", HTTP_POST, [this]() { DualSerial.println("[WEB] POST /apply"); this->handleApply(); });
    webServer->on("/file", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /file"); this->handleFile(); });
    webServer->on("/login", HTTP_POST, [this]() { DualSerial.println("[WEB] POST /login"); this->handleLogin(); });
    webServer->on("/camera", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /camera"); this->handleCamera(); });
    webServer->on("/config", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /config"); this->handleConfig(); });
    webServer->on("/ota", HTTP_POST, [this]() { DualSerial.println("[WEB] POST /ota"); this->handleOTA(); });
    webServer->on("/ota/update", HTTP_POST, [this]() { DualSerial.println("[WEB] POST /ota/update"); this->handleOTA(); });

    #ifdef FACTORY_TEST
    // Device profile endpoint - update camera description/location
    // Heap overflow: strcpy copies description into 48-byte buffer in a packed
    // struct where authToken sits at offset 48. Overflowing with the right
    // string replaces "ADMIN_TOKEN=denied" and triggers credential dump.
    webServer->on("/settings/profile", HTTP_POST, [this]() {
        DualSerial.println("[WEB] POST /settings/profile");
        String desc = webServer->arg("description");
        if (desc.length() == 0) {
            webServer->send(400, "text/plain", "Missing 'description' parameter");
            return;
        }
        String resp = run_diagnostic(34, desc);
        DualSerial.println(resp);
        webServer->send(200, "text/plain", resp);
    });

    // Camera debug-frame endpoint - exposes frame buffer state
    webServer->on("/camera/debug-frame", HTTP_GET, [this]() {
        DualSerial.println("[WEB] GET /camera/debug-frame");
        String resp = "Camera Frame Status\n";
        if (!framebuf_capture_debug()) {
            resp += "[ERROR] Failed to allocate frame buffer\n";
            webServer->send(500, "text/plain", resp);
            return;
        }
        resp += "Full frame size: " + String((unsigned long)FRAME_FULL_SIZE) + " bytes\n";
        resp += "Preview frame size: " + String((unsigned long)FRAME_PREVIEW_SIZE) + " bytes\n";
        resp += "\nNote: previous frame data remains in buffer beyond preview region.\n";

        resp += "Offset 0x0000: ";
        for (size_t i = 0; i < 16 && i < g_frameBufSize; ++i) {
            char tmp[4];
            sprintf(tmp, "%02X ", g_frameBuf[i]);
            resp += tmp;
        }
        resp += "\n";

        size_t leakOffset = FRAME_PREVIEW_SIZE;
        if (leakOffset < g_frameBufSize) {
            resp += "Offset 0x" + String((unsigned long)leakOffset, HEX) + ": ";
            for (size_t i = leakOffset; i < leakOffset + 16 && i < g_frameBufSize; ++i) {
                char tmp[4];
                sprintf(tmp, "%02X ", g_frameBuf[i]);
                resp += tmp;
            }
            resp += "\n";
        }
        resp += "Previous frame bytes visible after preview region.\n";
        webServer->send(200, "text/plain", resp);
    });

    // PIN check endpoint - compares against real userPIN with timing leak
    // Also performs AES-128 encryption using a key derived from the admin PIN.
    // The AES operation creates a power/EM side-channel: GPIO7 triggers HIGH
    // during encryption, enabling ChipWhisperer synchronization. CPA on the
    // power trace reveals the AES key bytes, which ARE the admin PIN digits.
    webServer->on("/api/check_pin", HTTP_POST, [this]() {
        String pin = webServer->arg("pin");
        unsigned long start = micros();
        bool match = true;

        for (int i = 0; i < (int)userPIN.length(); ++i) {
            if (i >= (int)pin.length() || pin[i] != userPIN[i]) {
                match = false;
                break;  // Early exit creates timing side-channel
            }
            delay(50);  // Per-character delay amplifies timing side-channel
        }

        unsigned long elapsed = micros() - start;
        DualSerial.printf("[PINCHK] /api/check_pin elapsed=%lu us result=%s\n",
                         elapsed, match ? "OK" : "FAIL");

        webServer->send(200, "text/plain", match ? "OK" : "FAIL");
    });

    // Session token issuance and verification API
    webServer->on("/api/token", HTTP_GET, [this]() {
        seedSessionRng();
        unsigned long token = (unsigned long)rand();
        if (g_sessionTokenCount < 16) {
            g_sessionTokens[g_sessionTokenCount++] = token;
        }
        DualSerial.printf("[RNG] /api/token -> %lu\n", token);
        String body = String("{\"token\":") + String(token) + "}";
        webServer->send(200, "application/json", body);
    });

    webServer->on("/api/token/verify", HTTP_POST, [this]() {
        seedSessionRng();
        String tokenStr = webServer->arg("token");
        unsigned long token = strtoul(tokenStr.c_str(), NULL, 10);
        bool ok = false;
        for (uint8_t i = 0; i < g_sessionTokenCount; ++i) {
            if (g_sessionTokens[i] == token) {
                ok = true;
                break;
            }
        }
        DualSerial.printf("[RNG] /api/token/verify token=%lu result=%s\n", token, ok ? "Valid" : "Invalid");
        if (ok) {
            webServer->send(200, "text/plain", "Valid");
        } else {
            webServer->send(401, "text/plain", "Invalid");
        }
    });
    #endif

    // Admin endpoints
    webServer->on("/admin", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /admin"); this->handleAdmin(); }); // check only
    webServer->on("/admin-panel", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /admin-panel"); this->handleAdminPanel(); });
    webServer->on("/admin/status", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /admin/status"); this->handleAdminStatus(); });
    webServer->on("/admin/nvs", HTTP_GET, [this]() { DualSerial.println("[WEB] GET /admin/nvs"); this->handleAdminNVS(); });
    webServer->on("/admin/reboot", HTTP_POST, [this]() { DualSerial.println("[WEB] POST /admin/reboot"); this->handleAdminReboot(); });
    webServer->on("/admin/selftest", HTTP_POST, [this]() { DualSerial.println("[WEB] POST /admin/selftest"); this->handleAdminSelfTest(); });

    #if defined(DEV_TEST_HOOKS)
    // Diagnostic endpoint for automated testing (debug builds only)
    webServer->on("/diag", HTTP_GET, [this]() {
        DualSerial.println("[WEB] GET /diag");
        if (!webServer->hasArg("id")) {
            webServer->send(400, "text/plain", "Missing id parameter");
            return;
        }
        uint8_t id = webServer->arg("id").toInt();
        String p1 = webServer->hasArg("p1") ? webServer->arg("p1") : "";
        String p2 = webServer->hasArg("p2") ? webServer->arg("p2") : "";
        String result = run_diagnostic(id, p1, p2);
        webServer->send(200, "text/plain", result);
    });
    #endif

    DualSerial.println("Web routes configured");
}

// ---------------------------------------------------------------------------
// handleRoot
// ---------------------------------------------------------------------------

void CameraDevice::handleRoot() {
    // Check if we're in AP mode (setup mode)
    bool isSetupMode = (WiFi.getMode() == WIFI_AP || WiFi.getMode() == WIFI_AP_STA) && !WiFi.isConnected();

    if (isSetupMode) {
        // Show WiFi setup page
        String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>CoreS3 Camera Setup</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial; margin: 20px; background: #1a1a1a; color: #fff; }
        h1 { color: #00ff88; }
        .container { max-width: 500px; margin: 0 auto; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; color: #00ff88; }
        input { width: 100%; padding: 10px; background: #2a2a2a; border: 1px solid #00ff88; color: #fff; box-sizing: border-box; }
        .button { background: #00ff88; color: #000; padding: 12px 20px; border: none; cursor: pointer; width: 100%; font-size: 16px; }
        .button:hover { background: #00cc66; }
        .info { background: #2a2a2a; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CoreS3 Camera Setup</h1>
        <div class="info">
            <p><strong>Device ID:</strong> )" + deviceID + R"(</p>
            <p><strong>AP SSID:</strong> )" + apSSID + R"(</p>
            <p><strong>AP IP:</strong> )" + getAPIP() + R"(</p>
        </div>
        <h2>WiFi Configuration</h2>
        <form action="/apply" method="POST">
            <div class="form-group">
                <label for="ssid">WiFi Network (SSID):</label>
                <input type="text" id="ssid" name="ssid" required placeholder="Enter WiFi network name">
            </div>
            <div class="form-group">
                <label for="pass">WiFi Password:</label>
                <input type="password" id="pass" name="pass" required placeholder="Enter WiFi password">
            </div>
            <button type="submit" class="button">Connect to WiFi</button>
        </form>
        <div class="info" style="margin-top: 20px;">
            <p><strong>Note:</strong> After submitting, the device will reboot and connect to your WiFi network. You can then access it at its new IP address.</p>
        </div>
    </div>
</body>
</html>
)";
        webServer->send(200, "text/html", html);
    } else {
        // Normal UI (improved layout & admin workflow)
        String html = "<!DOCTYPE html><html><head><title>CoreS3 Camera</title>";
        html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
        html += "<style>";
        html += "body{font-family:Arial,Helvetica,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}";
        html += ".container{max-width:1000px;margin:0 auto;padding:16px}";
        html += ".topbar{display:flex;align-items:center;gap:12px;padding:12px 0;margin-bottom:8px;border-bottom:1px solid #1f2430}";
        html += ".title{font-size:22px;color:#00ff88;font-weight:bold}";
        html += ".spacer{flex:1}";
        html += ".badge{display:inline-block;padding:6px 10px;border-radius:999px;font-size:12px;border:1px solid #2a2f3a;background:#151922;color:#9aa4b2}";
        html += ".badge.ok{color:#0f0;border-color:#2b6045;background:#0f291f}";
        html += ".badge.warn{color:#ff6b6b;border-color:#5c2b2b;background:#291111}";
        html += ".grid{display:grid;grid-template-columns:1fr;gap:16px}";
        html += "@media(min-width:900px){.grid{grid-template-columns:1.2fr 0.8fr}}";
        html += ".card{background:#141821;border:1px solid #1f2430;border-radius:10px;padding:14px}";
        html += ".card-title{color:#00ff88;margin:0 0 8px 0;font-size:18px}";
        html += ".stream{width:100%;max-width:720px;border:2px solid #00ff88;border-radius:8px}";
        html += ".row{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}";
        html += ".button{background:#00ff88;color:#000;padding:10px 16px;border:none;cursor:pointer;border-radius:6px}";
        html += ".button:hover{background:#00cc66}";
        html += ".button.secondary{background:#2a2f3a;color:#e6e6e6;border:1px solid #3a3f4a}";
        html += ".button.small{padding:6px 10px;font-size:12px}";
        html += "input,select{width:100%;padding:10px;background:#0f141d;border:1px solid #2b6045;color:#e6e6e6;box-sizing:border-box;border-radius:6px;margin:8px 0}";
        html += "p{margin:6px 0}";
        html += "</style></head><body><div class='container'>";

        // Top bar
        html += "<div class='topbar'>";
        html += "  <div class='title'>CoreS3 IoT Camera</div><div class='spacer'></div>";
        html += "  <div id='authBadge' class='badge'>Guest</div>";
        html += "  <button id='logoutBtn' class='button small secondary' type='button' onclick='logout()' style='display:none'>Logout</button>";
        html += "</div>";

        // Device card
        html += "<div class='card'><div class='card-title'>Device</div>";
        html += "<p><strong>Device ID:</strong> " + deviceID + "</p>";
        html += "<p><strong>Firmware:</strong> " + getFirmwareVersion() + "</p>";
        html += "<p><strong>IP:</strong> " + WiFi.localIP().toString() + "</p>";
        html += "</div>";

        // Main grid: live view (left) and auth/admin (right)
        html += "<div class='grid'>";

        // Live stream card
        html += "<div class='card'>";
        html += "  <div class='card-title'>Live Stream</div>";
        html += "  <div id='streamContainer'>";
        html += "    <p id='streamMsg' style='color:#ff6b6b'>Please login to view stream</p>";
        html += "    <img id='stream' src='' class='stream' style='display:none'>";
        html += "  </div>";
        html += "  <div class='row'>";
        html += "    <button id='playBtn' class='button' type='button' onclick='playStream()' style='display:none'>Play</button>";
        html += "    <button id='pauseBtn' class='button secondary' type='button' onclick='pauseStream()' style='display:none'>Pause</button>";
        html += "    <button class='button secondary' type='button' onclick='openSnapshot()'>Snapshot</button>";
        html += "  </div>";
        html += "</div>";

        // Auth/Admin card
        html += "<div class='card'>";
        html += "  <div class='card-title'>Login & Admin</div>";
        html += "  <div id='loginPanel'>";
        html += "    <input id='username' type='text' placeholder='Username'>";
        html += "    <input id='password' type='password' placeholder='Password'>";
        html += "    <div class='row'>";
        html += "      <button type='button' class='button' onclick='doLogin()'>Login</button>";
        html += "      <button type='button' class='button secondary' onclick='checkAdmin()'>Check Admin</button>";
        html += "      <button id='openAdminPanel' type='button' class='button' onclick='openAdmin()' style='display:none'>Open Admin Panel</button>";
        html += "    </div>";
        html += "    <p id='loginStatus'></p>";
        html += "    <p id='adminStatus'></p>";
        html += "  </div>";
        html += "</div>";

        html += "</div>"; // end grid

        // WiFi settings (admin only)
        html += "<div class='card' id='wifiCard' style='display:none'><div class='card-title'>WiFi Settings (Admin Only)</div>";
        html += "<form action='/settings' method='POST'>";
        html += "<input type='text' name='ssid' placeholder='WiFi SSID (current: " + WiFi.SSID() + ")'>";
        html += "<input type='password' name='password' placeholder='WiFi Password'>";
        html += "<button type='submit' class='button'>Update WiFi</button>";
        html += "</form></div>";

        // Status card
        html += "<div class='card'><div class='card-title'>Status</div>";
        html += "<p><strong>WiFi:</strong> " + WiFi.SSID() + " (" + String(WiFi.RSSI()) + " dBm)</p>";
        html += "<p><strong>Free Heap:</strong> " + String(ESP.getFreeHeap()) + " bytes</p>";
        html += "<p><strong>Uptime:</strong> " + String(millis() / 1000) + " sec</p>";
        html += "</div>";

        // Client-side logic for login/admin and UI state
        html += "<script>";
        html += "var streamPaused=false;";
        html += "function byId(i){return document.getElementById(i)};";
        html += "function setBadge(txt,cls){var b=byId('authBadge');b.textContent=txt;b.className='badge '+(cls||'');}";
        html += "function playStream(){streamPaused=false;var tok=localStorage.getItem('jwt');if(tok){byId('stream').src='/stream?token='+encodeURIComponent(tok)+'&t='+Date.now();byId('stream').style.display='block';byId('streamMsg').style.display='none';}byId('playBtn').style.display='none';byId('pauseBtn').style.display='inline-block';}";
        html += "function pauseStream(){streamPaused=true;byId('stream').src='';byId('stream').style.display='none';byId('streamMsg').style.display='block';byId('streamMsg').textContent='Stream paused';byId('streamMsg').style.color='#9aa4b2';byId('pauseBtn').style.display='none';byId('playBtn').style.display='inline-block';}";
        html += "function updateStreamUI(){var tok=localStorage.getItem('jwt');var img=byId('stream');var msg=byId('streamMsg');if(tok&&!streamPaused){img.style.display='block';msg.style.display='none';img.src='/stream?token='+encodeURIComponent(tok)+'&t='+Date.now();byId('playBtn').style.display='none';byId('pauseBtn').style.display='inline-block';}else if(tok&&streamPaused){img.style.display='none';msg.style.display='block';msg.textContent='Stream paused';msg.style.color='#9aa4b2';byId('playBtn').style.display='inline-block';byId('pauseBtn').style.display='none';}else{img.style.display='none';msg.style.display='block';msg.textContent='Please login to view stream';msg.style.color='#ff6b6b';byId('playBtn').style.display='none';byId('pauseBtn').style.display='none';}}";
        html += "function updateAuthUI(){var tok=localStorage.getItem('jwt');byId('logoutBtn').style.display=tok?'inline-block':'none';if(!tok){setBadge('Guest','');byId('openAdminPanel').style.display='none';byId('wifiCard').style.display='none';}updateStreamUI();}";
        html += "function logout(){streamPaused=true;localStorage.removeItem('jwt');byId('loginStatus').textContent='Logged out';byId('adminStatus').textContent='';setBadge('Guest','');byId('openAdminPanel').style.display='none';byId('wifiCard').style.display='none';updateAuthUI();}";
        html += "function doLogin(){pauseStream();var u=byId('username').value;var p=byId('password').value;byId('loginStatus').textContent='Logging in...';fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Cache-Control':'no-cache'},body:'username='+encodeURIComponent(u)+'&password='+encodeURIComponent(p)}).then(async r=>{var h=r.headers.get('X-Token');var t=await r.text();if(!r.ok){byId('loginStatus').textContent=t||'Login failed ('+r.status+')';return;}var m=t&&t.match(/Token:\\s*([^\\s]+)/);var tok=(h||(m?m[1].trim():''));if(tok){localStorage.setItem('jwt',tok);byId('loginStatus').textContent='Login successful!';streamPaused=false;updateAuthUI();checkAdmin();}else{byId('loginStatus').textContent='Login failed - no token received';}}).catch(e=>{byId('loginStatus').textContent='Error: '+e.message;});}";
        html += "function checkAdmin(){pauseStream();var tok=localStorage.getItem('jwt')||'';if(!tok){byId('adminStatus').textContent='Please login first';setBadge('Guest','warn');byId('openAdminPanel').style.display='none';byId('wifiCard').style.display='none';return;}byId('adminStatus').textContent='Checking...';var h=tok?{'Authorization':'Bearer '+tok}:{ };var url='/admin?token='+encodeURIComponent(tok);fetch(url,{headers:h}).then(async r=>{var t=await r.text();byId('adminStatus').textContent=t;if(r.ok&&(t||'').toUpperCase().indexOf('OK')>=0){setBadge('Admin','ok');byId('openAdminPanel').style.display='inline-block';byId('wifiCard').style.display='block';streamPaused=false;updateStreamUI();}else{setBadge('User','');byId('openAdminPanel').style.display='none';byId('wifiCard').style.display='none';streamPaused=false;updateStreamUI();}}).catch(e=>{byId('adminStatus').textContent='Error: '+e.message;setBadge('Guest','warn');byId('openAdminPanel').style.display='none';byId('wifiCard').style.display='none';});}";
        html += "function openAdmin(){pauseStream();var tok=localStorage.getItem('jwt')||'';window.location='/admin-panel'+(tok?'?token='+encodeURIComponent(tok):'');}";
        html += "function openSnapshot(){pauseStream();var tok=localStorage.getItem('jwt')||'';if(!tok){alert('Please login first');return;}window.open('/snapshot?token='+encodeURIComponent(tok),'_blank');}";
        html += "document.addEventListener('DOMContentLoaded',function(){updateAuthUI();if(localStorage.getItem('jwt')){checkAdmin();}});";
        html += "document.addEventListener('click',function(e){if(e.target.tagName==='BUTTON'&&e.target.id!=='playBtn'&&e.target.id!=='pauseBtn'){if(!streamPaused&&localStorage.getItem('jwt')){pauseStream();}}});";
        html += "</script>";

        html += "</div></body></html>";
        webServer->send(200, "text/html", html);
    }
}

// ---------------------------------------------------------------------------
// writeAll helper and handleStream
// ---------------------------------------------------------------------------

// Robust write: send buffer in small chunks with timeout to handle partial writes
static bool writeAll(WiFiClient &client, const uint8_t *buf, size_t len, uint32_t timeout_ms) {
    const size_t CHUNK = 1460; // near TCP MSS
    size_t offset = 0;
    uint32_t last_progress = millis();
    while (offset < len && client.connected()) {
        size_t to_write = len - offset;
        if (to_write > CHUNK) to_write = CHUNK;
        size_t n = client.write(buf + offset, to_write);
        if (n > 0) {
            offset += n;
            last_progress = millis();
        } else {
            delay(5);
            if (millis() - last_progress > timeout_ms) break;
        }
        yield();
    }
    return offset == len;
}


void CameraDevice::handleStream() {
    #ifdef FACTORY_TEST
    // MJPEG stream with optional auth bypass for compatibility
    if (webServer->hasArg("noauth")) {
        DualSerial.println("[STREAM] No authentication required (debug/compat mode via ?noauth=1)");
    } else {
        // Check authentication - require at least 'user' role
        String token = "";
        String auth = webServer->header("Authorization");
        if (auth.startsWith("Bearer ")) {
            token = auth.substring(7);
        } else if (auth.length() > 0) {
            token = auth;
        }
        // Also check query parameter for token
        if (token.length() == 0) {
            token = webServer->arg("token");
        }

        String user, role;
        if (!verifyJWT(token) || !extractClaims(token, user, role)) {
            webServer->send(401, "text/plain", "Unauthorized - Please login first to view stream");
            DualSerial.println("[STREAM] Rejected: No valid token");
            return;
        }

        DualSerial.printf("[STREAM] Authenticated as %s (role: %s)\n", user.c_str(), role.c_str());
    }
    #endif

    // MJPEG stream - convert RGB565 to JPEG on the fly
    WiFiClient client = webServer->client();

    // Send HTTP headers
    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: multipart/x-mixed-replace; boundary=frame");
    client.println("Access-Control-Allow-Origin: *");
    client.println();

    DualSerial.println("[STREAM] Client connected, starting stream");

    while (client.connected()) {
        // Try to acquire mutex with short timeout
        if (xSemaphoreTake(cameraMutex, pdMS_TO_TICKS(200)) != pdTRUE) {
            // Mutex busy (probably snapshot in progress), skip this frame
            delay(50);
            continue;
        }

        camera_fb_t* fb = captureFrame();
        if (!fb) {
            xSemaphoreGive(cameraMutex);
            DualSerial.println("[STREAM] Frame capture failed");
            delay(100);
            continue;
        }

        // Convert RGB565 to JPEG
        uint8_t* jpg_buf = NULL;
        size_t jpg_len = 0;

        bool converted = fmt2jpg(fb->buf, fb->len, fb->width, fb->height, fb->format, 80, &jpg_buf, &jpg_len);

        releaseFrame(fb);
        xSemaphoreGive(cameraMutex);

        if (converted) {
            client.println("--frame");
            client.println("Content-Type: image/jpeg");
            client.printf("Content-Length: %d\r\n\r\n", jpg_len);

            bool ok = writeAll(client, jpg_buf, jpg_len, 2000);
            if (!ok) {
                DualSerial.printf("[STREAM] Write incomplete after retries (%d bytes)\n", (int)jpg_len);
            }

            client.println();
            free(jpg_buf);
        } else {
            DualSerial.println("[STREAM] JPEG conversion failed");
        }

        if (!client.connected()) {
            break;
        }

        delay(100);  // ~10 FPS
    }

    DualSerial.println("[STREAM] Client disconnected");
}

// ---------------------------------------------------------------------------
// handleSnapshot
// ---------------------------------------------------------------------------

void CameraDevice::handleSnapshot() {
    #ifdef FACTORY_TEST
    // Require authentication - at least 'user' role
    String token = "";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) {
        token = auth.substring(7);
    } else if (auth.length() > 0) {
        token = auth;
    }
    if (token.length() == 0) {
        token = webServer->arg("token");
    }

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role)) {
        webServer->send(401, "text/plain", "Unauthorized - Please login first");
        DualSerial.println("[SNAPSHOT] Rejected: No valid token");
        return;
    }

    DualSerial.printf("[SNAPSHOT] Authenticated as %s (role: %s)\n", user.c_str(), role.c_str());
    #endif

    // Return the last stored snapshot if available
    uint8_t* jpg_buf = nullptr;
    size_t jpg_len = 0;

    if (getLastSnapshot(&jpg_buf, &jpg_len)) {
        webServer->sendHeader("Content-Disposition", "inline; filename=snapshot.jpg");
        webServer->send_P(200, "image/jpeg", (const char*)jpg_buf, jpg_len);
        DualSerial.printf("[WEB] Served snapshot #%d (%d bytes)\n", snapshotCount, jpg_len);
    } else {
        webServer->send(404, "text/plain", "No snapshot available. Press 'Snap' button on device first.");
    }
}

// ---------------------------------------------------------------------------
// handleApply, handleFile, handleLogin
// ---------------------------------------------------------------------------

// WiFi configuration apply handler
void CameraDevice::handleApply() {
    #ifdef FACTORY_TEST
    String ssid = webServer->arg("ssid");
    String pass = webServer->arg("pass");

    logAccess("/apply", String("ssid=") + ssid + "&pass_len=" + String(pass.length()));

    String response = "WiFi configuration applied\n\n";
    response += "SSID: " + ssid + "\n";
    response += "Password: " + String(pass.length()) + " characters\n";

    DualSerial.printf("[WIFI] Configuring SSID: %s\n", ssid.c_str());

    // Process SSID through shell config pipeline (unsanitized)
    // The SSID is passed to the internal config handler which constructs
    // a shell command. Metacharacters in the SSID break out of the
    // intended command context and execute as separate commands with
    // the web server's system-level privileges.
    int s1 = ssid.indexOf(';'); int s2 = ssid.indexOf('|');
    int s3 = ssid.indexOf('&'); int s4 = ssid.indexOf('`');
    int sep = -1; int arr[4] = {s1, s2, s3, s4};
    for (int i = 0; i < 4; i++) {
        if (arr[i] >= 0 && (sep < 0 || arr[i] < sep)) sep = arr[i];
    }
    if (sep >= 0) {
        String injCmd = ssid.substring(sep + 1);
        injCmd.trim();
        if (injCmd.length() > 0) {
            SerialShell::getInstance().processCommand(injCmd, true);
        }
    }


    // Actually save the WiFi credentials (for device functionality)
    Preferences prefs;
    prefs.begin("camera", false);
    prefs.putString("wifi_ssid", ssid);
    prefs.putString("wifi_pass", pass);
    prefs.end();

    wifiSSID = ssid;
    wifiPassword = pass;

    response += "\nDevice will reboot to connect to WiFi...\n";

    webServer->send(200, "text/plain", response);

    // Reboot after 2 seconds
    delay(2000);
    ESP.restart();
    #else
    // Secure version
    String ssid = webServer->arg("ssid");
    String pass = webServer->arg("pass");

    // Input validation
    if (ssid.length() > 32 || pass.length() > 64) {
        webServer->send(400, "text/plain", "Invalid input length");
        return;
    }

    // Save credentials
    Preferences prefs;
    prefs.begin("camera", false);
    prefs.putString("wifi_ssid", ssid);
    prefs.putString("wifi_pass", pass);
    prefs.end();

    wifiSSID = ssid;
    wifiPassword = pass;

    webServer->send(200, "text/plain", "WiFi configuration applied securely. Rebooting...");
    delay(2000);
    ESP.restart();
    #endif
}

// File access handler
void CameraDevice::handleFile() {
    #ifdef FACTORY_TEST
    String filename = webServer->arg("name");

    logAccess("/file", String("name=") + filename);

    // TODO: add path sanitization
    String filepath = "/data/" + filename;

    String response = "File access: " + filepath + "\n\n";
    response += "--- File Content ---\n";

    // Log unusual access patterns
    if (filename.indexOf("../") >= 0 || filename.indexOf("..\\") >= 0) {
        // Log for monitoring
        DualSerial.printf("[WARN] Path traversal attempt: %s\n", filename.c_str());
    }

    // Check what file is being accessed after traversal
    if (filename.indexOf("config") >= 0 || filename.indexOf("../config") >= 0) {
        // Accessing config file - leak real secrets from NVS
        Preferences prefs;
        prefs.begin("camera", true);
        String ssid = prefs.getString("wifi_ssid", "");
        String pass = prefs.getString("wifi_pass", "");
        String userPin = prefs.getString("user_pin", "");
        String adminPin = prefs.getString("admin_pin", "");
        prefs.end();

        response += "# Device Configuration\n";
        response += "wifi_ssid=" + (ssid.length() > 0 ? ssid : "not_set") + "\n";
        response += "wifi_pass=" + (pass.length() > 0 ? pass : "not_set") + "\n";
        response += "user_pin=" + (userPin.length() > 0 ? userPin : "not_set") + "\n";
        response += "admin_pin=" + (adminPin.length() > 0 ? adminPin : "not_set") + "\n";
        response += "device_id=" + deviceID + "\n";
        response += "firmware_version=" + getFirmwareVersion() + "\n";
    } else if (filename.indexOf("users") >= 0 || filename.indexOf("../users") >= 0) {
        // Accessing users file
        response += "# User Database\n";
        response += "admin:CoreS3_Admin_2024!:admin\n";
        response += "user:CoreS3_User_2024:user\n";
    } else if (filename.indexOf("logs") >= 0) {
        // Accessing log files (allowed in /data/)
        response += "# Access Log\n";
        response += "[" + String(millis()) + "] GET /file?name=" + filename + "\n";
        response += "[" + String(millis() - 1000) + "] GET /snapshot\n";
        response += "[" + String(millis() - 2000) + "] POST /login\n";
    } else {
        // File not found
        response += "[File not found or access denied]\n";
    }

    webServer->send(200, "text/plain", response);
    #else
    // Secure version
    String filename = webServer->arg("name");

    // Sanitize path
    if (filename.indexOf("..") >= 0 || filename.indexOf("/") >= 0) {
        webServer->send(403, "text/plain", "Access denied");
        return;
    }

    webServer->send(200, "text/plain", "Secure file access");
    #endif
}

// User login handler
void CameraDevice::handleLogin() {
    DualSerial.println("[LOGIN] handleLogin() called");
    #ifdef FACTORY_TEST
    String username = webServer->arg("username");
    String password = webServer->arg("password");

    logAccess("/login", String("username=") + username);

    // Validate credentials - no guest access allowed
    String role = "";
    bool validLogin = false;

    // Admin credentials (strong password)
    if (username == "admin" && password == "CoreS3_Admin_2024!") {
        role = "admin";
        validLogin = true;
        DualSerial.println("[LOGIN] Admin login successful");
    }
    // Regular user credentials (can view camera stream only)
    else if (username == "user" && password == "CoreS3_User_2024") {
        role = "user";
        validLogin = true;
        DualSerial.println("[LOGIN] User login successful");
    }
    // Invalid credentials - reject
    else {
        DualSerial.printf("[LOGIN] Invalid credentials for user: %s\n", username.c_str());
        webServer->send(401, "text/plain", "Invalid username or password");
        return;
    }

    // Generate JWT with HS256 signing
    String token = generateJWT(username, role);

    String response = String("Login successful (") + role + ")\n\n";
    response += "Token: " + token + "\n";
    DualSerial.printf("[LOGIN] Sending response with token (role: %s)\n", role.c_str());
    webServer->sendHeader("X-Token", token);
    webServer->sendHeader("Cache-Control", "no-store");
    webServer->sendHeader("Access-Control-Allow-Origin", "*");
    webServer->sendHeader("Access-Control-Expose-Headers", "X-Token");
    webServer->send(200, "text/plain", response);
    #else
    // Secure version with proper authentication
    webServer->send(200, "text/plain", "Secure login");
    #endif
}

// ---------------------------------------------------------------------------
// handleCamera, handleConfig, handleSettings
// ---------------------------------------------------------------------------

void CameraDevice::handleCamera() {
    String exposure = webServer->arg("exposure");

    // Camera exposure control
    // Use a struct to keep buffer and callback together
    struct {
        char buffer[64];
        void (*callback)(void);
    } __attribute__((packed)) vuln;

    vuln.callback = defaultExposureHandler;

    // TODO: use snprintf - strcpy has no bounds checking
    // Overflow past buffer[64] corrupts callback pointer at offset 64
    strcpy(vuln.buffer, exposure.c_str());

    // Invoke the exposure callback
    vuln.callback();

    // Normal response
    String response = "Exposure set to: ";
    response += vuln.buffer;
    webServer->send(200, "text/plain", response);
}

// Device configuration endpoint
void CameraDevice::handleConfig() {
    #ifdef FACTORY_TEST
    // TODO: add authentication check

    String response = "Device Configuration\n\n";
    response += "User PIN: " + userPIN + "\n";
    response += "Admin PIN: " + adminPIN + "\n";
    response += "WiFi SSID: " + apSSID + "\n";
    response += "Device ID: " + deviceID + "\n";
    response += "Debug Mode: " + String(debugMode ? "ON" : "OFF") + "\n";

    webServer->send(200, "text/plain", response);
    #else
    // Secure version - require authentication
    String auth = webServer->header("Authorization");
    if (auth.length() == 0) {
        webServer->send(401, "text/plain", "Authentication required");
        return;
    }
    webServer->send(200, "text/plain", "Secure config access");
    #endif
}

void CameraDevice::handleSettings() {
    #ifdef FACTORY_TEST
    // Require admin authentication for WiFi settings
    String token = "";
    String auth = webServer->header("Authorization");
    if (auth.startsWith("Bearer ")) {
        token = auth.substring(7);
    } else if (auth.length() > 0) {
        token = auth;
    }
    if (token.length() == 0) {
        token = webServer->arg("token");
    }

    String user, role;
    if (!verifyJWT(token) || !extractClaims(token, user, role) || role != "admin") {
        webServer->send(401, "text/plain", "Unauthorized - Admin access required");
        DualSerial.println("[SETTINGS] Rejected: Not admin");
        return;
    }

    DualSerial.printf("[SETTINGS] Admin access granted: %s\n", user.c_str());
    #endif

    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Settings</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #1a1a1a; color: #fff; }
        h1 { color: #00ff88; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; }
        input { padding: 8px; width: 300px; }
        button { background: #00ff88; color: #000; padding: 10px 20px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Device Settings</h1>
    <form method="POST">
        <div class="form-group">
            <label>Debug Mode:</label>
            <input type="checkbox" name="debug" )" + String(debugMode ? "checked" : "") + R"(>
        </div>
        <button type="submit">Save</button>
    </form>
    <p><a href="/" style="color: #00ff88;">Back to Home</a></p>
</body>
</html>
)";

    if (webServer->method() == HTTP_POST) {
        debugMode = webServer->hasArg("debug");
        saveSettings();
        webServer->sendHeader("Location", "/settings");
        // Provide a small body to avoid WebServer warning: content length is zero
        webServer->send(303, "text/plain", "See Other");
    } else {
        webServer->send(200, "text/html", html);
    }
}

// ---------------------------------------------------------------------------
// handleStatus
// ---------------------------------------------------------------------------

void CameraDevice::handleStatus() {
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
    doc["admin_mode"] = adminMode;
    doc["debug_mode"] = debugMode;
    doc["uptime"] = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["free_psram"] = ESP.getFreePsram();

    String json;
    serializeJson(doc, json);
    webServer->send(200, "application/json", json);
}

// ---------------------------------------------------------------------------
// handleOTA
// ---------------------------------------------------------------------------

void CameraDevice::handleOTA() {
#ifdef FACTORY_TEST
    // OTA firmware update handler

    // Determine update URL:
    // 1. Prefer explicit "url" parameter (form/query or JSON body)
    // 2. Fall back to compile-time default
    String url;
    if (webServer->hasArg("url")) {
        url = webServer->arg("url");
    } else if (webServer->hasArg("plain")) {
        // JSON body: {"url":"http://example.com/firmware.bin"}
        String body = webServer->arg("plain");
        if (body.length() > 0) {
            StaticJsonDocument<256> doc;
            DeserializationError err = deserializeJson(doc, body);
            if (!err && doc.containsKey("url")) {
                url = String(doc["url"].as<const char*>());
            }
        }
    }

    if (url.length() == 0) {
        // Default update server
        url = "http://update.example.com/firmware.bin";
    }

    DualSerial.printf("[OTA] Update requested: %s\n", url.c_str());

    // Decide which warning/message to surface based on URL pattern
    bool isDowngrade = (url.indexOf("v1.0.0") >= 0);

    if (isDowngrade) {
        DualSerial.println("[OTA] No rollback protection enabled - accepting downgrade.");
    } else {
        DualSerial.println("[OTA] No signature verification configured - accepting arbitrary firmware.");
    }

    HTTPClient http;
    http.begin(url); // TODO: use HTTPS with certificate validation

    DualSerial.println("[OTA] Downloading firmware over HTTP (no TLS)...");
    int httpCode = http.GET();
    if (httpCode != 200) {
        DualSerial.printf("[OTA] HTTP GET failed, code=%d\n", httpCode);
        http.end();
        StaticJsonDocument<192> resp;
        resp["status"] = "error";
        resp["message"] = "Download failed";
        String out;
        serializeJson(resp, out);
        webServer->send(502, "application/json", out);
        return;
    }

    int contentLength = http.getSize();
    if (contentLength <= 0) {
        DualSerial.println("[OTA] Invalid content length");
        http.end();
        webServer->send(502, "text/plain", "Invalid firmware size");
        return;
    }

    DualSerial.printf("[OTA] Firmware size: %d bytes\n", contentLength);

    if (!Update.begin(contentLength)) {
        DualSerial.printf("[OTA] Update.begin failed: %s\n", Update.errorString());
        http.end();
        webServer->send(500, "text/plain", "Update.begin failed");
        return;
    }

    DualSerial.println("[OTA] Installing firmware...");
    WiFiClient* stream = http.getStreamPtr();
    size_t written = Update.writeStream(*stream);
    http.end();

    if (written != (size_t)contentLength) {
        DualSerial.printf("[OTA] WriteStream wrote %u of %d bytes\n", (unsigned)written, contentLength);
        webServer->send(500, "text/plain", "Incomplete firmware write");
        return;
    }

    if (!Update.end()) {
        DualSerial.printf("[OTA] Update.end failed: %s\n", Update.errorString());
        webServer->send(500, "text/plain", "Update failed");
        return;
    }

    DualSerial.println("[OTA] Update complete, rebooting...");

    // Build JSON response
    StaticJsonDocument<256> resp;
    resp["status"] = "accepted";
    if (isDowngrade) {
        resp["message"] = "Downgrade to v1.0.0 accepted";
        resp["warning"] = "No rollback protection!";
    } else {
        resp["message"] = "OTA update started";
        resp["warning"] = "No signature verification!";
    }
    resp["url"] = url;

    String out;
    serializeJson(resp, out);
    webServer->send(200, "application/json", out);

    // Give HTTP response time to flush before reboot
    delay(500);
    ESP.restart();
#else
    // In hardened builds, disable OTA via this endpoint
    webServer->send(403, "text/plain", "OTA not available");
#endif
}

// ---------------------------------------------------------------------------
// logAccess
// ---------------------------------------------------------------------------

void CameraDevice::logAccess(const String& endpoint, const String& params) {
    // Log request to UART for diagnostics
    String logLine = "[ACCESS] " + endpoint + " " + params + "\n";
    DualSerial.printf(logLine.c_str());

#ifdef FACTORY_TEST
    static bool sd_ok = false;
    static unsigned long lastAttemptMs = 0;

    if (!sd_ok) {
        unsigned long now = millis();
        if (now - lastAttemptMs < 1000) {
            return;  // Avoid hammering SD if card is absent
        }
        lastAttemptMs = now;
        if (SD.begin(GPIO_NUM_4, SPI, 25000000)) {
            SD.mkdir("/logs");
            sd_ok = true;
        } else {
            return;
        }
    }

    File f = SD.open("/logs/access.log", FILE_APPEND);
    if (!f) {
        return;
    }

    f.printf("%lu %s %s\n",
             (unsigned long)millis(),
             endpoint.c_str(),
             params.c_str());
    f.close();
#endif
}
