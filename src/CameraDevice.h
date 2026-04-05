/**
 * @file CameraDevice.h
 * @brief Core device singleton for the CoreS3 IoT Camera
 *
 * CameraDevice owns all hardware subsystems: camera, WiFi, HTTP server,
 * JWT authentication, NVS settings, BLE, and I2C/SPI peripherals.
 *
 * Implementation is split across multiple .cpp files to keep each module
 * focused (see CameraDevice_*.cpp). This header declares the unified
 * public API; internal cross-module declarations live in
 * CameraDevice_Internal.h.
 */

#ifndef CAMERA_DEVICE_H
#define CAMERA_DEVICE_H

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include "esp_camera.h"

class CameraDevice {
public:
    static CameraDevice& getInstance();

    // Core device functions
    bool init();
    void loop();
    void maintainMemory();  // Soft watchdog: cleanup aged/unused buffers

    // Camera functions
    bool initCamera();
    void deinitCamera();
    camera_fb_t* captureFrame();
    void releaseFrame(camera_fb_t* fb);
    bool isCameraInitialized() { return cameraInitialized; }

    // Snapshot functions
    bool takeSnapshot();  // Capture and store snapshot
    bool getLastSnapshot(uint8_t** jpg_buf, size_t* jpg_len);  // Get stored snapshot
    void clearSnapshot();  // Free snapshot memory

    // Audio functions
    bool initAudio();
    void deinitAudio();
    bool testSpeaker();      // Play test tone
    bool testMicrophone();   // Record and playback test
    bool isAudioInitialized() { return audioInitialized; }
    bool mixedSignalUnlock(const char* context);  // Mic-based auth bypass

    // WiFi functions
    bool startAP(const char* ssid = nullptr, const char* password = nullptr);
    bool connectWiFi(const char* ssid, const char* password);
    String getAPIP();
    String getAPSSID();

    // Web server functions
    void startWebServer();
    void handleWebServer();

    // PIN/Auth functions
    bool checkPIN(const String& pin);
    void generateUserPIN();
    String getUserPIN();
    String getAdminPIN() { return adminPIN; }
    void setAdminPIN(const String& pin);
    bool isAdminMode();
    void setAdminMode(bool enabled);
    String getWifiSSID() { return wifiSSID; }

    // Settings
    void saveSettings();
    void loadSettings();
    bool getDebugMode();
    void setDebugMode(bool enabled);

    // Device info
    String getDeviceID();
    String getFirmwareVersion();

    #if defined(DEV_TEST_HOOKS) || defined(FACTORY_TEST)
    // Dev/test hooks
    String dev_generateJWT(const String& username);
    bool dev_verifyJWT(const String& token);
    String dev_getJWTSecret();
    String dev_fileAccess(const String& filename);
    String dev_configResponse();
    String dev_getLastI2CPattern();
    String dev_getLastSPIPattern();
    // Unified diagnostic hook (id = 1..39)
    String run_diagnostic(uint8_t id, const String& p1 = "", const String& p2 = "");
    #endif

    // Early boot emission helpers (called from main.cpp before camera init)
    void runBootDiagnostics();
    void emitI2CSecrets();  // I2C-only emission for bus-diag command
#ifdef FACTORY_TEST
    String runBusContentionTest();  // Security gate check (used by self-test)
#endif

private:
    CameraDevice();
    ~CameraDevice();
    CameraDevice(const CameraDevice&) = delete;
    CameraDevice& operator=(const CameraDevice&) = delete;

    // Web server handlers
    void handleRoot();
    void handleStream();
    void handleSnapshot();
    void handleApply();          // WiFi config apply
    void handleFile();           // File access
    void handleLogin();          // User authentication
    void handleCamera();         // Camera settings
    void handleConfig();         // Device configuration
    void handleSettings();
    void handleStatus();
    void handleAdmin();          // Admin check (requires role="admin")
    void handleAdminPanel();     // Admin UI (HTML)
    void handleAdminStatus();    // Admin-only status JSON
    void handleAdminNVS();       // Admin-only NVS listing
    void handleAdminReboot();    // Admin-only reboot
    void handleAdminSelfTest();  // Admin-only self-test trigger
    void handleOTA();
    void checkSDCardUpdate();  // Unsigned SD card firmware update

    // Helper functions
    void setupRoutes();
    String generateJWT(const String& username);
    String generateJWT(const String& username, const String& role); // overload with role claim
    bool verifyJWT(const String& token);
    bool extractClaims(const String& token, String& user, String& role);
    void logAccess(const String& endpoint, const String& params);

    // Web server
    WebServer* webServer;       // HTTP server on port 80
    Preferences prefs;          // NVS key-value store handle

    // Authentication / identity
    String userPIN;             // 6-digit user PIN (generated on first boot)
    String adminPIN;            // 6-digit admin PIN (generated on first boot)
    bool adminMode;             // True when admin is authenticated via serial or JWT
    bool debugMode;             // Persistent debug flag (stored in NVS)
    String deviceID;            // MAC-derived unique device identifier
    String jwtSecret;           // HMAC-SHA256 signing key for JWT tokens

    // Network
    String wifiSSID;            // Saved station-mode SSID (from NVS)
    String wifiPassword;        // Saved station-mode password (from NVS)
    String apSSID;              // Soft-AP SSID ("CoreS3-CAM-XXXX")
    String apPassword;          // Soft-AP password (empty = open network)

    // Camera
    bool cameraInitialized;     // True after esp_camera_init() succeeds
    SemaphoreHandle_t cameraMutex; // Protects frame capture from concurrent access

    // Snapshot (last captured JPEG)
    uint8_t* lastSnapshotBuf;   // Heap-allocated JPEG buffer (or nullptr)
    size_t lastSnapshotLen;     // JPEG size in bytes
    unsigned long lastSnapshotMillis; // millis() when snapshot was taken
    int snapshotCount;          // Running count of snapshots taken

    // Audio
    bool audioInitialized;      // True after initAudio() succeeds
    int  lastMicAvg;            // Last microphone average level (for mixed-signal auth)
    int  lastMicPeak;           // Last microphone peak level
};

#endif // CAMERA_DEVICE_H

