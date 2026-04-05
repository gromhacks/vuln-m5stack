/**
 * @file CameraDevice.cpp
 * @brief Core singleton: constructor, destructor, init(), loop(), SD update
 *
 * CameraDevice is the central object that owns all hardware subsystems.
 * It is instantiated as a Meyer's singleton (getInstance()) and wired into
 * the Arduino setup()/loop() by main.cpp.
 *
 * Implementation is split across multiple files to keep each ~200-700 lines:
 *   CameraDevice.cpp        - This file (lifecycle + SD card update)
 *   CameraDevice_Camera.cpp - Camera hardware and snapshot operations
 *   CameraDevice_Audio.cpp  - Speaker and microphone
 *   CameraDevice_Auth.cpp   - JWT, PIN, NVS settings persistence
 *   CameraDevice_Web.cpp    - HTTP server, routes, all request handlers
 *   CameraDevice_Admin.cpp  - Admin panel endpoints
 *   CameraDevice_Bus.cpp    - I2C/SPI/BLE bus peripherals and boot diagnostics
 *   CameraDevice_Diag.cpp   - Diagnostic hooks (debug/test builds only)
 *
 * Boot sequence (called from main.cpp setup()):
 *   1. NVS init + DualSerial + M5Unified + audio hardware
 *   2. runBootDiagnostics() - I2C/SPI pattern emission (FACTORY_TEST only)
 *   3. I2C bus released for camera
 *   4. LVGL + CameraApp + SerialShell init
 *   5. CameraDevice::init() - WiFi, web server, camera, audio, BLE, bus slaves
 */

#include "CameraDevice.h"
#include "CameraDevice_Internal.h"
#include <esp_system.h>
#include <esp_random.h>
#include <M5Unified.h>
#include <SD.h>
#include <SPI.h>
#include <Preferences.h>
#include <Update.h>

#include "config.h"
#include "DualSerial.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include <Wire.h>

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

CameraDevice& CameraDevice::getInstance() {
    static CameraDevice instance;
    return instance;
}

CameraDevice::CameraDevice()
    : webServer(nullptr), adminMode(false), debugMode(false), cameraInitialized(false),
      lastSnapshotBuf(nullptr), lastSnapshotLen(0), lastSnapshotMillis(0), snapshotCount(0),
      audioInitialized(false), lastMicAvg(0), lastMicPeak(0) {
    // Generate device ID from MAC address
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    deviceID = String(macStr);

    // Default AP credentials
    apSSID = "CoreS3-CAM-" + deviceID.substring(6);
    apPassword = "";  // Open AP by default

    // JWT secret for session tokens
    jwtSecret = "secret123";

    // Create camera mutex
    cameraMutex = xSemaphoreCreateMutex();
}

CameraDevice::~CameraDevice() {
    if (webServer) {
        delete webServer;
    }
    if (cameraInitialized) {
        deinitCamera();
    }
    if (audioInitialized) {
        deinitAudio();
    }
    clearSnapshot();
    if (cameraMutex) {
        vSemaphoreDelete(cameraMutex);
    }
}

// ---------------------------------------------------------------------------
// SD card firmware update (unsigned firmware from /firmware.bin)
// ---------------------------------------------------------------------------

void CameraDevice::checkSDCardUpdate() {
#ifdef FACTORY_TEST
    DualSerial.println("[SD-UPDATE] Checking SD card for firmware update...");

    // CoreS3 microSD uses GPIO_NUM_4 as CS and shares the main SPI bus
    if (!SD.begin(GPIO_NUM_4, SPI, 25000000)) {
        DualSerial.println("[SD-UPDATE] SD card not detected or init failed");
        return;
    }

    const char *imagePath = "/firmware.bin";
    if (!SD.exists(imagePath)) {
        DualSerial.println("[SD-UPDATE] No firmware image found on SD (expected /firmware.bin)");
        return;
    }

    File image = SD.open(imagePath, FILE_READ);
    if (!image) {
        DualSerial.println("[SD-UPDATE] Failed to open firmware image on SD");
        return;
    }

    size_t size = image.size();
    DualSerial.printf("[SD-UPDATE] Found firmware image on SD (%u bytes)\n", (unsigned)size);
    if (size == 0) {
        DualSerial.println("[SD-UPDATE] Image size is zero, aborting");
        image.close();
        return;
    }

    // TODO: add signature/integrity/rollback checks before flashing
    if (!Update.begin(size)) {
        DualSerial.printf("[SD-UPDATE] Update.begin failed: %s\n", Update.errorString());
        image.close();
        return;
    }

    size_t written = Update.writeStream(image);
    image.close();

    if (written != size) {
        DualSerial.printf("[SD-UPDATE] writeStream wrote %u/%u bytes\n", (unsigned)written, (unsigned)size);
        Update.abort();
        return;
    }

    if (!Update.end()) {
        DualSerial.printf("[SD-UPDATE] Update.end failed: %s\n", Update.errorString());
        return;
    }

    // Remove firmware file so it doesn't re-flash on next boot.
    // If the file is still present after reboot, the device will try to
    // flash again and crash (can't write to the running partition).
    if (SD.exists("/firmware.bin.applied")) {
        SD.remove("/firmware.bin.applied");
    }
    if (!SD.rename("/firmware.bin", "/firmware.bin.applied")) {
        // Rename failed - delete the file instead to prevent boot loop
        DualSerial.println("[SD-UPDATE] Rename failed, removing firmware.bin");
        SD.remove("/firmware.bin");
    }
    SD.end();
    DualSerial.println("[SD-UPDATE] Firmware update from SD card completed. Rebooting...");
    delay(500);
    ESP.restart();
#endif
}

// ---------------------------------------------------------------------------
// Device initialisation
// ---------------------------------------------------------------------------

bool CameraDevice::init() {
    DualSerial.println("\n=== CoreS3 IoT Camera Device ===");
    DualSerial.printf("Device ID: %s\n", deviceID.c_str());
    DualSerial.printf("Firmware: %s\n", getFirmwareVersion().c_str());

    // Check for unsigned offline firmware on SD card before normal boot
#ifdef FACTORY_TEST
    checkSDCardUpdate();
#endif

    // Load settings from NVS
    DualSerial.println("Loading settings...");
    loadSettings();

    // Check if we have WiFi credentials stored
    Preferences prefs;
    prefs.begin("camera", true);
    String savedSSID = prefs.getString("wifi_ssid", "");
    String savedPass = prefs.getString("wifi_pass", "");
    prefs.end();

    wifiSSID = savedSSID;
    wifiPassword = savedPass;

    #ifdef FORCE_AP
    bool hasWiFiConfig = false;
    #else
    bool hasWiFiConfig = (savedSSID.length() > 0);
    #endif

    // Generate user PIN if not exists
    if (userPIN.length() == 0) {
        DualSerial.println("Generating user PIN...");
        generateUserPIN();
    }

    DualSerial.printf("User PIN: %s\n", userPIN.c_str());
    if (adminPIN.length() > 0) {
        DualSerial.println("Admin PIN: ******");
    }

    #ifdef FACTORY_TEST
    // Configure side-channel trigger GPIO for crypto operations
    gpio_config_t io_conf = {};
    io_conf.intr_type = GPIO_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = 1ULL << SCA_TRIGGER_GPIO;
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    gpio_config(&io_conf);
    gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 0);

    // Initialize BLE early (before WiFi) but defer advertising
    init_ble_service(deviceID, false);
    #endif

    // Decide mode: Setup (AP) or Normal (Station)
    if (!hasWiFiConfig) {
        DualSerial.println("\n*** SETUP MODE ***");
        DualSerial.println("No WiFi credentials found. Starting AP for setup...");

        if (!startAP()) {
            DualSerial.println("ERROR: WiFi AP failed to start!");
            return false;
        }

        DualSerial.println("Connect to WiFi AP and configure at:");
        DualSerial.printf("  SSID: %s\n", apSSID.c_str());
        DualSerial.printf("  URL: http://%s/\n", WiFi.softAPIP().toString().c_str());
    } else {
        DualSerial.println("\n*** NORMAL MODE ***");
        DualSerial.printf("Connecting to WiFi: %s\n", savedSSID.c_str());

        if (connectWiFi(savedSSID.c_str(), savedPass.c_str())) {
            DualSerial.println("WiFi connected successfully!");
            DualSerial.printf("  IP: %s\n", WiFi.localIP().toString().c_str());
            DualSerial.printf("  Access device at: http://%s/\n", WiFi.localIP().toString().c_str());
        } else {
            DualSerial.println("WiFi connection failed! Falling back to AP mode...");
            if (!startAP()) {
                DualSerial.println("ERROR: WiFi AP failed to start!");
                return false;
            }
        }
    }

    // Start web server
    DualSerial.println("Starting web server...");
    startWebServer();

    // Initialize camera (non-fatal)
    DualSerial.println("Initializing camera...");
    if (!initCamera()) {
        DualSerial.println("WARNING: Camera initialization failed! Device will work without camera.");
        cameraInitialized = false;
    }

    // Initialize audio (non-fatal)
    DualSerial.println("Initializing audio...");
    if (!initAudio()) {
        DualSerial.println("WARNING: Audio initialization failed! Device will work without audio.");
        audioInitialized = false;
    }

    #ifdef FACTORY_TEST
    // Start BLE advertising now that WiFi and camera are stable
    DualSerial.println("Starting BLE advertising...");
    start_ble_advertising();
    #endif

    #ifdef FACTORY_TEST
    // Initialize I2C secure element slave on Port.A (GPIO2 SDA / GPIO1 SCL)
    // using the ESP-IDF I2C slave driver for proper open-drain configuration.
    // A polling task reads received data from the driver's ring buffer and
    // feeds it into the vulnerable struct handler (same overflow as Wire callbacks).
    {
        gpio_reset_pin((gpio_num_t)PORTA_PIN_0);
        gpio_reset_pin((gpio_num_t)PORTA_PIN_1);
        delay(50);

        i2c_config_t i2c_slave_conf = {};
        i2c_slave_conf.mode = I2C_MODE_SLAVE;
        i2c_slave_conf.sda_io_num = (gpio_num_t)PORTA_PIN_1;  // GPIO2
        i2c_slave_conf.scl_io_num = (gpio_num_t)PORTA_PIN_0;  // GPIO1
        i2c_slave_conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
        i2c_slave_conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
        i2c_slave_conf.slave.addr_10bit_en = 0;
        i2c_slave_conf.slave.slave_addr = 0x55;

        esp_err_t ret = i2c_param_config(I2C_NUM_0, &i2c_slave_conf);
        if (ret == ESP_OK) {
            ret = i2c_driver_install(I2C_NUM_0, I2C_MODE_SLAVE, 256, 256, 0);
        }
        if (ret == ESP_OK) {
            DualSerial.printf("[I2C-SEC] Secure element online (0x55 on GPIO%d/GPIO%d)\n",
                              PORTA_PIN_1, PORTA_PIN_0);
            // Polling task: reads from ESP-IDF I2C slave RX buffer one byte at a time,
            // accumulates into the vulnerable struct, then calls the callback when
            // no more data arrives (10ms idle timeout = end of transaction).
            xTaskCreatePinnedToCore([](void*) {
                memset(g_i2cSlave.buffer, 0, sizeof(g_i2cSlave.buffer));
                g_i2cSlave.authCallback = i2c_default_handler;
                int writeIdx = 0;
                while (true) {
                    uint8_t byte;
                    int got = i2c_slave_read_buffer(I2C_NUM_0, &byte, 1, pdMS_TO_TICKS(10));
                    if (got > 0) {
                        if (writeIdx < 256) {
                            ((char*)&g_i2cSlave)[writeIdx++] = byte;
                        }
                    } else if (writeIdx > 0) {
                        // No more data - end of I2C transaction
                        g_i2cBytesReceived = writeIdx;
                        DualSerial.printf("[I2C-SEC] Received %d bytes\n", writeIdx);
                        if (g_i2cSlave.authCallback) {
                            g_i2cSlave.authCallback();
                        }
                        // Reset for next transaction
                        writeIdx = 0;
                        memset(g_i2cSlave.buffer, 0, sizeof(g_i2cSlave.buffer));
                        g_i2cSlave.authCallback = i2c_default_handler;
                    }
                }
            }, "i2c_sec", 4096, NULL, 1, NULL, 1);
        } else {
            DualSerial.printf("[I2C-SEC] Init failed: 0x%x\n", ret);
        }
    }

    // Initialize SPI DMA slave on Port.B/C for peripheral data reception
    // Uses the same GPIO pins as the boot SPI logger (GPIO8/9/17/18)
    // After boot diagnostics complete, these pins are reconfigured as SPI slave
    initSPISlave();
    #endif

    DualSerial.println("=== Device Ready ===\n");
    return true;
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

void CameraDevice::loop() {
    handleWebServer();
    maintainMemory();
}

// Periodic housekeeping called from loop(). Runs every 2 seconds.
// Clears stale snapshots (>30s old) and frees snapshot memory when
// heap or PSRAM drops below safety thresholds to prevent fragmentation.
void CameraDevice::maintainMemory() {
    static unsigned long last_check = 0;
    unsigned long now = millis();
    if (now - last_check < 2000) return;
    last_check = now;

    size_t freeHeap = ESP.getFreeHeap();
    size_t freePSRAM = ESP.getFreePsram();

    // Auto-clear snapshot if older than 30 seconds
    if (lastSnapshotBuf && lastSnapshotLen > 0) {
        if (lastSnapshotMillis > 0 && (now - lastSnapshotMillis > 30000)) {
            DualSerial.printf("[WD] Clearing stale snapshot (%u ms old, %u bytes)\n",
                             (unsigned)(now - lastSnapshotMillis), (unsigned)lastSnapshotLen);
            clearSnapshot();
        }
    }

    // Free snapshot on low memory to avoid fragmentation
    if ((freeHeap < 45000) || (freePSRAM < 800000)) {
        if (lastSnapshotBuf) {
            DualSerial.printf("[WD] Low memory (heap=%u, psram=%u). Releasing snapshot (%u bytes)\n",
                             (unsigned)freeHeap, (unsigned)freePSRAM, (unsigned)lastSnapshotLen);
            clearSnapshot();
        }
    }
}
