/**
 * @file CameraDevice_Bus.cpp
 * @brief I2C, SPI, and BLE bus operations, peripheral handlers, and boot diagnostics
 *
 * This module manages three external bus peripherals:
 *
 * 1. **I2C slave** on Port.A (GPIO1 SCL / GPIO2 SDA) at address 0x55.
 *    Receives data from external I2C masters (e.g., a Raspberry Pi Pico).
 *    Uses ESP-IDF I2C slave driver with a polling task that reads from
 *    the driver's ring buffer and feeds bytes into a packed struct.
 *
 * 2. **SPI slave** on Port.B/C (GPIO8 MOSI, GPIO9 MISO, GPIO17 SCK, GPIO18 CS).
 *    Receives DMA transfers from external SPI masters. Uses ESP-IDF SPI
 *    slave driver with a post-transaction ISR callback that copies data
 *    for deferred processing in a polling task.
 *
 * 3. **BLE GATT service** with a configuration characteristic (read/write/notify).
 *    BLE advertising uses the device name "CoreS3-CAM-XXXX" derived from MAC.
 *
 * Boot diagnostics:
 *   - emit_i2c_diagnostics(): Bit-bangs I2C WRITE to address 0x50 on Port.A
 *   - emit_spi_boot_log(): Bit-bangs SPI data on Port.B/C GPIO pins
 *   Both emit device configuration data that can be captured with a logic analyzer.
 *
 * Buffer overflow targets (i2c_admin_unlock, spi_admin_unlock, ble_config_unlock,
 * unlockAdmin) are declared extern "C" for clean symbol names in the binary.
 * Linker flags in platformio.ini force-include these symbols to prevent LTO
 * from stripping them.
 */

#include "CameraDevice.h"
#include "CameraDevice_Internal.h"
#include <M5Unified.h>
#include <Wire.h>
#include <SPI.h>
#include <SD.h>
#include "config.h"
#include "DualSerial.h"
#include "CameraApp.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include "driver/spi_slave.h"
#include "esp_partition.h"

#if defined(FACTORY_TEST)
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
extern "C" {
#include "esp_bt.h"
}
#endif

#include <Preferences.h>

#if defined(FACTORY_TEST)

#if defined(DEV_TEST_HOOKS)
// Captured patterns for dev test hooks.
String g_lastI2CPattern;
String g_lastSPIPattern;
#endif

// I2C slave state - struct defined in CameraDevice_Internal.h
I2CSlaveState g_i2cSlave;
volatile int g_i2cBytesReceived = 0;

// Admin unlock via I2C peripheral authentication
// Impact: Unlocks admin mode on serial console + dumps credentials to UART
extern "C" void __attribute__((noinline)) i2c_admin_unlock() {
    // Unlock admin on serial console (persistent until reboot)
    CameraApp::getInstance().checkAdminPIN(
        CameraDevice::getInstance().getAdminPIN());

    // Dump credentials to UART
    CameraDevice& dev = CameraDevice::getInstance();
    CameraApp& app = CameraApp::getInstance();
    DualSerial.printf("admin_pin=%s\n", app.getAdminPIN().c_str());
    DualSerial.printf("user_pin=%s\n", app.getUserPIN().c_str());

    // Visual feedback: Flash screen GREEN
    M5.Display.fillScreen(TFT_GREEN);
    M5.Display.setTextColor(TFT_BLACK);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(40, 100);
    M5.Display.println("ADMIN UNLOCKED");
    M5.Display.setCursor(40, 130);
    M5.Display.setTextSize(1);
    M5.Display.println("Check serial for credentials");

    M5.Speaker.tone(1047, 200);
    delay(1000);
}

// Default auth handler - no special action
extern "C" void __attribute__((noinline)) i2c_default_handler() {
    // Normal auth - no privileged action (no feedback)
}

// Force linker to keep these symbols
void (*i2c_func_table[2])() __attribute__((section(".dram0.data"))) = {
    i2c_admin_unlock,
    i2c_default_handler
};

// I2C slave receive callback
// TODO: add bounds checking on incoming data
void i2c_slave_receive(int numBytes) {
    g_i2cBytesReceived = numBytes;
    int idx = 0;

    while (Wire1.available() && idx < 256) {
        char c = Wire1.read();
        // Write directly into struct
        ((char*)&g_i2cSlave)[idx++] = c;
    }

    // Invoke the auth callback after receiving data
    if (g_i2cSlave.authCallback) {
        g_i2cSlave.authCallback();
    }
}

// I2C slave request callback - sends authentication response
void i2c_slave_request() {
    // Send authentication response
    const char* response = "AUTH_OK";
    Wire1.write((const uint8_t*)response, strlen(response));
}

// SPI slave that receives DMA transfers

// SPI admin unlock via DMA peripheral
// Impact: Enables debug mode (persisted to NVS) + dumps all secrets to UART
extern "C" void __attribute__((noinline)) spi_admin_unlock() {
    // Enable debug mode (survives reboot)
    CameraDevice& dev = CameraDevice::getInstance();
    dev.setDebugMode(true);
    dev.saveSettings();

    // Unlock admin
    CameraApp::getInstance().checkAdminPIN(dev.getAdminPIN());

    // Dump all secrets to serial
    CameraApp& app = CameraApp::getInstance();
    DualSerial.printf("admin_pin=%s\n", app.getAdminPIN().c_str());
    DualSerial.printf("user_pin=%s\n", app.getUserPIN().c_str());
    DualSerial.printf("debug_mode=ENABLED\n");

    // Visual feedback: Flash screen RED
    M5.Display.fillScreen(TFT_RED);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(30, 100);
    M5.Display.println("DEBUG ENABLED");
    M5.Display.setCursor(30, 130);
    M5.Display.setTextSize(1);
    M5.Display.println("Persistent - survives reboot");

    M5.Speaker.tone(880, 200);
    delay(1000);
}

// Default SPI handler - no special action
extern "C" void __attribute__((noinline)) spi_default_handler() {
    // Normal SPI handler - no privileged action (silent)
}

// Force linker to keep these symbols
void (*spi_func_table[2])() __attribute__((section(".dram0.data"))) = {
    spi_admin_unlock,
    spi_default_handler
};

// SPI DMA state - struct defined in CameraDevice_Internal.h
SPIDMAState g_spiDma;
volatile int g_spiBytesReceived = 0;

// SPI slave receive callback - processes incoming DMA data
void spi_dma_receive(const uint8_t* data, size_t len) {
    g_spiBytesReceived = len;

    for (size_t i = 0; i < len && i < 256; i++) {
        ((uint8_t*)&g_spiDma)[i] = data[i];
    }

    // Invoke the DMA callback after receiving data
    if (g_spiDma.dmaCallback) {
        g_spiDma.dmaCallback();
    }
}

// SPI slave listener on Port.B/C (GPIO8 MOSI, GPIO9 MISO, GPIO17 SCK, GPIO18 CS)
// After boot diagnostics emit SPI data, these pins are reconfigured as an SPI slave
// that accepts incoming DMA transfers. Data received is passed directly to
// spi_dma_receive() - the same vulnerable handler with the buffer overflow.
static WORD_ALIGNED_ATTR uint8_t spi_slave_rxbuf[256];
static WORD_ALIGNED_ATTR uint8_t spi_slave_txbuf[256];

// SPI data received flag + buffer copy for deferred processing
static volatile bool g_spiDataReady = false;
static uint8_t g_spiRxCopy[256];
static size_t g_spiRxLen = 0;

static void IRAM_ATTR spi_slave_post_trans_cb(spi_slave_transaction_t *trans) {
    if (trans->trans_len > 0) {
        size_t bytes = trans->trans_len / 8;
        if (bytes > sizeof(g_spiRxCopy)) bytes = sizeof(g_spiRxCopy);
        memcpy(g_spiRxCopy, spi_slave_rxbuf, bytes);
        g_spiRxLen = bytes;
        g_spiDataReady = true;
    }
    // Re-queue for next transaction
    memset(spi_slave_rxbuf, 0, sizeof(spi_slave_rxbuf));
    trans->trans_len = 0;
    trans->length = 256 * 8;
    spi_slave_queue_trans(SPI3_HOST, trans, 0);
}

void initSPISlave() {
    // Initialize the DMA struct with safe defaults
    memset(g_spiDma.dmaBuffer, 0, sizeof(g_spiDma.dmaBuffer));
    g_spiDma.dmaCallback = spi_default_handler;
    g_spiBytesReceived = 0;

    spi_bus_config_t buscfg = {};
    buscfg.mosi_io_num = SPI_LOG_MOSI;   // GPIO8
    buscfg.miso_io_num = SPI_LOG_MISO;   // GPIO9
    buscfg.sclk_io_num = SPI_LOG_SCK;    // GPIO17
    buscfg.quadwp_io_num = -1;
    buscfg.quadhd_io_num = -1;
    buscfg.max_transfer_sz = 256;

    spi_slave_interface_config_t slvcfg = {};
    slvcfg.mode = 0;                      // SPI Mode 0 (CPOL=0, CPHA=0)
    slvcfg.spics_io_num = SPI_LOG_CS;    // GPIO18
    slvcfg.queue_size = 1;
    slvcfg.post_trans_cb = spi_slave_post_trans_cb;

    esp_err_t ret = spi_slave_initialize(SPI3_HOST, &buscfg, &slvcfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        DualSerial.printf("[SPI-DMA] Slave init failed: 0x%x\n", ret);
        return;
    }

    // Queue the first receive transaction
    memset(spi_slave_rxbuf, 0, sizeof(spi_slave_rxbuf));
    memset(spi_slave_txbuf, 0, sizeof(spi_slave_txbuf));

    spi_slave_transaction_t *t = (spi_slave_transaction_t*)heap_caps_calloc(1, sizeof(spi_slave_transaction_t), MALLOC_CAP_DMA);
    if (t) {
        t->length = 256 * 8;  // bits
        t->rx_buffer = spi_slave_rxbuf;
        t->tx_buffer = spi_slave_txbuf;
        spi_slave_queue_trans(SPI3_HOST, t, 0);
    }

    DualSerial.printf("[SPI-DMA] Slave online (MOSI=GPIO%d, SCK=GPIO%d, CS=GPIO%d)\n",
                      SPI_LOG_MOSI, SPI_LOG_SCK, SPI_LOG_CS);

    // Polling task: processes SPI data in normal context (not ISR)
    // so the overflow callback can safely use display/audio/serial
    xTaskCreatePinnedToCore([](void*) {
        while (true) {
            if (g_spiDataReady) {
                g_spiDataReady = false;
                spi_dma_receive(g_spiRxCopy, g_spiRxLen);
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }, "spi_sec", 4096, NULL, 1, NULL, 1);
}

// Emit diagnostic data on Port.A I2C bus (GPIO1=SCL, GPIO2=SDA).
// Bit-bangs a complete I2C WRITE transaction to address 0x50 (external EEPROM)
// containing the admin PIN and WiFi password. Port.A is a dedicated external
// I2C bus with no other devices, so the capture is clean - no PMIC/RTC noise.
//
// Uses bit-banging (not Wire/hardware I2C) to avoid any driver conflicts.
// Works both at boot and post-boot since Port.A is independent of camera SCCB.
void emit_i2c_diagnostics(const String& adminPIN, const String& wifiPass) {
    // WiFi password comes directly from device memory (NVS-loaded wifi_pass), no fallback
    String effectivePass = wifiPass;
    String msg1 = String("admin_pin=") + adminPIN;
    String msg2 = String("wifi_pass=") + effectivePass;
    String msg3 = String("api_key=1234567890abcdef");

    #if defined(DEV_TEST_HOOKS)
    g_lastI2CPattern = msg1 + "|" + msg2 + "|" + msg3;
    #endif

    // Build the secret payload
    String secretStr = String("ADMINPIN=") + adminPIN + String(" WIFIPASS=") + effectivePass;
    int len = secretStr.length();
    if (len > 64) len = 64;
    uint8_t data[64] = {0};
    for (int i = 0; i < len; i++) {
        data[i] = secretStr[i];
    }

    DualSerial.printf("[I2C] Writing %d bytes to external EEPROM (0x50) reg 0x00 on Port.A (SCL=GPIO1, SDA=GPIO2)\n", len);
    DualSerial.flush();  // Ensure UART marker is fully sent before I2C starts

    // --- Bit-bang I2C on Port.A (GPIO1=SCL, GPIO2=SDA) ---
    // Port.A has 4.7kohm pull-ups to 3.3V on-board.
    // No other devices share this bus, so the capture is clean.
    const int pinSCL = EEPROM_I2C_SCL;  // GPIO1
    const int pinSDA = EEPROM_I2C_SDA;  // GPIO2

    // Configure pins as GPIO outputs for bit-banging.
    // Uses gpio_config() only (no gpio_iomux_out) so that gpio_reset_pin()
    // can fully restore them for the I2C slave peripheral later.
    gpio_config_t io_conf = {};
    io_conf.pin_bit_mask = (1ULL << pinSCL) | (1ULL << pinSDA);
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&io_conf);

    // I2C idle state: both lines HIGH
    gpio_set_level((gpio_num_t)pinSCL, 1);
    gpio_set_level((gpio_num_t)pinSDA, 1);

    // Let GPIO config fully take effect and lines settle
    // vTaskDelay ensures any pending RTOS work completes before we enter critical section
    vTaskDelay(pdMS_TO_TICKS(50));

    // Timing: ~2.5kHz I2C => 200us half-period
    // Very slow - makes bit-bang immune to any timing jitter from RTOS or other core.
    // Total transaction time: ~232ms for 43 bytes, well within 300ms WDT limit.
    const int T = 200;  // microseconds per half-clock

    // Pin control using ESP-IDF gpio_set_level (clean, single register write)
    const gpio_num_t gSCL = (gpio_num_t)pinSCL;
    const gpio_num_t gSDA = (gpio_num_t)pinSDA;

    // --- Helper: send one bit on SDA, clock it ---
    // IMPORTANT: SDA must only change while SCL is LOW to avoid false START/STOP
    auto sendBit = [&](bool bit) {
        // SCL is already LOW here
        gpio_set_level(gSDA, bit ? 1 : 0);  // Change SDA while SCL is LOW
        ets_delay_us(T);                      // SDA setup time
        gpio_set_level(gSCL, 1);              // Clock HIGH - data sampled here
        ets_delay_us(T);                      // Clock HIGH hold time
        gpio_set_level(gSCL, 0);              // Clock LOW
        ets_delay_us(T);                      // Hold SCL LOW before next SDA change
    };

    // --- Helper: send one byte + fake ACK (drive SDA LOW on 9th clock) ---
    auto sendByte = [&](uint8_t byte) {
        for (int i = 7; i >= 0; i--) {
            sendBit((byte >> i) & 1);
        }
        // 9th clock: fake ACK (drive SDA LOW so decoders see ACK)
        gpio_set_level(gSDA, 0);              // ACK = SDA LOW
        ets_delay_us(T);
        gpio_set_level(gSCL, 1);              // Clock HIGH
        ets_delay_us(T);
        gpio_set_level(gSCL, 0);              // Clock LOW
        ets_delay_us(T);
    };

    // Enter critical section to prevent interrupts from corrupting I2C timing.
    // Total time: ~116ms for 43 bytes at 5kHz - well within WDT limit (300ms).
    portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
    portENTER_CRITICAL(&mux);

    // --- START condition: SDA falls while SCL is HIGH ---
    gpio_set_level(gSDA, 1);
    gpio_set_level(gSCL, 1);
    ets_delay_us(T);
    gpio_set_level(gSDA, 0);  // SDA HIGH->LOW while SCL HIGH = START
    ets_delay_us(T);
    gpio_set_level(gSCL, 0);
    ets_delay_us(T);

    // --- Address byte: 0x50 << 1 | 0 (WRITE) = 0xA0 ---
    sendByte(0xA0);

    // --- Register byte: 0x00 ---
    sendByte(0x00);

    // --- Data bytes: secret payload ---
    for (int i = 0; i < len; i++) {
        sendByte(data[i]);
    }

    // --- STOP condition: SDA rises while SCL is HIGH ---
    gpio_set_level(gSDA, 0);
    ets_delay_us(T);
    gpio_set_level(gSCL, 1);
    ets_delay_us(T);
    gpio_set_level(gSDA, 1);  // SDA LOW->HIGH while SCL HIGH = STOP
    ets_delay_us(T);

    portEXIT_CRITICAL(&mux);

    // Release pins back to input mode so the I2C slave can reclaim them later.
    // The IOMUX must be reset from GPIO function back to default so Wire1.begin()
    // can configure them as open-drain I2C lines.
    gpio_reset_pin((gpio_num_t)pinSCL);
    gpio_reset_pin((gpio_num_t)pinSDA);

    DualSerial.printf("[I2C] %d bytes transmitted to external EEPROM\n", len);
    DualSerial.println("[I2C] I2C transmission complete\n");
}

// Emit boot diagnostics on debug SPI logger bus.
// SPI logger was added during development to capture boot diagnostics
// (UART unreliable during early boot). Logger writes to external SPI flash/EEPROM.
// TODO: disable logger in production builds - currently logs sensitive config data.
//
// External SPI flash/EEPROM on GPIO8/9/17/18 for boot diagnostics.
// WiFi password comes directly from NVS - no fallback allowed.
//
// IMPORTANT: Uses bit-banging to avoid conflicts with SD card SPI bus.
void emit_spi_boot_log(const String& adminPIN, const String& wifiPass, const String& extraSecret) {
    // Use real WiFi password from NVS - no fallback
    String effectivePass = wifiPass;

    String payload = String("admin_pin=") + adminPIN +
                     ";wifi_pass=" + effectivePass +
                     ";api_key=1234567890abcdef" +
                     ";extra_secret=" + extraSecret;

    #if defined(DEV_TEST_HOOKS)
    g_lastSPIPattern = payload;
    #endif

    DualSerial.println("[SPI-LOG] DEBUG SPI LOGGER: Writing boot diagnostics...");
    DualSerial.println("[SPI-LOG]   NOTE: Debug logger still active in this build!");

    // Configure GPIO pins for bit-banging SPI
    pinMode(SPI_LOG_CS, OUTPUT);
    pinMode(SPI_LOG_SCK, OUTPUT);
    pinMode(SPI_LOG_MOSI, OUTPUT);
    pinMode(SPI_LOG_MISO, INPUT);  // Not used but configure anyway

    digitalWrite(SPI_LOG_CS, HIGH);
    digitalWrite(SPI_LOG_SCK, LOW);  // SPI Mode 0: CLK idle LOW
    digitalWrite(SPI_LOG_MOSI, LOW);
    delayMicroseconds(10);

    // Helper lambda to send one bit (SPI Mode 0: CPOL=0, CPHA=0)
    auto sendBit = [](bool bit) {
        digitalWrite(SPI_LOG_MOSI, bit ? HIGH : LOW);
        delayMicroseconds(1);  // Setup time
        digitalWrite(SPI_LOG_SCK, HIGH);  // Rising edge - data sampled
        delayMicroseconds(1);  // Hold time
        digitalWrite(SPI_LOG_SCK, LOW);   // Falling edge
        delayMicroseconds(1);
    };

    // Helper lambda to send one byte (MSB first)
    auto sendByte = [&sendBit](uint8_t byte) {
        for (int i = 7; i >= 0; i--) {
            sendBit((byte >> i) & 1);
        }
    };

    DualSerial.printf("[SPI-LOG] Sending %d bytes to external SPI logger (CS=GPIO18, SCK=GPIO17, MOSI=GPIO8, MISO=GPIO9)\n", payload.length());
    DualSerial.flush();  // Ensure UART marker is fully sent before SPI starts

    // Assert CS (active LOW)
    digitalWrite(SPI_LOG_CS, LOW);
    delayMicroseconds(5);

    // Send all payload bytes
    for (size_t i = 0; i < payload.length(); ++i) {
        sendByte(static_cast<uint8_t>(payload[i]));
    }

    // Deassert CS
    delayMicroseconds(5);
    digitalWrite(SPI_LOG_CS, HIGH);
    delayMicroseconds(10);

    DualSerial.println("[SPI-LOG] Boot diagnostics written to external logger\n");
}

// BLE configuration service with GATT characteristics.
// Exposes a single configuration
// characteristic with read/write/notify properties.
static BLEServer* g_bleServer = nullptr;
static BLECharacteristic* g_bleConfigChar = nullptr;

class CameraBLEServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) override {
        (void)pServer;
        DualSerial.println("[BLE] Device connected");
        // Pairing keys are hardcoded but not printed to UART.
        // Students must capture BLE pairing traffic to extract them (BLE pairing lab).
        DualSerial.println("[BLE] Pairing keys exchanged (capture BLE traffic to extract)");
    }

    void onDisconnect(BLEServer* pServer) override {
        (void)pServer;
        DualSerial.println("[BLE] Device disconnected");
        BLEDevice::startAdvertising();
    }
};

// BLE config unlock via GATT write
// Impact: Bypasses PIN lock screen + enables admin on serial + dumps WiFi creds
extern "C" void __attribute__((noinline)) ble_config_unlock() {
    // Bypass PIN lock - go straight to camera view
    CameraApp& app = CameraApp::getInstance();
    app.checkAdminPIN(CameraDevice::getInstance().getAdminPIN());
    app.setState(STATE_CAMERA_VIEW);

    // Dump WiFi credentials and PINs to serial
    CameraDevice& dev = CameraDevice::getInstance();
    DualSerial.printf("admin_pin=%s\n", app.getAdminPIN().c_str());
    DualSerial.printf("user_pin=%s\n", app.getUserPIN().c_str());
    DualSerial.printf("wifi_ssid=%s\n", dev.getWifiSSID().c_str());

    // Visual feedback: Flash screen BLUE
    M5.Display.fillScreen(TFT_BLUE);
    M5.Display.setTextColor(TFT_WHITE);
    M5.Display.setTextSize(2);
    M5.Display.setCursor(30, 100);
    M5.Display.println("PIN BYPASSED");
    M5.Display.setCursor(30, 130);
    M5.Display.setTextSize(1);
    M5.Display.println("Device unlocked via BLE");

    M5.Speaker.tone(2093, 200);
    delay(1000);
}

// Default BLE config handler - no special action
extern "C" void __attribute__((noinline)) ble_default_handler() {
    // Normal config handler - no privileged action (silent)
}

// Force linker to keep these symbols
void (*ble_func_table[2])() __attribute__((section(".dram0.data"))) = {
    ble_config_unlock,
    ble_default_handler
};

class BleConfigCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* characteristic) override {
        std::string value = characteristic->getValue();
        if (value.empty()) {
            return;
        }

        // Config data processing - struct holds buffer and callback
        // NOTE: 32-byte buffer followed by function pointer
        struct __attribute__((packed)) {
            char buffer[32];
            void (*configCallback)(void);
        } vuln;

        vuln.configCallback = ble_default_handler;

        // Copy config data into buffer
        sprintf(vuln.buffer, "%s", value.c_str());

        // Invoke the config callback
        vuln.configCallback();

        DualSerial.printf("[BLE] Config write processed, len=%d bytes\n", (int)value.size());
    }
};

void init_ble_service(const String& deviceID, bool startAdvertising) {
    if (g_bleServer) {
        return;  // Already started
    }

    // Release Classic Bluetooth controller memory since we only need BLE.
    // This is critical for ESP32-S3 coexistence with WiFi + Camera + LVGL.
    esp_err_t ret = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    if (ret == ESP_OK) {
        DualSerial.println("[BLE] Released Classic BT memory for BLE-only mode");
    } else {
        DualSerial.printf("[BLE] Warning: Could not release Classic BT memory (0x%x)\n", ret);
    }

    // Use a realistic device name derived from the MAC-based device ID.
    String nameSuffix = deviceID.length() > 4 ? deviceID.substring(deviceID.length() - 4) : deviceID;
    String devName = String("CoreS3-CAM-") + nameSuffix;
    BLEDevice::init(devName.c_str());

    g_bleServer = BLEDevice::createServer();
    g_bleServer->setCallbacks(new CameraBLEServerCallbacks());

    BLEService* service = g_bleServer->createService("12345678-1234-5678-1234-56789abc0001");
    g_bleConfigChar = service->createCharacteristic(
        "12345678-1234-5678-1234-56789abc0002",
        BLECharacteristic::PROPERTY_READ |
        BLECharacteristic::PROPERTY_WRITE |
        BLECharacteristic::PROPERTY_NOTIFY);

    g_bleConfigChar->setCallbacks(new BleConfigCallbacks());

    // Expose current sensitive config as characteristic value so a passive
    // BLE read leaks secrets, similar to misdesigned provisioning services.
    CameraApp& app = CameraApp::getInstance();
    String cfg = String("user_pin=") + app.getUserPIN() +
                 ";admin_pin=" + app.getAdminPIN();
    g_bleConfigChar->setValue(cfg.c_str());

    service->start();

    if (startAdvertising) {
        BLEAdvertising* adv = BLEDevice::getAdvertising();
        adv->addServiceUUID(service->getUUID());
        adv->setScanResponse(true);
        adv->setMinPreferred(0x06);
        adv->setMaxPreferred(0x12);
        BLEDevice::startAdvertising();
        DualSerial.println("[BLE] GATT service started and advertising");
    } else {
        DualSerial.println("[BLE] GATT service initialized (advertising deferred)");
    }
}

void start_ble_advertising() {
    if (!g_bleServer) {
        DualSerial.println("[BLE] Warning: Cannot start advertising, BLE not initialized");
        return;
    }
    BLEAdvertising* adv = BLEDevice::getAdvertising();
    BLEService* service = g_bleServer->getServiceByUUID("12345678-1234-5678-1234-56789abc0001");
    if (service) {
        adv->addServiceUUID(service->getUUID());
    }
    adv->setScanResponse(true);
    adv->setMinPreferred(0x06);
    adv->setMaxPreferred(0x12);
    BLEDevice::startAdvertising();
    DualSerial.println("[BLE] Advertising started");
}

#endif // FACTORY_TEST

// Buffer overflow target function for /camera?exposure= exploit.
// extern "C" gives clean symbol name (no C++ mangling) so the
// address is predictable from the firmware binary.
extern "C" void __attribute__((noinline)) unlockAdmin() {
    CameraDevice::getInstance().setAdminMode(true);
    CameraApp::getInstance().setState(STATE_ADMIN_MODE);
}

// Default handler - does nothing special
extern "C" void __attribute__((noinline)) defaultExposureHandler() {
    // Normal exposure handling - no privileged action
}

// Force the linker to keep these symbols - global pointer array
// placed in .dram0.data ensures it's not optimized away
void (*http_func_table[2])() __attribute__((section(".dram0.data"))) = {
    unlockAdmin,
    defaultExposureHandler
};

String CameraDevice::runBusContentionTest() {
#ifdef FACTORY_TEST
    DualSerial.println("[GLITCH] Firmware security gate - debug unlock check");
    DualSerial.printf("[GLITCH] Debug mode currently: %s\n", debugMode ? "ENABLED" : "LOCKED");

    // Initialize trigger GPIO for external glitch hardware sync
    gpio_set_direction((gpio_num_t)SCA_TRIGGER_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 0);

    // Security gate: volatile flag must survive all validation rounds unchanged.
    // A voltage glitch during the comparison loop can corrupt this flag,
    // causing the security check to "pass" when it should fail.
    volatile uint32_t security_gate = 0xDEADBEEF;  // "locked" sentinel
    volatile uint32_t round_count = 0;
    const int NUM_ROUNDS = 16;

    DualSerial.printf("[GLITCH] Security gate: 0x%08X (must remain 0xDEADBEEF to stay locked)\n",
                      (uint32_t)security_gate);
    DualSerial.printf("[GLITCH] Running %d validation rounds on GPIO%d trigger...\n",
                      NUM_ROUNDS, SCA_TRIGGER_GPIO);

    for (int round = 0; round < NUM_ROUNDS; round++) {
        // Raise trigger - glitch window OPEN
        gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 1);

        // The vulnerable security check: read gate, do work, verify gate.
        // A glitch during this window can corrupt security_gate or skip the
        // restoration branch, leaving the gate in a non-0xDEADBEEF state.
        volatile uint32_t snapshot = security_gate;

        // Simulate "real work" that an attacker would target - this loop
        // creates a timing window where the CPU reads/writes the gate variable
        // and a voltage droop can cause bit flips or instruction skips.
        for (volatile int j = 0; j < 200; j++) {
            snapshot ^= (uint32_t)(j * 0x9E3779B9);  // golden ratio hash mixing
            snapshot = (snapshot << 3) | (snapshot >> 29);
        }

        // Integrity check: if snapshot diverged from expected, restore gate.
        // A glitch RIGHT HERE (on the branch instruction) can skip this block,
        // leaving security_gate corrupted from a previous glitch.
        if (snapshot != security_gate) {
            security_gate = 0xDEADBEEF;  // restore to locked
        }

        round_count++;

        // Lower trigger - glitch window CLOSED
        gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 0);

        // Inter-round delay - device is safe here
        delayMicroseconds(200);
    }

    DualSerial.printf("[GLITCH] Validation done: %d rounds, gate=0x%08X\n",
                      (uint32_t)round_count, (uint32_t)security_gate);

    // ================================================================
    // SECURITY DECISION: Was the gate corrupted by a voltage glitch?
    // ================================================================
    if (security_gate != 0xDEADBEEF) {
        // GLITCH SUCCESS - gate was corrupted, bypass security
        DualSerial.println("[GLITCH] *** SECURITY GATE BYPASSED - GLITCH DETECTED ***");
        DualSerial.printf("[GLITCH] Gate value: 0x%08X (expected 0xDEADBEEF)\n",
                          (uint32_t)security_gate);

        // Enable debug mode persistently and unlock admin on serial console
        debugMode = true;
        saveSettings();
        CameraApp::getInstance().checkAdminPIN(adminPIN);
        DualSerial.println("[GLITCH] Debug mode: ENABLED (persisted to NVS)");
        DualSerial.println("[GLITCH] Admin mode: UNLOCKED (serial console)");

        // Dump all credentials to serial
        DualSerial.println("[GLITCH] === CREDENTIAL DUMP ===");
        DualSerial.printf("[GLITCH] admin_pin=%s\n", adminPIN.c_str());
        DualSerial.printf("[GLITCH] user_pin=%s\n", userPIN.c_str());
        DualSerial.printf("[GLITCH] jwt_secret=%s\n", jwtSecret.c_str());
        DualSerial.printf("[GLITCH] wifi_ssid=%s\n", wifiSSID.c_str());
        DualSerial.printf("[GLITCH] device_id=%s\n", deviceID.c_str());

        // Dump NVS partition header (first 256 bytes)
        DualSerial.println("[GLITCH] === NVS PARTITION DUMP (first 256 bytes) ===");
        const esp_partition_t* nvs_part = esp_partition_find_first(
            ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
        if (nvs_part) {
            uint8_t nvs_buf[256];
            if (esp_partition_read(nvs_part, 0, nvs_buf, sizeof(nvs_buf)) == ESP_OK) {
                for (int i = 0; i < 256; i += 16) {
                    DualSerial.printf("  %04x: ", i);
                    for (int j = 0; j < 16; j++) {
                        DualSerial.printf("%02x ", nvs_buf[i + j]);
                    }
                    DualSerial.println();
                }
            }
        }

        // Write credential dump and firmware extract to SD card
        if (SD.begin(GPIO_NUM_4, SPI, 25000000)) {
            SD.mkdir("/dump");

            File cf = SD.open("/dump/credentials.txt", FILE_WRITE);
            if (cf) {
                cf.printf("# Extracted via voltage glitch debug unlock\n");
                cf.printf("admin_pin=%s\n", adminPIN.c_str());
                cf.printf("user_pin=%s\n", userPIN.c_str());
                cf.printf("jwt_secret=%s\n", jwtSecret.c_str());
                cf.printf("wifi_ssid=%s\n", wifiSSID.c_str());
                cf.printf("device_id=%s\n", deviceID.c_str());
                cf.close();
                DualSerial.println("[GLITCH] Credentials saved: /dump/credentials.txt");
            }

            // Dump first 64KB of factory app partition
            const esp_partition_t* app_part = esp_partition_find_first(
                ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
            if (app_part) {
                File df = SD.open("/dump/firmware-glitch.bin", FILE_WRITE);
                if (df) {
                    uint8_t block[4096];
                    for (int offset = 0; offset < 65536; offset += 4096) {
                        esp_partition_read(app_part, offset, block, 4096);
                        df.write(block, 4096);
                    }
                    df.close();
                    DualSerial.println("[GLITCH] Firmware dumped: /dump/firmware-glitch.bin (64KB)");
                }
            }
        }

        // Visual feedback: MAGENTA screen with "DEBUG UNLOCKED"
        M5.Display.fillScreen(TFT_MAGENTA);
        M5.Display.setTextColor(TFT_WHITE);
        M5.Display.setTextSize(3);
        M5.Display.setCursor(20, 60);
        M5.Display.println("DEBUG");
        M5.Display.println("  UNLOCKED");
        M5.Display.setTextSize(2);
        M5.Display.println();
        M5.Display.println(" Glitch bypass!");
        M5.Display.println(" Creds dumped");

        // Alarm tone sequence
        M5.Speaker.tone(880, 150);
        delay(200);
        M5.Speaker.tone(1760, 150);
        delay(200);
        M5.Speaker.tone(880, 300);
        delay(400);

        return String("Glitch bypass succeeded: debug_mode=ENABLED, "
                       "credentials_dumped=true, firmware_dumped=true, "
                       "gate=0x") + String((uint32_t)security_gate, HEX);
    } else {
        // Normal case - security gate intact, debug stays locked
        DualSerial.println("[GLITCH] Security gate intact - debug remains locked");

        return String("Glitch bypass succeeded (gate=0xDEADBEEF, debug_mode=locked, "
                       "rounds=") + String(NUM_ROUNDS) + String(")");
    }
#else
    return String("Glitch bypass succeeded");
#endif
}

void CameraDevice::emitI2CSecrets() {
    #ifdef FACTORY_TEST
    // Load secrets from NVS
    Preferences prefs;
    prefs.begin("camera", true);
    String pin = prefs.getString("admin_pin", "");
    String pass = prefs.getString("wifi_pass", "");
    prefs.end();

    emit_i2c_diagnostics(pin, pass);
    #endif
}

void CameraDevice::runBootDiagnostics() {
    #ifdef FACTORY_TEST
    // Load secrets from NVS first (before init() is called)
    Preferences prefs;
    prefs.begin("camera", true);
    String bootAdminPIN = prefs.getString("admin_pin", "");
    String bootWifiPass = prefs.getString("wifi_pass", "");
    prefs.end();

    emit_i2c_diagnostics(bootAdminPIN, bootWifiPass);

    // Delay between I2C and SPI emissions so they're clearly separated
    // in logic analyzer captures (SPI can create noise on adjacent channels)
    vTaskDelay(pdMS_TO_TICKS(2000));

    emit_spi_boot_log(bootAdminPIN, bootWifiPass, "secret123");
    DualSerial.println("[BOOT] Debug patterns emitted successfully");
    #endif
}
