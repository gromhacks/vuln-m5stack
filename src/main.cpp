/**
 * @file main.cpp
 * @brief CoreS3 IoT Camera Device Firmware
 *
 * IoT camera firmware for the M5Stack CoreS3 (ESP32-S3).
 */

#include <Arduino.h>
#include <M5Unified.h>
#include <nvs_flash.h>
#include "lvgl.h"
#include "m5gfx_lvgl.h"
#include "CameraApp.h"
#include "SerialShell.h"
#include "config.h"
#include "DualSerial.h"
#include "esp_log.h"
#include "rom/ets_sys.h"
#include "hal/usb_serial_jtag_ll.h"

// Debug UART enabled on expansion header
// Echoes ALL serial output to GPIO43 (TX) / GPIO44 (RX) at 115200 baud
HardwareSerial DebugUART(1);  // Use UART1
DualSerialClass DualSerial;   // Global dual serial instance

// Prevent USB Serial/JTAG from blocking boot when no USB host is connected.
// The ESP32-S3 USB JTAG TX FIFO stalls when full and no host is draining it,
// which hangs ESP-IDF boot logs and Arduino framework init before setup() runs.
// This constructor runs early enough to set the timeout before any Serial output.
__attribute__((constructor(200)))
static void early_usb_serial_unblock() {
    Serial.setTxTimeoutMs(0);
}

// Redirect ESP-IDF log output through DualSerial so it never blocks
// on the USB JTAG/Serial FIFO when no USB host is connected.
static int dualserial_vprintf(const char *fmt, va_list args) {
    char buf[256];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    if (len > 0) {
        DualSerial.write((const uint8_t*)buf, len < (int)sizeof(buf) ? len : sizeof(buf) - 1);
    }
    return len;
}

// ROM-level putc redirect: sends ets_printf output to debug UART
// instead of USB JTAG FIFO (which busy-waits when no host is connected)
static void rom_putc_to_uart(char c) {
    DebugUART.write(c);
}

void setup() {
    // Initialize DualSerial FIRST so the ESP-IDF log redirect works immediately
    DualSerial.begin(115200, &DebugUART, DEBUG_UART_RX, DEBUG_UART_TX);

    // Redirect ROM-level ets_printf output to debug UART.
    // This catches all low-level output from ESP-IDF drivers, bootloader
    // messages, and panic handlers that bypass esp_log.
    ets_install_putc1(rom_putc_to_uart);

    // Redirect ESP-IDF log output through our non-blocking DualSerial.
    esp_log_set_vprintf(dualserial_vprintf);

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    DualSerial.printf("\n\n=================================\n");
    DualSerial.printf("CoreS3 IoT Camera Device\n");
    DualSerial.printf("=================================\n\n");

    // Give display/PMIC hardware time to stabilize on cold boot
    vTaskDelay(pdMS_TO_TICKS(500));

    // Initialize M5Stack with audio enabled
    auto cfg = M5.config();
    cfg.internal_spk = true;  // Enable internal speaker
    cfg.internal_mic = true;  // Enable internal microphone
    M5.begin(cfg);

    // Initialize BM8563 RTC (clear INT)
    M5.In_I2C.writeRegister8(0x51, 0x00, 0x00, 100000L);
    M5.In_I2C.writeRegister8(0x51, 0x01, 0x00, 100000L);
    M5.In_I2C.writeRegister8(0x51, 0x0D, 0x00, 100000L);

    // Enable AW9523 BOOST
    M5.In_I2C.bitOn(0x58, 0x03, 0b10000000, 100000L);

    // Set display brightness
    M5.Display.setBrightness(80);

    // Show boot splash immediately so the user sees the device is alive.
    // This uses M5GFX directly (LVGL isn't initialized yet).
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(0x07F1);  // Green (RGB565 approx of 0x00ff88)
    M5.Display.setTextSize(2);
    M5.Display.setTextDatum(middle_center);
    M5.Display.drawString("CoreS3 IoT Camera", 160, 80);
    M5.Display.setTextColor(0xFFFF);  // White
    M5.Display.setTextSize(1);
    M5.Display.drawString("Booting...", 160, 130);
    M5.Display.setTextColor(0x8410);  // Dim gray (RGB565 approx of 0x888888)
    M5.Display.drawString("Firmware 1.0.0", 160, 220);

    // Initialize audio BEFORE camera init (audio needs I2C to configure amplifier)
    DualSerial.println("Initializing audio hardware...");
    // Keep only one audio endpoint active at a time (CoreS3 shares I2S for mic/spk)
    M5.Mic.end();        // ensure mic is off initially
    M5.Speaker.begin();  // enable speaker; mic will be enabled on-demand
    M5.Speaker.setVolume(255);  // Set to maximum volume
    DualSerial.println("Audio hardware initialized");

    // CRITICAL: Manually configure speaker hardware while I2C is still available
    // The speaker enable callback needs I2C access, so we do it manually here
    DualSerial.println("Manually configuring speaker hardware...");

    // Enable BOOST on AW9523 (CRITICAL - powers the amplifier!)
    DualSerial.println("  - Enabling BOOST via AW9523 (0x58)...");
    bool boost_ok = M5.In_I2C.bitOn(0x58, 0x03, 0b10000000, 400000);
    DualSerial.printf("    AW9523 BOOST: %s\n", boost_ok ? "OK" : "FAILED");

    // Enable speaker via AW9523 GPIO expander (bit 2 of register 0x02)
    DualSerial.println("  - Enabling speaker power via AW9523 (0x58)...");
    bool aw9523_ok = M5.In_I2C.bitOn(0x58, 0x02, 0b00000100, 400000);
    DualSerial.printf("    AW9523 speaker: %s\n", aw9523_ok ? "OK" : "FAILED");

    // Read back to verify
    uint8_t aw9523_val = M5.In_I2C.readRegister8(0x58, 0x02, 400000);
    DualSerial.printf("    AW9523 reg 0x02 = 0x%02X (bit 2 should be 1)\n", aw9523_val);

    // Configure AW88298 amplifier for 48kHz operation
    DualSerial.println("  - Configuring AW88298 amplifier (0x36)...");
    auto writeAW88298 = [](uint8_t reg, uint16_t value) {
        value = __builtin_bswap16(value);
        bool ok = M5.In_I2C.writeRegister(0x36, reg, (const uint8_t*)&value, 2, 400000);
        DualSerial.printf("    AW88298 reg 0x%02X = 0x%04X: %s\n", reg, __builtin_bswap16(value), ok ? "OK" : "FAILED");
        return ok;
    };

    writeAW88298(0x61, 0x0673);  // boost mode disabled
    writeAW88298(0x04, 0x4040);  // I2SEN=1 AMPPD=0 PWDN=0
    writeAW88298(0x05, 0x0008);  // RMSE=0 HAGCE=0 HDCCE=0 HMUTE=0
    writeAW88298(0x06, 0x14C0);  // I2SBCK=0 (BCK mode 16*2), sample rate for 48kHz
    writeAW88298(0x0C, 0x00FF);  // volume setting (maximum volume)

    DualSerial.println("Speaker hardware configuration complete!");

    // Update boot splash with progress
    M5.Display.fillRect(0, 125, 320, 20, TFT_BLACK);
    M5.Display.setTextColor(0xFFFF);
    M5.Display.setTextSize(1);
    M5.Display.setTextDatum(middle_center);
    M5.Display.drawString("Initializing hardware...", 160, 130);

    #ifdef FACTORY_TEST
    // Emit I2C/SPI boot diagnostics BEFORE releasing I2C bus for camera
    CameraDevice& device = CameraDevice::getInstance();
    device.runBootDiagnostics();
    #endif

    // Release I2C bus for camera
    // NOTE: Speaker tests will need to reinitialize I2C before playing audio
    // This is the same approach used in the official M5Stack CoreS3 demo
    DualSerial.println("Releasing I2C bus for camera...");
    M5.In_I2C.release();

    // Update boot splash
    M5.Display.fillRect(0, 125, 320, 20, TFT_BLACK);
    M5.Display.setTextColor(0xFFFF);
    M5.Display.setTextSize(1);
    M5.Display.setTextDatum(middle_center);
    M5.Display.drawString("Starting services...", 160, 130);

    DualSerial.println("Initializing LVGL...");

    // Initialize LVGL
    lv_init();
    m5gfx_lvgl_init();

    DualSerial.println("Initializing camera app...");

    // Initialize camera app
    CameraApp_Init();

    // Force LVGL to render the first frame immediately
    lv_timer_handler();

    DualSerial.println("=== System Ready ===\n");

    // Initialize serial shell (prints banner and prompt last)
    SerialShell::getInstance().init();
}

void loop() {
    // Update M5 state
    M5.update();

    // Handle serial shell
    SerialShell::getInstance().loop();

    // Handle camera app
    CameraApp_Loop();

    // Handle LVGL tasks
    lv_timer_handler();

    // Small delay
    delay(5);
}

