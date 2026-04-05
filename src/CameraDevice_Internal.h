/**
 * @file CameraDevice_Internal.h
 * @brief Shared internal declarations between CameraDevice_*.cpp modules
 *
 * This header is NOT part of the public API. It declares cross-module
 * globals, struct layouts, and helper functions that multiple CameraDevice
 * implementation files need access to. External code (CameraApp, SerialShell,
 * main.cpp) should only include CameraDevice.h.
 *
 * Most declarations here are guarded by FACTORY_TEST since they only exist
 * in the training build.
 */

#ifndef CAMERA_DEVICE_INTERNAL_H
#define CAMERA_DEVICE_INTERNAL_H

#include <Arduino.h>

#ifdef FACTORY_TEST

// I2C diagnostic pattern emission (CameraDevice_Bus.cpp)
void emit_i2c_diagnostics(const String& adminPIN, const String& wifiPass);

// SPI boot log emission (CameraDevice_Bus.cpp)
void emit_spi_boot_log(const String& adminPIN, const String& wifiPass, const String& extraSecret);

// SPI DMA receive callback and slave init (CameraDevice_Bus.cpp)
void spi_dma_receive(const uint8_t* data, size_t len);
void initSPISlave();

// I2C slave state (CameraDevice_Bus.cpp)
// Layout: 32-byte data buffer immediately followed by a function pointer.
// The polling task writes received bytes sequentially into this struct
// starting at offset 0, then invokes authCallback when the transaction ends.
struct __attribute__((packed)) I2CSlaveState {
    char buffer[32];             // Received data from I2C master
    void (*authCallback)(void);  // Called after full transaction received
};
extern I2CSlaveState g_i2cSlave;
extern volatile int g_i2cBytesReceived;
void i2c_slave_receive(int numBytes);
void i2c_slave_request();

// SPI DMA state (CameraDevice_Bus.cpp)
// Layout: 64-byte DMA receive buffer followed by a function pointer.
// Data received from the SPI master is copied into dmaBuffer, then
// dmaCallback is invoked. Same sequential-write pattern as I2CSlaveState.
struct __attribute__((packed)) SPIDMAState {
    char dmaBuffer[64];          // Received data from SPI master
    void (*dmaCallback)(void);   // Called after DMA transfer completes
};
extern SPIDMAState g_spiDma;
extern volatile int g_spiBytesReceived;

// AES SCA helpers (CameraDevice_Diag.cpp) - used by /api/check_pin
void sca_derive_aes_key(const String& adminPIN, uint8_t key[16]);
void sca_aes_encrypt_triggered(const uint8_t plaintext[16], const uint8_t key[16], uint8_t ciphertext[16]);

// Bus handler symbols (CameraDevice_Bus.cpp)
extern "C" void i2c_admin_unlock();
extern "C" void i2c_default_handler();
extern "C" void spi_admin_unlock();
extern "C" void spi_default_handler();
extern "C" void ble_config_unlock();
extern "C" void ble_default_handler();
extern "C" void unlockAdmin();
extern "C" void defaultExposureHandler();

// BLE service init/advertising (CameraDevice_Bus.cpp)
void init_ble_service(const String& deviceID, bool startAdvertising = true);
void start_ble_advertising();

// Session RNG helpers (CameraDevice_Web.cpp)
void seedSessionRng();

// Frame buffer helpers (CameraDevice_Camera.cpp)
extern uint8_t* g_frameBuf;
extern size_t   g_frameBufSize;
extern bool     g_frameBufFilled;
extern const size_t FRAME_FULL_SIZE;
extern const size_t FRAME_PREVIEW_SIZE;
bool framebuf_init_full();
bool framebuf_prepare_preview();
bool framebuf_capture_debug();

// Session token state (CameraDevice_Web.cpp)
extern unsigned long g_sessionTokens[16];
extern uint8_t g_sessionTokenCount;

#if defined(DEV_TEST_HOOKS)
// Test hook pattern storage (CameraDevice_Bus.cpp)
extern String g_lastI2CPattern;
extern String g_lastSPIPattern;
#endif

#endif // FACTORY_TEST

// JWT helper functions (CameraDevice_Auth.cpp)
String base64UrlEncode(const uint8_t* data, size_t len);
String base64UrlDecode(const String& input);
String hmacSha256(const String& data, const String& key);

#endif // CAMERA_DEVICE_INTERNAL_H
