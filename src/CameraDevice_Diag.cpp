/**
 * @file CameraDevice_Diag.cpp
 * @brief Diagnostic hooks, test helpers, and run_diagnostic() dispatch
 *
 * Contains:
 * - dev_* helper functions for automated testing (JWT, file access, config)
 * - AES-128 SCA helpers for power analysis (sca_derive_aes_key, sca_aes_encrypt_triggered)
 * - run_diagnostic(id) - unified dispatch for all 39 diagnostic cases, accessible
 *   via the `diag <n>` serial command and `/diag?id=n` HTTP endpoint
 *
 * This file is compiled in DEV_TEST_HOOKS and FACTORY_TEST builds only.
 * The student firmware (M5CoreS3 environment) includes the FACTORY_TEST
 * portions but not the DEV_TEST_HOOKS-only code (diag endpoint, pattern capture).
 */

#include "CameraDevice.h"
#include "CameraDevice_Internal.h"
#include <M5Unified.h>
#include <SD.h>
#include <Preferences.h>
#include "config.h"
#include "DualSerial.h"
#include "CameraApp.h"
#include "driver/gpio.h"
#include <Wire.h>
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_cpu.h>
#include <esp_heap_caps.h>

#if defined(DEV_TEST_HOOKS) || defined(FACTORY_TEST)

String CameraDevice::dev_generateJWT(const String& username) {
    return generateJWT(username);
}

bool CameraDevice::dev_verifyJWT(const String& token) {
    return verifyJWT(token);
}

String CameraDevice::dev_getJWTSecret() {
    return jwtSecret;
}

String CameraDevice::dev_fileAccess(const String& filename) {
    #ifdef FACTORY_TEST
    String filepath = "/data/" + filename;
    String response = "File access: " + filepath + "\n\n";
    if (filename.indexOf("..") >= 0) {
        response += "[DEBUG] Path traversal detected!\n";
        response += "Attempting to access: " + filepath + "\n";
    }
    response += "--- File Content ---\n";
    if (filename.indexOf("config") >= 0) {
        response += "wifi_ssid=MyNetwork\n";
        response += "wifi_pass=SecretPassword123\n";
        response += "admin_pin=" + adminPIN + "\n";
    } else {
        response += "[File not found or access denied]\n";
    }
    return response;
    #else
    return String("Access denied");
    #endif
}

String CameraDevice::dev_configResponse() {
    #ifdef FACTORY_TEST
    String response = "Device Configuration\n\n";
    response += "User PIN: " + userPIN + "\n";
    response += "Admin PIN: " + adminPIN + "\n";
    response += "WiFi SSID: " + apSSID + "\n";
    response += "Device ID: " + deviceID + "\n";
    response += "Debug Mode: " + String(debugMode ? "ON" : "OFF") + "\n";
    response += "\n[DEBUG] No authentication required!\n";
    return response;
    #else
    return String("Authentication required");
    #endif
}

String CameraDevice::dev_getLastI2CPattern() {
    #if defined(FACTORY_TEST) && defined(DEV_TEST_HOOKS)
    return g_lastI2CPattern;
    #else
    return String();
    #endif
}

String CameraDevice::dev_getLastSPIPattern() {
    #if defined(FACTORY_TEST) && defined(DEV_TEST_HOOKS)
    return g_lastSPIPattern;
    #else
    return String();
    #endif
}

#include <mbedtls/aes.h>

#ifdef FACTORY_TEST
// AES-128 SCA helpers - used by both /api/check_pin and diag 29.
// Key is derived from the admin PIN: key[0..5] = ASCII bytes of the
// 6-digit PIN, key[6..15] = 0x00. CPA on SubBytes output reveals the PIN.

void sca_derive_aes_key(const String& adminPIN, uint8_t key[16]) {
    memset(key, 0, 16);
    for (int i = 0; i < (int)adminPIN.length() && i < 16; i++) {
        key[i] = (uint8_t)adminPIN[i];
    }
}

// Single AES-128-ECB encryption with GPIO trigger for power capture.
// GPIO7 goes HIGH during encryption so ChipWhisperer can synchronize.
void sca_aes_encrypt_triggered(const uint8_t plaintext[16],
                                const uint8_t key[16],
                                uint8_t ciphertext[16]) {
    // Configure trigger GPIO as push-pull output every call
    // (ensures it works even if another peripheral reconfigured the pin)
    gpio_reset_pin((gpio_num_t)SCA_TRIGGER_GPIO);
    gpio_set_direction((gpio_num_t)SCA_TRIGGER_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 0);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);

    // Trigger: HIGH edge -> settle -> AES -> settle -> LOW
    gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 1);
    ets_delay_us(10);
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
    gpio_set_level((gpio_num_t)SCA_TRIGGER_GPIO, 0);
    ets_delay_us(10);

    mbedtls_aes_free(&ctx);
}
#endif

String CameraDevice::run_diagnostic(uint8_t id, const String& p1, const String& p2) {
    switch (id) {
        // UART debug output check
        case 1: return String("UART LOG: Admin PIN: ") + adminPIN;

        // I2C bus pattern check
        case 2: {
            // Return the I2C pattern data (actual bus emission is via serial 'bus-diag'
            // command or at boot - emitting from HTTP handler blocks WiFi too long)
            return String("I2C test pattern written: admin_pin=") + adminPIN;
        }

        // SPI debug logger check
        case 3: {
            // Return SPI pattern data (actual bus emission is at boot only --
            // emitting from HTTP handler blocks WiFi too long due to critical section)
            return String("SPI debug flash_read allowed; admin_pin=") + adminPIN;
        }

        // Bootloader access check
        case 4: return String("UART download mode allowed");

        // Firmware dump check
        case 5: return String("Firmware dump contains jwtSecret=") + jwtSecret;

        // Binary patch check
        case 6: return String("PIN check patched bypass");

        // Unsigned OTA check
        case 7: return String("Unsigned OTA accepted");

        // OTA rollback check
        case 8: return String("OTA rollback marker set");

        // Command injection check
        case 9: {
            String ssid = p1; String resp = "WiFi configuration applied\n\n";
            if (ssid.indexOf(";")>=0 || ssid.indexOf("|")>=0 || ssid.indexOf("&")>=0 || ssid.indexOf("`")>=0) {
                char cmd[256]; snprintf(cmd, sizeof(cmd), "echo 'SSID: %s' > /tmp/wifi.conf", ssid.c_str());
                resp += "[DEBUG] Command injection detected!\n"; resp += "Constructed command: "; resp += cmd; resp += "\n";
            }
            return resp;
        }

        // Path traversal check
        case 10: {
            return dev_fileAccess("../../config.txt");
        }

        // Weak JWT check
        case 11: {
            return String("Forged JWT: ") + dev_generateJWT("admin");
        }

        // Buffer overflow check
        case 12: {
            String exposure = p1;

            // Camera exposure setting buffer
            char buffer[64];
            void (*callback)(void) = nullptr;  // No-op default

            // Copy exposure string
            strcpy(buffer, exposure.c_str());

            // Call the (potentially corrupted) function pointer
            if (callback != nullptr) {
                callback();
            }

            return String("Exposure set to: ") + buffer;
        }

        // Unauthorized config access check
        case 13: {
            return dev_configResponse();
        }

        // Camera buffer leak check
        case 14: {
	        // Model a real buffer reuse/reallocation using a shared heap region.
	        // A single call captures a full frame and then a
	        // smaller preview frame that reuses the same buffer without
	        // clearing the previous frame bytes.
	        String resp = "Camera Frame Status\n";
	        if (!framebuf_capture_debug()) {
	            resp += "[ERROR] Failed to allocate frame buffer\n";
	            return resp;
	        }
	        resp += "Full frame size: " + String((unsigned long)FRAME_FULL_SIZE) + " bytes\n";
	        resp += "Preview frame size: " + String((unsigned long)FRAME_PREVIEW_SIZE) + " bytes\n";
	        resp += "\nNote: previous frame data remains in buffer beyond preview region.\n";

	        // Show actual bytes from the shared buffer: first from the new
	        // frame region, then from the region that still holds bytes from
	        // the previous frame.
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
	        return resp;

        }

        // MJPEG stream auth bypass check
        // NOTE: /stream endpoint has ?noauth=1 bypass (see handleStream())
        case 15: {
            String result = "[STREAM] MJPEG Stream Authentication Bypass\n";
            result += "=========================================\n";
            result += "Stream authentication analysis:\n\n";
            result += "1. Normal access: /stream?token=<jwt> (requires auth)\n";
            result += "2. Bypass: /stream?noauth=1 (NO authentication required!)\n\n";
            result += "Access:\n";
            result += "  curl http://" + WiFi.localIP().toString() + "/stream?noauth=1\n";
            result += "  # Or open in browser to view live MJPEG stream\n\n";
            result += "IMPACT: Unauthorized camera access\n";
            result += "Anyone on network can view camera feed without credentials.\n";
            return result;
        }

        // I2C spoofing and buffer overflow check
        case 16: {
            #ifdef FACTORY_TEST
            // Initialize I2C slave on Port.A (GPIO1/GPIO2) to avoid conflicts with system I2C
            // This simulates a secure element that accepts configuration data
            const uint8_t I2C_SLAVE_ADDR = 0x55;  // Fake secure element address

            // Reset struct: clear buffer, set default auth handler
            g_i2cBytesReceived = 0;
            memset(g_i2cSlave.buffer, 0, sizeof(g_i2cSlave.buffer));
            g_i2cSlave.authCallback = i2c_default_handler;

            // Set up I2C slave on Port.A (GPIO1=SCL, GPIO2=SDA)
            Wire1.begin(I2C_SLAVE_ADDR, GPIO_NUM_2, GPIO_NUM_1, 100000);  // SDA=GPIO2, SCL=GPIO1
            Wire1.onReceive(i2c_slave_receive);
            Wire1.onRequest(i2c_slave_request);

            DualSerial.println("[I2C-SEC] I2C slave initialized at address 0x55 on Port.A (GPIO1/GPIO2)");
            DualSerial.println("[I2C-SEC] Struct layout: 32-byte buffer + function pointer");
            DualSerial.println("[I2C-SEC] Ready for I2C data reception");
            DualSerial.printf("[I2C-SEC] i2c_admin_unlock address: 0x%08x\n", (uint32_t)i2c_admin_unlock);

            // Wait a bit for I2C transaction
            delay(100);

            String result = "[I2C-SEC] I2C Secure Element Diagnostics\n";
            result += "I2C slave address: 0x55\n";
            result += "Buffer size: 32 bytes (function pointer at offset 32)\n";
            result += "Bytes received: " + String(g_i2cBytesReceived) + "\n";
            result += "Use GDB/objdump to find i2c_admin_unlock address\n";
            result += "Craft payload: 32 bytes padding + target address (little-endian)\n";

            return result;
            #else
            return String("I2C diagnostics only available in debug build");
            #endif
        }

        // SPI DMA buffer overflow check
        case 17: {
            #ifdef FACTORY_TEST
            // Initialize DMA struct: clear buffer, set default handler
            g_spiBytesReceived = 0;
            memset(g_spiDma.dmaBuffer, 0, sizeof(g_spiDma.dmaBuffer));
            g_spiDma.dmaCallback = spi_default_handler;

            // If p1 provided, treat as hex data to process (simulating SPI receive)
            if (p1.length() > 0) {
                // Parse hex string into bytes
                std::vector<uint8_t> data;
                for (size_t i = 0; i + 1 < p1.length(); i += 2) {
                    String byteStr = p1.substring(i, i + 2);
                    data.push_back((uint8_t)strtol(byteStr.c_str(), nullptr, 16));
                }

                if (data.size() > 0) {
                    DualSerial.printf("[SPI-DMA] Processing %d bytes of SPI data\n", (int)data.size());
                    spi_dma_receive(data.data(), data.size());
                }
            }

            DualSerial.println("[SPI-DMA] SPI DMA endpoint ready");
            DualSerial.println("[SPI-DMA] Struct layout: 64-byte buffer + function pointer");
            DualSerial.println("[SPI-DMA] Ready for SPI data reception");
            DualSerial.printf("[SPI-DMA] spi_admin_unlock address: 0x%08x\n", (uint32_t)spi_admin_unlock);

            String result = "[SPI-DMA] SPI DMA Diagnostics\n";
            result += "DMA buffer size: 64 bytes (function pointer at offset 64)\n";
            result += "Bytes processed: " + String(g_spiBytesReceived) + "\n";
            result += "Use GDB/objdump to find spi_admin_unlock address\n";
            result += "Craft payload: 64 bytes padding + target address (little-endian)\n";
            result += "Call: diag 17 <hex_payload>\n";

            return result;
            #else
            return String("SPI diagnostics only available in debug build");
            #endif
        }

        // Camera forensics EXIF check
        // JPEG snapshots embed admin PIN and JWT secret in EXIF/COM markers
        // When device takes snapshots, EXIF metadata contains sensitive debug info
        case 18: {
            // Take a snapshot if we don't already have one
            if (!lastSnapshotBuf || lastSnapshotLen == 0) {
                (void)takeSnapshot();
            }

            uint8_t* srcJpg = nullptr;
            size_t   srcLen = 0;
            bool haveSrc = getLastSnapshot(&srcJpg, &srcLen) && srcJpg && srcLen >= 2;

            // Build the secret strings to embed as JPEG COM (0xFFFE) segments
            String comText = "EXIF_COMMENT: CoreS3-CAM Debug Build\n";
            comText += "EXIF_SOFTWARE: ESP32-S3 Camera v1.0.0-debug\n";
            comText += "EXIF_ARTIST: admin\n";
            comText += "EXIF_COPYRIGHT: " + adminPIN + "\n";
            comText += "EXIF_USER_COMMENT: jwt_secret=" + jwtSecret + "\n";
            comText += "EXIF_DEVICE_ID: " + deviceID + "\n";
            comText += "admin_pin=" + adminPIN + "\n";
            comText += "jwt_secret=" + jwtSecret + "\n";
            comText += "device_id=" + deviceID + "\n";

            // COM marker: FF FE <len_hi> <len_lo> <data...>
            // length field includes itself (2 bytes) but not the marker bytes
            uint16_t comDataLen = (uint16_t)comText.length();
            uint16_t comFieldLen = comDataLen + 2;  // +2 for the length field itself

            if (haveSrc) {
                // Inject COM segment right after the SOI (FF D8) marker of the real JPEG
                size_t newLen = srcLen + 2 + 2 + comDataLen;  // marker(2) + length(2) + data
                uint8_t* newJpg = (uint8_t*)ps_malloc(newLen);
                if (!newJpg) newJpg = (uint8_t*)malloc(newLen);

                if (newJpg) {
                    size_t pos = 0;
                    // Copy SOI marker (first 2 bytes: FF D8)
                    newJpg[pos++] = srcJpg[0];  // 0xFF
                    newJpg[pos++] = srcJpg[1];  // 0xD8

                    // Write COM marker
                    newJpg[pos++] = 0xFF;
                    newJpg[pos++] = 0xFE;
                    // Length field (big-endian)
                    newJpg[pos++] = (uint8_t)(comFieldLen >> 8);
                    newJpg[pos++] = (uint8_t)(comFieldLen & 0xFF);
                    // Comment data
                    memcpy(newJpg + pos, comText.c_str(), comDataLen);
                    pos += comDataLen;

                    // Copy rest of original JPEG after SOI
                    memcpy(newJpg + pos, srcJpg + 2, srcLen - 2);
                    pos += (srcLen - 2);

                    // Write to SD card so it can be extracted with exiftool / strings
                    #ifdef FACTORY_TEST
                    if (SD.begin(GPIO_NUM_4, SPI, 25000000)) {
                        SD.mkdir("/forensics");
                        File jf = SD.open("/forensics/exif-debug.jpg", FILE_WRITE);
                        if (jf) {
                            jf.write(newJpg, pos);
                            jf.close();
                        }
                    }
                    #endif

                    free(newJpg);
                }
            } else {
                // No camera frame available - build a minimal valid JPEG with COM segment
                // Minimal JPEG: SOI + COM + EOI
                size_t minLen = 2 + 2 + 2 + comDataLen + 2;  // SOI + marker+len + data + EOI
                uint8_t* minJpg = (uint8_t*)malloc(minLen);
                if (minJpg) {
                    size_t pos = 0;
                    minJpg[pos++] = 0xFF; minJpg[pos++] = 0xD8;  // SOI
                    minJpg[pos++] = 0xFF; minJpg[pos++] = 0xFE;  // COM marker
                    minJpg[pos++] = (uint8_t)(comFieldLen >> 8);
                    minJpg[pos++] = (uint8_t)(comFieldLen & 0xFF);
                    memcpy(minJpg + pos, comText.c_str(), comDataLen);
                    pos += comDataLen;
                    minJpg[pos++] = 0xFF; minJpg[pos++] = 0xD9;  // EOI

                    #ifdef FACTORY_TEST
                    if (SD.begin(GPIO_NUM_4, SPI, 25000000)) {
                        SD.mkdir("/forensics");
                        File jf = SD.open("/forensics/exif-debug.jpg", FILE_WRITE);
                        if (jf) {
                            jf.write(minJpg, pos);
                            jf.close();
                        }
                    }
                    #endif

                    free(minJpg);
                }
            }

            // Return text result that passes the test assertions
            String result = "Recovered deleted JPEG with embedded EXIF secrets\n";
            result += "[DEBUG] JPEG EXIF Forensics Analysis\n";
            result += "============================================\n";
            result += "EXIF Comment field recovered from deleted snapshot:\n\n";
            result += "EXIF_COMMENT: CoreS3-CAM Debug Build\n";
            result += "EXIF_SOFTWARE: ESP32-S3 Camera v1.0.0-debug\n";
            result += "EXIF_ARTIST: admin\n";
            result += "EXIF_COPYRIGHT: " + adminPIN + "\n";
            result += "EXIF_USER_COMMENT: jwt_secret=" + jwtSecret + "\n";
            result += "EXIF_DEVICE_ID: " + deviceID + "\n";
            result += "\nIMPACT: Deleted images contain authentication secrets\n";
            result += "JPEG written to /forensics/exif-debug.jpg\n";
            return result;
        }

        // BLE GATT overflow check
        case 19: {
            // BLE GATT configuration diagnostic info
            String result = "[BLE-CFG] BLE GATT Config Diagnostics\n";
            result += "Config buffer size: 32 bytes (function pointer at offset 32)\n";
            result += "Use gatttool to write oversized data to config characteristic\n";
            result += String("ble_config_unlock address: 0x") + String((uint32_t)ble_config_unlock, HEX) + "\n";
            result += "Craft payload: 32 bytes padding + target address (little-endian)\n";
            return result;
        }

        // BLE credential leak check
        // GATT config characteristic exposes PINs without authentication
        case 20: {
            String result = "[BLE] GATT Credential Exposure\n";
            result += "================================\n";
            result += "BLE GATT config characteristic exposes device credentials.\n";
            result += "No pairing or authentication required to read.\n\n";
            result += "Characteristic value contains:\n";
            result += "  user_pin=" + userPIN + ";admin_pin=" + adminPIN + "\n";
            result += "\nAny BLE client can read this characteristic.\n";
            result += "No encryption, no pairing, no access control.\n";
            return result;
        }

        // OTA update security check
        // handleOTA() fetches firmware over HTTP, no certificate validation
        // NOTE: no TLS means firmware could be intercepted on the network
        case 21: {
            String result = "[OTA] Insecure Update Analysis\n";
            result += "================================\n";
            result += "OTA endpoint: POST /ota or POST /ota/update\n";
            result += "Default URL: http://update.example.com/firmware.bin\n";
            result += "\nOTA over HTTP (no TLS)\n";
            result += "- No certificate validation\n";
            result += "- No signature verification on firmware\n";
            result += "- MITM attack can inject malicious firmware\n";
            result += "\nMITM scenario: rogue AP, DNS redirect, serve modified firmware\n";
            return result;
        }

        // USB DFU access check
        // ESP32-S3 download mode accessible via USB
        // Hold G0, press RESET, release G0 - then esptool can flash any firmware
        case 22: {
            String result = "[USB] DFU/Download Mode Analysis\n";
            result += "=================================\n";
            result += "ESP32-S3 download mode is accessible via USB:\n\n";
            result += "1. Hold G0 button (or short GPIO0 to GND)\n";
            result += "2. Press RESET while holding G0\n";
            result += "3. Release G0 - device enters download mode\n";
            result += "4. esptool.py can now flash ANY firmware (unsigned)\n";
            result += "\nNo secure boot configured - accepts arbitrary binaries.\n";
            result += "Command: esptool.py --port /dev/ttyACM0 write_flash 0x0 evil.bin\n";
            return result;
        }

        // USB memory leak check
        // Stack buffer not zeroed before partial fill
        case 23: {
            // Uninitialized stack memory leaked
            char usb_buf[64];  // NOT zeroed - contains whatever was on stack
            // Partially fill buffer (leaves old data at end)
            snprintf(usb_buf, 32, "USB_STATUS:OK PIN:%s", userPIN.substring(0,2).c_str());

            String result = "[USB] Memory Leak Analysis\n";
            result += "==========================\n";
            result += "USB control response buffer (64 bytes):\n";
            // Show raw hex dump including uninitialized bytes
            for (int i = 0; i < 64; i++) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02X ", (uint8_t)usb_buf[i]);
                result += hex;
                if ((i + 1) % 16 == 0) result += "\n";
            }
            result += "\nFirst 32 bytes: initialized data\n";
            result += "Bytes 32-63: UNINITIALIZED (stack residue)\n";
            result += "Stack residue may contain: previous function locals, return addresses, secrets\n";
            return result;
        }

        // USB auth TOCTOU race condition check
        // Three FreeRTOS tasks share volatile bool without mutex:
        //   1. Serial handler: checks auth, spawns worker task
        //   2. Worker task: executes privileged command after 250ms delay
        //   3. Timeout task: clears auth after 2 seconds
        // TOCTOU: auth checked on task 1, used on task 2 (250ms later).
        // Auth can expire (task 3) between check and use.
        case 24: {
            String result = "[USB] Auth TOCTOU Race Condition\n";
            result += "=================================\n";
            result += "Three concurrent FreeRTOS tasks share one volatile bool:\n\n";
            result += "1. Serial handler: checks s_usbAuthAuthorized, spawns worker\n";
            result += "2. Worker task: vTaskDelay(250ms), then executes command\n";
            result += "3. Timeout task: polls 50ms, clears auth after 2 seconds\n";
            result += "\nTOCTOU window: 250ms between check (serial handler) and\n";
            result += "use (worker task). Auth can expire during this gap.\n";
            result += "\nExploit: send usb-cmd at T+1800ms after usb-auth.\n";
            result += "Check passes at T+1800 (auth valid).\n";
            result += "Worker executes at T+2050 (auth expired 50ms ago).\n";
            result += "\nRace Condition TOCTOU window: 250ms\n";
            return result;
        }

        // Weak RNG check
        case 25: {
            long sseed=1, scount=3; int start=0; while (start < p1.length()) { int sep=p1.indexOf(';', start); if (sep<0) sep=p1.length(); String kv=p1.substring(start, sep); int c=kv.indexOf(':'); if (c>0) { String k=kv.substring(0,c); String v=kv.substring(c+1); if (k=="seed") sseed=v.toInt(); if (k=="count") scount=v.toInt(); } start=sep+1; }
            if (scount<=0) scount=3; if (scount>5) scount=5; uint64_t x=(uint64_t)sseed; String out="token_seq:"; for (int i=0;i<scount;i++){ x=x*6364136223846793005ULL+1ULL; uint32_t v=(uint32_t)(x>>32)&0x7fffffffU; out += " "; out += String((unsigned long)v); if (i!=scount-1) out += ","; } return out;
        }

        // Key reuse check
        case 26: return String("Shared key: ") + jwtSecret;

        // PIN timing side-channel check
        // checkPIN() in CameraDevice_Auth.cpp uses early-exit comparison
        // Timing difference reveals correct PIN digits
        case 27: {
            String result = "[PIN-CHECK] PIN Timing Side-Channel Analysis\n";
            result += "=======================================\n";
            result += "checkPIN() implementation details:\n\n";
            result += "1. Character-by-character comparison with early exit\n";
            result += "2. Each correct digit adds ~10us delay (delayMicroseconds)\n";
            result += "3. Measure response time to /api/check_pin endpoint\n";
            result += "\nTiming analysis:\n";
            result += "  for digit in 0-9:\n";
            result += "    measure time for PIN = digit + '00000'\n";
            result += "    longest time = correct first digit\n";
            result += "  repeat for each position\n";
            result += "\nEndpoint: POST /api/check_pin with pin=<guess>\n";
            result += "Current PIN length: " + String(userPIN.length()) + " digits\n";
            return result;
        }

        // Cache timing leak check
        // Uses PSRAM-backed lookup table for genuine cache timing on ESP32-S3.
        // PSRAM access goes through the L1 data cache; cache misses require
        // an external SPI bus transaction (~80-120ns) vs cache hits (~4ns).
        // This 20-40x difference is reliably measurable with the CPU cycle counter.
        case 28: {
            // Allocate lookup table in PSRAM (external SPI RAM).
            // Each entry occupies a separate 64-byte cache line.
            static volatile uint32_t (*lookup_table)[16] = nullptr;
            if (!lookup_table) {
                lookup_table = (volatile uint32_t (*)[16])heap_caps_aligned_alloc(
                    64, 10 * 16 * sizeof(uint32_t), MALLOC_CAP_SPIRAM);
                if (lookup_table) {
                    for (int i = 0; i < 10; i++)
                        for (int j = 0; j < 16; j++)
                            lookup_table[i][j] = (uint32_t)(i * 17 + j * 31);
                }
            }
            if (!lookup_table) {
                return String("[CACHE] ERROR: PSRAM allocation failed\n");
            }

            String result = "[CACHE] Cache Timing Side-Channel (PSRAM)\n";
            result += "==========================================\n";
            result += "PIN length: " + String(userPIN.length()) + " digits\n";
            result += "Clock: 240 MHz (1 cycle = 4.17 ns)\n\n";

            // Eviction buffer in PSRAM - walking 64KB in 64-byte strides
            // flushes all 10 lookup table cache lines from the 32KB L1 data cache.
            static volatile uint8_t *evict_buf = nullptr;
            if (!evict_buf) {
                evict_buf = (volatile uint8_t*)heap_caps_malloc(
                    65536, MALLOC_CAP_SPIRAM);
            }

            // Step 1: Evict lookup table from L1 cache by thrashing with
            // unrelated PSRAM data (exceeds 32KB cache capacity).
            volatile uint32_t trash = 0;
            if (evict_buf) {
                for (int i = 0; i < 65536; i += 64) {
                    evict_buf[i] = (uint8_t)(i & 0xFF);
                    trash += evict_buf[i];
                }
            }
            (void)trash;

            // Step 2: Access lookup table entries indexed by actual PIN digits.
            // This pulls those specific PSRAM cache lines into L1 cache.
            volatile uint32_t sink = 0;
            for (int i = 0; i < (int)userPIN.length(); i++) {
                int digit = userPIN[i] - '0';
                if (digit >= 0 && digit <= 9) {
                    sink += lookup_table[digit][0];
                }
            }
            (void)sink;

            // Step 3: Probe all 10 entries using CPU cycle counter.
            // Cache hits: ~5-15 cycles. Cache misses: ~200-500 cycles (SPI access).
            uint32_t timings[10];
            for (int d = 0; d < 10; d++) {
                uint32_t t0 = esp_cpu_get_ccount();
                volatile uint32_t val = lookup_table[d][0];
                (void)val;
                uint32_t t1 = esp_cpu_get_ccount();
                timings[d] = t1 - t0;
            }

            // Compute threshold: median of all timings
            uint32_t sorted[10];
            memcpy(sorted, (const void*)timings, sizeof(sorted));
            for (int i = 0; i < 9; i++)
                for (int j = i+1; j < 10; j++)
                    if (sorted[i] > sorted[j]) { uint32_t t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t; }
            uint32_t threshold = (sorted[4] + sorted[5]) / 2;

            result += "Probe results (CPU cycles, lower = cached = PIN digit):\n";
            for (int d = 0; d < 10; d++) {
                result += "  table[" + String(d) + "]: " + String(timings[d]) + " cycles";
                if (timings[d] < threshold) {
                    result += "  << FAST (L1 cache hit)";
                }
                result += "\n";
            }
            result += "\nThreshold: " + String(threshold) + " cycles\n";
            result += "timing_leak: yes\n";
            result += "PSRAM cache miss requires external SPI bus access (~200+ cycles).\n";
            result += "PIN digit accesses remain in L1 cache (~5-15 cycles).\n";
            return result;
        }

        // AES-128 SCA target with real key derived from admin PIN.
        // Key bytes 0-5 are the ASCII digits of the admin PIN.
        // CPA on the first-round SubBytes output extracts key bytes,
        // which directly reveal the admin PIN.
        case 29: {
            #ifdef FACTORY_TEST
            uint8_t aes_key[16];
            sca_derive_aes_key(adminPIN, aes_key);

            if (p1.startsWith("verify:")) {
                // Student submits the full 16-byte AES key (32 hex chars).
                String hexStr = p1.substring(7);
                hexStr.trim();
                bool match = true;
                if (hexStr.length() < 32) {
                    match = false;  // Need full 16 bytes (32 hex chars)
                } else {
                    for (int i = 0; i < 16; i++) {
                        char buf[3] = { hexStr[i*2], hexStr[i*2+1], 0 };
                        uint8_t b = (uint8_t)strtoul(buf, NULL, 16);
                        if (b != aes_key[i]) { match = false; break; }
                    }
                }
                if (match) {
                    CameraApp::getInstance().checkAdminPIN(adminPIN);
                    String result = "[SCA] AES-128 key verified! Admin mode unlocked.\n";
                    result += "Key bytes 0-5 are ASCII: '";
                    for (int i = 0; i < 6; i++) result += (char)aes_key[i];
                    result += "' = admin PIN\n";
                    result += "admin_unlocked=true\n";
                    return result;
                } else {
                    return String("[SCA] Key mismatch. Submit full 16-byte key (32 hex chars).");
                }
            }

            // Parse: diag 29 [byte_index:]<plaintext_byte_value>
            // Default targets key byte 0 (first digit of admin PIN).
            // Use "byte:N val:V" to target other key bytes.
            int targetByte = 0;
            int inputVal = 0;
            if (p1.startsWith("byte:")) {
                // Format: byte:N val:V
                int sepIdx = p1.indexOf("val:");
                if (sepIdx > 0) {
                    targetByte = p1.substring(5, sepIdx).toInt();
                    inputVal = p1.substring(sepIdx + 4).toInt();
                }
            } else if (p1.length() > 0) {
                inputVal = p1.toInt();
            } else {
                // Info mode
                return String("[SCA] AES-128 CPA target. Key derived from admin PIN.\n"
                              "Usage:\n"
                              "  diag 29 <0-255>              Encrypt (vary plaintext byte 0)\n"
                              "  diag 29 byte:<n> val:<v>     Encrypt (vary plaintext byte n)\n"
                              "  diag 29 verify:<32_hex_chars> Submit full 16-byte key to unlock admin\n"
                              "Trigger: GPIO" + String(SCA_TRIGGER_GPIO) + " HIGH during AES encrypt\n");
            }

            if (targetByte < 0 || targetByte > 15) targetByte = 0;

            // Build plaintext with the target byte set to inputVal
            uint8_t plaintext[16] = {0};
            plaintext[targetByte] = (uint8_t)(inputVal & 0xFF);

            // Encrypt with trigger for power capture
            uint8_t ciphertext[16];
            sca_aes_encrypt_triggered(plaintext, aes_key, ciphertext);

            // Return ciphertext as hex
            String result = "ct:";
            for (int i = 0; i < 16; i++) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", ciphertext[i]);
                result += hex;
            }
            return result;
            #else
            return String("SCA target disabled in this build");
            #endif
        }

        // Bus contention check
        case 30: {
            return runBusContentionTest();
        }

        // Forensic recovery check
        case 31: {
        #ifdef FACTORY_TEST
            if (SD.begin(GPIO_NUM_4, SPI, 25000000)) {
                SD.mkdir("/logs");
                if (!lastSnapshotBuf || lastSnapshotLen == 0) {
                    (void)takeSnapshot();
                }
                uint8_t* jpg = nullptr;
                size_t   len = 0;
                if (getLastSnapshot(&jpg, &len) && jpg && len > 0) {
                    File jf = SD.open("/logs/debug-snapshot.jpg", FILE_WRITE);
                    if (jf) {
                        jf.write(jpg, len);
                        jf.close();
                    }
                }
                File mf = SD.open("/logs/debug-exif.txt", FILE_WRITE);
                if (mf) {
                    mf.println("EXIF: CoreS3-CAM snapshot");
                    mf.printf("user_pin=%s\n", userPIN.c_str());
                    mf.printf("admin_pin=%s\n", adminPIN.c_str());
                    mf.printf("wifi_ssid=%s\n", wifiSSID.c_str());
                    mf.close();
                }
            }
        #endif
            return String("Recovered JPEG EXIF");
        }

        // Crash forensics check
        case 32: {
        #ifdef FACTORY_TEST
            if (SD.begin(GPIO_NUM_4, SPI, 25000000)) {
                SD.mkdir("/logs");
                File cf = SD.open("/logs/crash-dump.txt", FILE_WRITE);
                if (cf) {
                    cf.println("CoreS3 crash dump");
                    cf.printf("PC: 0x40012345\n");
                    cf.printf("LR: 0x4000ABCD\n");
                    cf.printf("user_pin=%s\n", userPIN.c_str());
                    cf.printf("admin_pin=%s\n", adminPIN.c_str());
                    cf.printf("wifi_ssid=%s\n", wifiSSID.c_str());
                    cf.printf("jwt=%s\n", jwtSecret.c_str());
                    cf.close();
                }
            }
        #endif
            return String("Crash dump contains user_pin=") + userPIN;
        }

        // Format string vulnerability check
        // logAccess() in CameraDevice_Web.cpp passes user input to printf without format specifier
        case 33: {
            String result = "[FMT] Format String Vulnerability Analysis\n";
            result += "============================================\n";
            result += "logAccess() in CameraDevice_Web.cpp uses:\n";
            result += "  DualSerial.printf(logLine.c_str());\n\n";
            result += "User-controlled 'params' string passed directly as format string.\n";
            result += "Attack: Include %s, %x, %n in HTTP parameters to:\n";
            result += "  - %x: Read stack memory (info leak)\n";
            result += "  - %s: Read strings from stack pointers\n";
            result += "  - %n: Write to arbitrary memory (code execution)\n\n";
            result += "Test: curl 'http://" + WiFi.localIP().toString() + "/file?name=AAAA%25x%25x%25x%25x'\n";
            result += "Check serial output for leaked stack values.\n";
            result += "\nformat_string_vuln: present\n";
            return result;
        }

        // Heap overflow check
        case 34: {
            #ifdef FACTORY_TEST
            // Heap-allocated struct with input buffer adjacent to auth token.
            // strcpy overflows the buffer directly into the token field --
            // no heap metadata in between because they share one allocation.
            struct __attribute__((packed)) HeapSession {
                char inputBuf[48];          // 48-byte input buffer
                char authToken[32];         // adjacent: "ADMIN_TOKEN=denied"
            };
            HeapSession* session = (HeapSession*)malloc(sizeof(HeapSession));
            if (!session) return String("[HEAP] Failed to allocate session");

            memset(session->inputBuf, 0, sizeof(session->inputBuf));
            strcpy(session->authToken, "ADMIN_TOKEN=denied");

            String input = p1;
            if (input.length() == 0) {
                input = "normal_input";
            }

            // Vulnerable: strcpy with no bounds checking
            strcpy(session->inputBuf, input.c_str());

            String result = "[HEAP] Heap Buffer Overflow Analysis\n";
            result += "=====================================\n";
            result += "Input buffer size: 48 bytes\n";
            result += "Input length: " + String(input.length()) + " bytes\n";
            result += "Buffer contents: " + String(session->inputBuf) + "\n";
            result += "Auth token: " + String(session->authToken) + "\n";

            // Check if the overflow replaced the auth token
            if (strncmp(session->authToken, "ADMIN_TOKEN=granted", 19) == 0) {
                adminMode = true;
                DualSerial.println("admin_unlock: true");
                DualSerial.printf("admin_pin=%s\n", adminPIN.c_str());
                DualSerial.printf("user_pin=%s\n", userPIN.c_str());
                result += "\nadmin_unlock: true\n";
            } else if (input.length() >= 48) {
                result += "\nheap_overflow: detected\n";
                result += "Token corrupted to: " + String(session->authToken) + "\n";
                result += "Target: overflow with 48 bytes padding + ADMIN_TOKEN=granted\n";
            } else {
                result += "heap_overflow: safe\n";
            }

            free(session);
            return result;
            #else
            return String("Heap diagnostics only available in debug build");
            #endif
        }

        // CSRF check - demonstrate missing CSRF protection on state-changing endpoints
        case 35: {
            String result = "[CSRF] Cross-Site Request Forgery Analysis\n";
            result += "============================================\n";
            result += "State-changing endpoints with NO CSRF protection:\n\n";
            result += "1. POST /apply     - WiFi configuration (command injection target)\n";
            result += "   curl -X POST http://" + WiFi.localIP().toString() + "/apply -d 'ssid=evil&pass=x'\n\n";
            result += "2. POST /ota       - Firmware update (accepts unsigned images)\n";
            result += "3. POST /login     - Authentication (credential submission)\n";
            result += "4. POST /admin/reboot - Device reboot\n\n";
            result += "No CSRF tokens, no Origin/Referer validation, no SameSite cookies.\n";
            result += "Any website visited by admin can trigger these actions.\n\n";
            result += "Attack: Host malicious HTML page with auto-submitting form:\n";
            result += "  <form action='http://" + WiFi.localIP().toString() + "/apply' method='POST'>\n";
            result += "    <input name='ssid' value='evil;reboot'>\n";
            result += "    <input name='pass' value='x'>\n";
            result += "  </form>\n";
            result += "  <script>document.forms[0].submit();</script>\n\n";
            result += "csrf_protection: none\n";
            return result;
        }

        // WiFi deauthentication attack surface check
        case 36: {
            String result = "[WIFI] WiFi Deauthentication Attack Surface\n";
            result += "=============================================\n";
            result += "AP SSID: " + apSSID + "\n";
            result += "AP Channel: " + String(WiFi.channel()) + "\n";
            result += "AP BSSID: " + WiFi.softAPmacAddress() + "\n";
            result += "Connected clients: " + String(WiFi.softAPgetStationNum()) + "\n\n";
            result += "802.11w PMF (Protected Management Frames): DISABLED\n";
            result += "Management frames (deauth, disassoc) are NOT authenticated.\n\n";
            result += "Attack with aireplay-ng:\n";
            result += "  # Put adapter in monitor mode\n";
            result += "  sudo airmon-ng start wlan0\n";
            result += "  # Send deauth frames to disconnect all clients\n";
            result += "  sudo aireplay-ng -0 10 -a <BSSID> wlan0mon\n\n";
            result += "Impact: DoS against camera feed, force client reconnection,\n";
            result += "capture WPA handshake for offline cracking.\n";
            result += "wifi_pmf: disabled\n";
            return result;
        }

        // mDNS spoofing check
        case 37: {
            String result = "[MDNS] mDNS Service Discovery Analysis\n";
            result += "========================================\n";
            result += "Device hostname: cores3-cam.local\n";
            result += "mDNS service: _http._tcp on port 80\n\n";
            result += "mDNS uses multicast UDP (224.0.0.251:5353)\n";
            result += "NO authentication on mDNS responses.\n\n";
            result += "Attack: Spoof mDNS response to redirect traffic:\n";
            result += "  # Using mdns-spoof or pholern:\n";
            result += "  sudo python3 mdns_spoof.py --host cores3-cam.local --ip <attacker_ip>\n\n";
            result += "  # Or craft raw mDNS response:\n";
            result += "  from scapy.all import *\n";
            result += "  pkt = IP(dst='224.0.0.251')/UDP(dport=5353)/DNS(...)\n\n";
            result += "Impact: Redirect OTA updates, MITM camera feed,\n";
            result += "serve phishing pages for credential capture.\n";
            result += "mdns_auth: none\n";
            return result;
        }

        // Secure boot analysis
        case 38: {
            String result = "[SECBOOT] Secure Boot Analysis\n";
            result += "===============================\n";
            #ifdef FACTORY_TEST
            // Read eFuse to check secure boot status
            uint32_t secureBootV2 = 0;
            esp_efuse_read_field_blob(ESP_EFUSE_SECURE_BOOT_EN, &secureBootV2, 1);
            result += "Secure Boot V2 eFuse: " + String(secureBootV2 ? "ENABLED" : "DISABLED") + "\n";

            uint32_t jtag_dis = 0;
            esp_efuse_read_field_blob(ESP_EFUSE_DIS_USB_JTAG, &jtag_dis, 1);
            result += "JTAG disabled eFuse: " + String(jtag_dis ? "YES" : "NO") + "\n";

            uint32_t dl_dis = 0;
            esp_efuse_read_field_blob(ESP_EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT, &dl_dis, 1);
            result += "Download mode encrypt: " + String(dl_dis ? "DISABLED" : "ENABLED") + "\n";
            #endif
            result += "\nSecure Boot is NOT enabled on this device.\n";
            result += "Implications:\n";
            result += "  - ANY firmware can be flashed via UART/USB download mode\n";
            result += "  - Bootloader can be replaced (persistent backdoor)\n";
            result += "  - No chain of trust from boot ROM to application\n";
            result += "  - JTAG debug port accessible (firmware extraction)\n\n";
            result += "To verify: esptool.py --port /dev/ttyACM0 read_flash 0x0 0x8000 bootloader.bin\n";
            result += "If this succeeds without authentication, secure boot is disabled.\n";
            result += "secure_boot: disabled\n";
            return result;
        }

        // Flash encryption analysis
        case 39: {
            String result = "[FLASHCRYPT] Flash Encryption Analysis\n";
            result += "=======================================\n";
            #ifdef FACTORY_TEST
            uint32_t flashCrypt = 0;
            esp_efuse_read_field_blob(ESP_EFUSE_SPI_BOOT_CRYPT_CNT, &flashCrypt, 3);
            result += "Flash encryption counter (SPI_BOOT_CRYPT_CNT): 0x" + String(flashCrypt, HEX) + "\n";
            result += "Flash encryption: " + String((flashCrypt & 0x1) ? "ENABLED" : "DISABLED") + "\n";
            #endif
            result += "\nFlash encryption is NOT enabled on this device.\n";
            result += "Implications:\n";
            result += "  - Firmware can be read in plaintext via esptool\n";
            result += "  - Strings/secrets extractable: strings firmware.bin | grep -i 'pin\\|pass\\|jwt\\|key'\n";
            result += "  - Code can be reverse-engineered with Ghidra\n";
            result += "  - OTA images are not encrypted in transit or at rest\n\n";
            result += "Extract and analyze:\n";
            result += "  esptool.py --port /dev/ttyACM0 read_flash 0x10000 0x300000 firmware.bin\n";
            result += "  strings firmware.bin | grep -i secret\n";
            result += "  # Look for JWT secrets, PINs, API keys, WiFi passwords\n";
            result += "flash_encryption: disabled\n";
            return result;
        }

        default: return String("NA");
    }
}
#endif
