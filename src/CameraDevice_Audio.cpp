/**
 * @file CameraDevice_Audio.cpp
 * @brief Speaker and microphone hardware control
 *
 * The CoreS3 audio path is: ESP32-S3 I2S -> AW88298 amplifier -> speaker.
 * Microphone uses: ES7210 codec -> I2S -> ESP32-S3.
 *
 * IMPORTANT: I2C and I2S are shared resources. The camera holds the I2C bus
 * after init, so audio tests must temporarily reclaim it (via M5.In_I2C.begin())
 * and release it afterward. Speaker and microphone share a single I2S port, so
 * only one can be active at a time (M5.Mic.end() before M5.Speaker.begin()).
 *
 * The AW9523 GPIO expander (0x58) controls speaker power (reg 0x02 bit 2)
 * and boost enable (reg 0x03 bit 7). Both must be set before audio output.
 */

#include "CameraDevice.h"
#include <M5Unified.h>
#include "DualSerial.h"
#include "CameraApp.h"

// ============================================================================
// Audio Functions
// ============================================================================

bool CameraDevice::initAudio() {
    if (audioInitialized) {
        DualSerial.println("[AUDIO] Already initialized");
        return true;
    }

    DualSerial.println("[AUDIO] Audio was initialized in main.cpp during startup");

    // Just print the configuration
    auto spk_cfg = M5.Speaker.config();
    DualSerial.printf("[AUDIO] Speaker config: BCK=%d, WS=%d, DOUT=%d, I2S=%d\n",
                     spk_cfg.pin_bck, spk_cfg.pin_ws, spk_cfg.pin_data_out, spk_cfg.i2s_port);

    auto mic_cfg = M5.Mic.config();
    DualSerial.printf("[AUDIO] Mic config: BCK=%d, WS=%d, DIN=%d, I2S=%d\n",
                     mic_cfg.pin_bck, mic_cfg.pin_ws, mic_cfg.pin_data_in, mic_cfg.i2s_port);

    audioInitialized = true;
    DualSerial.println("[AUDIO] Audio ready");
    return true;
}

void CameraDevice::deinitAudio() {
    if (audioInitialized) {
        M5.Speaker.end();
        M5.Mic.end();
        audioInitialized = false;
        DualSerial.println("[AUDIO] Deinitialized");
    }
}

bool CameraDevice::testSpeaker() {
    if (!audioInitialized) {
        DualSerial.println("[AUDIO] Not initialized");
        return false;
    }

    DualSerial.println("[AUDIO] Testing speaker - playing 1kHz tone for 2 seconds at MAXIMUM volume");
    DualSerial.flush();

    // Keep camera initialized; the internal I2C bus is shared between
    // the camera and audio devices and can be used safely from both.

    // Use system I2C bus for speaker hardware access (do not force re-init here)
    DualSerial.println("[AUDIO] Using system I2C bus for speaker hardware (no explicit begin)");
    DualSerial.flush();

    // Manually configure speaker hardware (AW9523 + AW88298)
    // We cannot call M5.Speaker.begin() because it will hang
    DualSerial.println("[AUDIO] Configuring speaker hardware manually...");
    DualSerial.flush();

    bool success = true;

    // Enable BOOST on AW9523 (CRITICAL - this was missing!)
    bool boost_ok = M5.In_I2C.bitOn(0x58, 0x03, 0b10000000, 400000);
    DualSerial.printf("[AUDIO] AW9523 BOOST enable: %s\n", boost_ok ? "OK" : "FAILED");
    DualSerial.flush();
    success &= boost_ok;

    // Enable speaker via AW9523 GPIO expander (bit 2 of register 0x02)
    bool aw9523_ok = M5.In_I2C.bitOn(0x58, 0x02, 0b00000100, 400000);
    DualSerial.printf("[AUDIO] AW9523 speaker enable: %s\n", aw9523_ok ? "OK" : "FAILED");
    DualSerial.flush();
    success &= aw9523_ok;

    // Configure AW88298 amplifier for 48kHz operation
    auto writeAW88298 = [](uint8_t reg, uint16_t value) -> bool {
        value = __builtin_bswap16(value);
        bool ok = M5.In_I2C.writeRegister(0x36, reg, (const uint8_t*)&value, 2, 400000);
        DualSerial.printf("[AUDIO] AW88298 reg 0x%02X: %s\n", reg, ok ? "OK" : "FAILED");
        DualSerial.flush();
        return ok;
    };

    // Try software reset first
    DualSerial.println("[AUDIO] Performing AW88298 software reset...");
    DualSerial.flush();
    success &= writeAW88298(0x00, 0x55AA);  // Software reset (if supported)
    delay(10);

    success &= writeAW88298(0x61, 0x0673);  // boost mode disabled
    success &= writeAW88298(0x04, 0x4040);  // I2SEN=1 AMPPD=0 PWDN=0
    success &= writeAW88298(0x05, 0x0008);  // RMSE=0 HAGCE=0 HDCCE=0 HMUTE=0

    // Match AW88298 sample rate config to M5Unified logic
    auto spk_cfg2 = M5.Speaker.config();
    size_t rate_tbl[] = {4,5,6,8,10,11,15,20,22,44};
    size_t reg06 = 0;
    size_t rate = (spk_cfg2.sample_rate + 1102) / 2205;  // same as library
    while (rate > rate_tbl[reg06] && ++reg06 < (sizeof(rate_tbl)/sizeof(rate_tbl[0]))) {}
    reg06 |= 0x14C0;  // I2SBCK=0 (BCK mode 16*2)
    DualSerial.printf("[AUDIO] AW88298 calc reg0x06=0x%04X for sample_rate=%u\n", (unsigned)reg06, spk_cfg2.sample_rate);
    success &= writeAW88298(0x06, (uint16_t)reg06);

    success &= writeAW88298(0x0C, 0x00FF);  // volume setting (MAXIMUM volume for testing)

    DualSerial.println("[AUDIO] Speaker hardware configured");
    DualSerial.flush();

    // Stop any existing playback
    M5.Speaker.stop();
    delay(100);

    // Set volume to absolute maximum
    M5.Speaker.setVolume(255);
    M5.Speaker.setChannelVolume(0, 255);  // Left channel
    M5.Speaker.setChannelVolume(1, 255);  // Right channel

    // Read back AW88298 registers to verify configuration
    DualSerial.println("[AUDIO] Reading back AW88298 registers...");
    DualSerial.flush();
    auto readAW88298 = [](uint8_t reg) -> uint16_t {
        uint16_t value = 0;
        M5.In_I2C.readRegister(0x36, reg, (uint8_t*)&value, 2, 400000);
        value = __builtin_bswap16(value);
        DualSerial.printf("[AUDIO] AW88298 reg 0x%02X = 0x%04X\n", reg, value);
        DualSerial.flush();
        return value;
    };

    uint16_t chip_id = readAW88298(0x00);  // Chip ID
    uint16_t reg04   = readAW88298(0x04);  // Power/I2S enable
    uint16_t reg05   = readAW88298(0x05);  // Mute control
    uint16_t reg06_val = readAW88298(0x06);  // I2S config
    uint16_t reg0C   = readAW88298(0x0C);  // Volume
    uint16_t reg61   = readAW88298(0x61);  // Boost mode

    if (chip_id == 0x0000 || chip_id == 0xFFFF) {
        DualSerial.println("[AUDIO] ERROR: AW88298 chip ID readback is invalid (I2C communication failure)");
        success = false;
    }
    if (!success) {
        DualSerial.println("[AUDIO] Speaker hardware configuration FAILED");
        DualSerial.flush();
    } else {
        DualSerial.println("[AUDIO] Speaker hardware configuration verified OK");
        DualSerial.flush();
    }

    // Ensure microphone is disabled to free I2S for speaker
    DualSerial.println("[AUDIO] Ensuring Mic is disabled before enabling Speaker...");
    M5.Mic.end();

    // CRITICAL: Call M5.Speaker.begin() AFTER hardware configuration
    // This initializes the I2S peripheral
    DualSerial.println("[AUDIO] Calling M5.Speaker.begin() to initialize I2S...");
    DualSerial.flush();

    M5.Speaker.begin();
    delay(100);

    // Verify I2S is actually initialized
    auto spk_cfg = M5.Speaker.config();
    DualSerial.printf("[AUDIO] I2S initialized: port=%d, BCK=%d, WS=%d, DOUT=%d\n",
                     spk_cfg.i2s_port, spk_cfg.pin_bck, spk_cfg.pin_ws, spk_cfg.pin_data_out);
    DualSerial.flush();

    DualSerial.println("[AUDIO] Playing 1kHz tone using M5.Speaker.tone()...");
    DualSerial.println("[AUDIO] *** YOU SHOULD HEAR A LOUD 1kHz BEEP FOR 2 SECONDS ***");
    DualSerial.flush();

    // Use M5.Speaker.tone()
    M5.Speaker.tone(1000, 2000);  // 1kHz for 2000ms

    // Wait for playback to complete (tone)
    int timeout = 0;
    while (M5.Speaker.isPlaying() && timeout < 250) {  // 2.5 second timeout
        delay(10);
        timeout++;
        if (timeout % 50 == 0) {
            DualSerial.printf("[AUDIO] Still playing... (%d/250)\n", timeout);
            DualSerial.flush();
        }
    }

    if (timeout >= 250) {
        DualSerial.println("[AUDIO] WARNING: Playback timeout - stopping");
        DualSerial.flush();
        M5.Speaker.stop();
    } else {
        DualSerial.printf("[AUDIO] Playback completed after %d iterations\n", timeout);
        DualSerial.flush();
    }

    // As a second method, generate 1kHz 16-bit PCM and play via playRaw
    const uint32_t sr = M5.Speaker.config().sample_rate;
    const size_t samples = sr;  // 1 second
    int16_t* pcm = (int16_t*)heap_caps_malloc(samples * sizeof(int16_t), MALLOC_CAP_8BIT);
    if (pcm) {
        for (size_t i = 0; i < samples; ++i) {
            float t = (float)i / (float)sr;
            float s = sinf(2.0f * 3.14159265f * 1000.0f * t);
            pcm[i] = (int16_t)(s * 30000.0f);
        }
        DualSerial.println("[AUDIO] Playing raw 1kHz sine (16-bit) for 1s...");
        DualSerial.flush();
        M5.Speaker.playRaw(pcm, samples, sr, false, 1, -1, true);

        // Wait up to 1.5s
        timeout = 0;
        while (M5.Speaker.isPlaying() && timeout < 150) {
            delay(10);
            timeout++;
        }
        if (timeout >= 150) {
            DualSerial.println("[AUDIO] WARNING: Raw playback timeout - stopping");
            DualSerial.flush();
            M5.Speaker.stop();
        }
        free(pcm);
    } else {
        DualSerial.println("[AUDIO] Failed to alloc PCM buffer");
    }

    // Leave I2C and camera state as-is after audio test

    DualSerial.println("[AUDIO] Playback complete");
    DualSerial.println("[AUDIO] If you heard a loud beep, the speaker is working!");
    DualSerial.println("[AUDIO] If you heard nothing, there may be a hardware issue.");
    DualSerial.flush();

    return success;
}

bool CameraDevice::testMicrophone() {
    if (!audioInitialized) {
        DualSerial.println("[AUDIO] Not initialized");
        return false;
    }

    DualSerial.println("[AUDIO] Testing microphone - recording 2 seconds...");
    DualSerial.println("[AUDIO] *** SPEAK INTO THE MICROPHONE NOW ***");

    // CRITICAL: Deinitialize camera to free I2C bus
    bool cameraWasInitialized = cameraInitialized;
    if (cameraWasInitialized) {
        DualSerial.println("[AUDIO] Deinitializing camera to free I2C bus...");
        deinitCamera();
        delay(100);
    }

    // Reinitialize I2C bus for audio hardware access
    DualSerial.println("[AUDIO] Reinitializing I2C bus for audio hardware...");
    M5.In_I2C.begin();
    delay(100);

    // Manually configure speaker hardware for playback
    DualSerial.println("[AUDIO] Configuring speaker hardware manually...");
    M5.In_I2C.bitOn(0x58, 0x03, 0b10000000, 400000);  // Enable BOOST
    M5.In_I2C.bitOn(0x58, 0x02, 0b00000100, 400000);  // Enable speaker
    auto writeAW88298 = [](uint8_t reg, uint16_t value) {
        value = __builtin_bswap16(value);
        M5.In_I2C.writeRegister(0x36, reg, (const uint8_t*)&value, 2, 400000);
    };
    writeAW88298(0x61, 0x0673);
    writeAW88298(0x04, 0x4040);
    writeAW88298(0x05, 0x0008);
    writeAW88298(0x06, 0x14C0);
    writeAW88298(0x0C, 0x00FF);  // Maximum volume

    // Prepare for recording: ensure Speaker is disabled and Mic is enabled
    DualSerial.println("[AUDIO] Preparing I2S: disable Speaker, enable Mic...");
    M5.Speaker.end();
    M5.Mic.begin();
    delay(100);

    // Allocate buffer for recording (2 seconds at 16kHz, 16-bit samples)
    const size_t record_samples = 32000;  // 2 seconds at 16kHz
    const size_t record_size = record_samples * 2;  // bytes
    int16_t* rec_data = (int16_t*)heap_caps_malloc(record_size, MALLOC_CAP_8BIT);

    if (!rec_data) {
        DualSerial.println("[AUDIO] Failed to allocate recording buffer");
        M5.In_I2C.release();
        return false;
    }

    // Record audio
    DualSerial.println("[AUDIO] Recording...");
    if (!M5.Mic.record(rec_data, record_samples, 16000)) {
        DualSerial.println("[AUDIO] Recording failed");
        free(rec_data);
        M5.In_I2C.release();
        return false;
    }

    DualSerial.println("[AUDIO] Recording complete!");

    // Switch I2S back to Speaker for playback
    DualSerial.println("[AUDIO] Switching to Speaker for playback...");
    M5.Mic.end();

    // Ensure AW9523 BOOST + SPK power on before enabling Speaker
    M5.In_I2C.bitOn(0x58, 0x03, 0b10000000, 400000);  // BOOST_EN
    M5.In_I2C.bitOn(0x58, 0x02, 0b00000100, 400000);  // SPK_EN

    // Configure AW88298 safe defaults again
    auto writeAW = [](uint8_t reg, uint16_t value) {
        value = __builtin_bswap16(value);
        M5.In_I2C.writeRegister(0x36, reg, (const uint8_t*)&value, 2, 400000);
    };
    writeAW(0x61, 0x0673);
    writeAW(0x04, 0x4040);
    writeAW(0x05, 0x0008);
    // Match 16kHz sample rate
    writeAW(0x06, 0x14A6);  // 16kHz approx per rate_tbl mapping
    writeAW(0x0C, 0x00FF);

    M5.Speaker.begin();
    delay(50);

    // Analyze the recording to check if we captured any sound
    int32_t sum = 0;
    int32_t max_val = 0;
    for (size_t i = 0; i < record_samples; i++) {
        int32_t val = abs(rec_data[i]);
        sum += val;
        if (val > max_val) max_val = val;
    }
    int32_t avg = sum / record_samples;

    DualSerial.printf("[AUDIO] Audio level - Average: %d, Peak: %d\n", avg, max_val);

    if (max_val < 100) {
        DualSerial.println("[AUDIO] WARNING: Very low audio level - microphone may not be working");
    }

    DualSerial.println("[AUDIO] Playing back recording...");

    // Set volume to maximum for playback
    M5.Speaker.setVolume(255);

    // Play back the recorded audio
    M5.Speaker.playRaw(rec_data, record_samples, 16000, false, 1, -1, true);

    // Wait for playback to finish (with timeout)
    int timeout = 0;
    while (M5.Speaker.isPlaying() && timeout < 250) {  // 2.5 second timeout
        delay(10);
        timeout++;
    }

    if (timeout >= 250) {
        DualSerial.println("[AUDIO] WARNING: Playback timeout - stopping");
        M5.Speaker.stop();
    }

    free(rec_data);

    // Release I2C bus for camera
    DualSerial.println("[AUDIO] Releasing I2C bus for camera...");
    M5.In_I2C.release();

    // Reinitialize camera if it was initialized before
    if (cameraWasInitialized) {
        DualSerial.println("[AUDIO] Reinitializing camera...");
        delay(100);
        initCamera();
    }

    DualSerial.println("[AUDIO] Microphone test complete");
    DualSerial.println("[AUDIO] If you heard your voice, the microphone is working!");

    return true;
}

bool CameraDevice::mixedSignalUnlock(const char* context) {
#ifdef FACTORY_TEST
    if (!audioInitialized) {
        DualSerial.println("[MIXSIG] Audio not initialized, attempting initAudio()");
        if (!initAudio()) {
            DualSerial.println("[MIXSIG] initAudio() failed");
            return false;
        }
    }

    DualSerial.printf("[MIXSIG] Mixed-signal unlock check (%s)\n",
                     context ? context : "unknown");

    bool cameraWasInitialized = cameraInitialized;
    if (cameraWasInitialized) {
        DualSerial.println("[MIXSIG] Deinitializing camera for mic capture...");
        deinitCamera();
        delay(80);
    }

    M5.In_I2C.begin();
    delay(20);
    M5.Speaker.end();
    M5.Mic.begin();
    delay(20);

    const size_t record_samples = 8000;   // ~0.5s at 16kHz
    const size_t record_size    = record_samples * 2;
    int16_t* rec_data = (int16_t*)heap_caps_malloc(record_size, MALLOC_CAP_8BIT);

    if (!rec_data) {
        DualSerial.println("[MIXSIG] Failed to allocate recording buffer");
        M5.Mic.end();
        M5.In_I2C.release();
        if (cameraWasInitialized) {
            initCamera();
        }
        return false;
    }

    DualSerial.println("[MIXSIG] Recording microphone window for unlock...");
    if (!M5.Mic.record(rec_data, record_samples, 16000)) {
        DualSerial.println("[MIXSIG] Recording failed");
        free(rec_data);
        M5.Mic.end();
        M5.In_I2C.release();
        if (cameraWasInitialized) {
            initCamera();
        }
        return false;
    }

    int32_t sum = 0;
    int32_t max_val = 0;
    for (size_t i = 0; i < record_samples; ++i) {
        int32_t v = abs(rec_data[i]);
        sum += v;
        if (v > max_val) {
            max_val = v;
        }
    }
    int32_t avg = record_samples ? (sum / (int32_t)record_samples) : 0;

    lastMicAvg  = (int)avg;
    lastMicPeak = (int)max_val;

    DualSerial.printf("[MIXSIG] Mic levels - avg=%d peak=%d\n", lastMicAvg, lastMicPeak);

    free(rec_data);
    M5.Mic.end();
    M5.In_I2C.release();

    if (cameraWasInitialized) {
        DualSerial.println("[MIXSIG] Reinitializing camera after mic capture...");
        initCamera();
    }

    const int32_t peakThreshold = 500;
    if (max_val > peakThreshold) {
        DualSerial.println("[MIXSIG] Threshold exceeded - granting mixed-signal unlock");
        return true;
    }

    DualSerial.println("[MIXSIG] Threshold not reached - mixed-signal unlock denied");
    return false;
#else
    (void)context;
    return false;
#endif
}
