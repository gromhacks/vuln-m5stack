/**
 * @file CameraDevice_Camera.cpp
 * @brief Camera hardware init, frame capture, snapshot storage, and frame buffers
 *
 * The CoreS3 uses a GC0308 CMOS sensor connected via parallel DVP interface.
 * It only supports RGB565 output (no hardware JPEG), so all JPEG conversion
 * is done in software via fmt2jpg(). Frame buffers live in PSRAM (8MB available).
 *
 * The debug frame buffer (g_frameBuf) is a separate large allocation used by
 * the /camera/debug-frame endpoint to expose raw pixel data for diagnostics.
 */

#include "CameraDevice.h"
#include "CameraDevice_Internal.h"
#include <M5Unified.h>
#include "esp_camera.h"
#include "DualSerial.h"
#include "img_converters.h"

// ---------------------------------------------------------------------------
// Camera hardware configuration (CoreS3 GC0308)
// Pin mapping matches M5Stack CoreS3 schematic (Sch_M5_CoreS3_v1.0)
// ---------------------------------------------------------------------------

static camera_config_t camera_config = {
    .pin_pwdn     = -1,
    .pin_reset    = -1,
    .pin_xclk     = 2,
    .pin_sscb_sda = 12,
    .pin_sscb_scl = 11,

    .pin_d7 = 47,
    .pin_d6 = 48,
    .pin_d5 = 16,
    .pin_d4 = 15,
    .pin_d3 = 42,
    .pin_d2 = 41,
    .pin_d1 = 40,
    .pin_d0 = 39,

    .pin_vsync = 46,
    .pin_href  = 38,
    .pin_pclk  = 45,

    .xclk_freq_hz = 20000000,
    .ledc_timer   = LEDC_TIMER_0,
    .ledc_channel = LEDC_CHANNEL_0,

    .pixel_format = PIXFORMAT_RGB565,  // GC0308 only supports RGB565, not JPEG
    .frame_size   = FRAMESIZE_QVGA,    // 320x240 for web, will scale for display
    .jpeg_quality = 0,
    .fb_count     = 2,                 // Double buffering
    .fb_location  = CAMERA_FB_IN_PSRAM,  // Use PSRAM (CoreS3 has 8MB)
    .grab_mode    = CAMERA_GRAB_WHEN_EMPTY,
};

// ---------------------------------------------------------------------------
// Debug frame buffer
//
// Allocated on first use for the /camera/debug-frame endpoint. The full
// buffer (VGA, 640x480 RGB565) is filled with pattern 0xAA, then the
// preview region (QVGA, 320x240) is overwritten with 0xBB. This means
// bytes beyond the preview offset still contain the 0xAA fill - or stale
// data from a previous allocation - which the endpoint exposes.
// ---------------------------------------------------------------------------

uint8_t* g_frameBuf = nullptr;
size_t   g_frameBufSize = 0;
bool     g_frameBufFilled = false;
const size_t FRAME_FULL_SIZE = 640 * 480 * 2;     // 614,400 bytes (VGA RGB565)
const size_t FRAME_PREVIEW_SIZE = 320 * 240 * 2;  // 153,600 bytes (QVGA RGB565)

bool framebuf_init_full() {
    if (!g_frameBuf) {
        g_frameBuf = (uint8_t*)malloc(FRAME_FULL_SIZE);
        if (!g_frameBuf) {
            DualSerial.println("[CAMBUF] allocation failed");
            return false;
        }
        g_frameBufSize = FRAME_FULL_SIZE;
    }
    memset(g_frameBuf, 0xAA, FRAME_FULL_SIZE);
    g_frameBufFilled = true;
    return true;
}

bool framebuf_prepare_preview() {
    if (!g_frameBufFilled) {
        if (!framebuf_init_full()) {
            return false;
        }
    }
    size_t limit = FRAME_PREVIEW_SIZE;
    if (limit > g_frameBufSize) {
        limit = g_frameBufSize;
    }
    memset(g_frameBuf, 0xBB, limit);
    return true;
}

// Single-call helper used by the debug HTTP endpoint.
bool framebuf_capture_debug() {
    if (!framebuf_init_full()) {
        return false;
    }
    return framebuf_prepare_preview();
}

// ---------------------------------------------------------------------------
// Camera init / deinit / capture / release
// ---------------------------------------------------------------------------

bool CameraDevice::initCamera() {
    if (cameraInitialized) {
        return true;
    }

    DualSerial.println("  - Initializing camera hardware...");

    // Try to deinitialize first in case it's in a bad state
    DualSerial.println("  - Deinitializing any existing camera...");
    esp_camera_deinit();

    // I2C should already be released in main.cpp before this is called
    delay(200);  // Give hardware time to stabilize after deinit

    DualSerial.println("  - Calling esp_camera_init...");
    esp_err_t err = esp_camera_init(&camera_config);
    if (err != ESP_OK) {
        DualSerial.printf("  - Camera init failed with error 0x%x\n", err);

        // Try one more time with single buffer
        DualSerial.println("  - Retrying with single buffer...");
        camera_config.fb_count = 1;

        delay(100);
        err = esp_camera_init(&camera_config);
        if (err != ESP_OK) {
            DualSerial.printf("  - Camera init retry failed with error 0x%x\n", err);
            return false;
        }
    }

    cameraInitialized = true;
    DualSerial.println("  - Camera initialized successfully!");
    return true;
}

void CameraDevice::deinitCamera() {
    if (cameraInitialized) {
        esp_camera_deinit();
        cameraInitialized = false;
    }
}

camera_fb_t* CameraDevice::captureFrame() {
    if (!cameraInitialized) {
        return nullptr;
    }
    return esp_camera_fb_get();
}

void CameraDevice::releaseFrame(camera_fb_t* fb) {
    if (fb) {
        esp_camera_fb_return(fb);
    }
}

// ---------------------------------------------------------------------------
// Snapshot helpers
// ---------------------------------------------------------------------------

bool CameraDevice::takeSnapshot() {
    // Take mutex with timeout
    if (xSemaphoreTake(cameraMutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        DualSerial.println("[SNAPSHOT] Failed to acquire camera mutex");
        return false;
    }

    camera_fb_t* fb = captureFrame();
    if (!fb) {
        xSemaphoreGive(cameraMutex);
        DualSerial.println("[SNAPSHOT] Frame capture failed");
        return false;
    }

    // Convert RGB565 to JPEG
    uint8_t* jpg_buf = NULL;
    size_t jpg_len = 0;

    bool success = fmt2jpg(fb->buf, fb->len, fb->width, fb->height, fb->format, 90, &jpg_buf, &jpg_len);

    releaseFrame(fb);
    xSemaphoreGive(cameraMutex);

    if (!success) {
        DualSerial.println("[SNAPSHOT] JPEG conversion failed");
        return false;
    }

    // Store the snapshot (free old one first)
    clearSnapshot();
    lastSnapshotBuf = jpg_buf;
    lastSnapshotLen = jpg_len;
    lastSnapshotMillis = millis();
    snapshotCount++;

    DualSerial.printf("[SNAPSHOT] Snapshot #%d captured and stored (%d bytes)\n",
                     snapshotCount, jpg_len);

    return true;
}

bool CameraDevice::getLastSnapshot(uint8_t** jpg_buf, size_t* jpg_len) {
    if (!lastSnapshotBuf || lastSnapshotLen == 0) {
        return false;
    }

    *jpg_buf = lastSnapshotBuf;
    *jpg_len = lastSnapshotLen;
    return true;
}

void CameraDevice::clearSnapshot() {
    if (lastSnapshotBuf) {
        free(lastSnapshotBuf);
        lastSnapshotBuf = nullptr;
        lastSnapshotLen = 0;
    }
}
