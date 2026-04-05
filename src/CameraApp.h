/**
 * @file CameraApp.h
 * @brief Camera Application with PIN lock and web streaming
 */

#ifndef CAMERA_APP_H
#define CAMERA_APP_H

#include <Arduino.h>
#include "lvgl.h"
#include "esp_camera.h"

// Color scheme - Green theme
#define COLOR_BG        lv_color_hex(0x1a1a1a)
#define COLOR_PRIMARY   lv_color_hex(0x00ff88)
#define COLOR_SECONDARY lv_color_hex(0x2a2a2a)
#define COLOR_TEXT      lv_color_hex(0xffffff)
#define COLOR_TEXT_DIM  lv_color_hex(0x888888)
#define COLOR_DANGER    lv_color_hex(0xff4444)

// App states
enum AppState {
    STATE_SETUP_MODE,      // Initial setup - show AP info
    STATE_PIN_ENTRY,       // After WiFi configured - require PIN
    STATE_CAMERA_VIEW,     // After PIN unlock - show camera
    STATE_ADMIN_PIN_ENTRY, // Admin PIN entry
    STATE_ADMIN_MODE,      // Admin features
    STATE_SETTINGS,        // Settings screen
    STATE_SELF_TEST        // Self-test mode
};

class CameraApp {
public:
    static CameraApp& getInstance();
    
    bool init();
    void loop();
    
    // Camera functions
    bool initCamera();
    void deinitCamera();
    camera_fb_t* captureFrame();
    void releaseFrame(camera_fb_t* fb);
    bool isCameraInitialized() { return cameraInitialized; }
    
    // PIN functions
    bool checkUserPIN(const String& pin);
    bool checkAdminPIN(const String& pin);
    String getUserPIN() { return userPIN; }
    String getAdminPIN() { return adminPIN; }
    bool isUnlocked() { return unlocked; }
    bool isAdmin() { return adminUnlocked; }
    void lock();
    void lockAdmin() { adminUnlocked = false; }

    // State management
    AppState getState() { return currentState; }
    void setState(AppState state);

    // Admin UI helpers
    void showAdminMessage(const String& msg);

    // LED control
    void updateLED();

    // WiFi info
    String getAPSSID() { return apSSID; }
    String getAPIP();
    bool hasWiFiConfig() { return wifiConfigured; }
    void setWiFiConfigured(bool configured) { wifiConfigured = configured; }
    
private:
    CameraApp();
    ~CameraApp();
    CameraApp(const CameraApp&) = delete;
    CameraApp& operator=(const CameraApp&) = delete;

    void createSetupScreen();
    void createPINScreen();
    void createCameraScreen();
    void createAdminPINScreen();
    void createAdminScreen();
    void createSettingsScreen();
    void createSelfTestScreen();
    void updateCameraPreview();
    void runSelfTest();

    bool cameraInitialized;
    bool unlocked;
    bool adminUnlocked;
    bool wifiConfigured;
    AppState currentState;

    String userPIN;
    String adminPIN;
    String apSSID;

    // LVGL objects
    lv_obj_t* screen_setup;
    lv_obj_t* screen_pin;
    lv_obj_t* screen_camera;
    lv_obj_t* screen_admin_pin;
    lv_obj_t* screen_admin;
    lv_obj_t* screen_settings;
    lv_obj_t* screen_selftest;
    lv_obj_t* pin_label;
    lv_obj_t* admin_pin_label;
    lv_obj_t* status_label;
    lv_obj_t* camera_img;
    lv_obj_t* info_label;
    lv_obj_t* selftest_label;
    lv_obj_t* admin_msg_label;
};

// Global functions for LVGL callbacks
void CameraApp_Init();
void CameraApp_Loop();

#endif // CAMERA_APP_H

