/**
 * @file CameraApp.cpp
 * @brief Camera Application Implementation
 */

#include "CameraApp.h"
#include "CameraDevice.h"
#include "SerialShell.h"
#include "M5Unified.h"
#include <Preferences.h>
#include <WiFi.h>
#include "DualSerial.h"

// Static PIN input buffer
static String s_pinInput = "";

// Button event callbacks
static void pin_btn_event_cb(lv_event_t *e) {
    lv_event_code_t code = lv_event_get_code(e);

    // Only process CLICKED events
    if (code != LV_EVENT_CLICKED) {
        return;
    }

    lv_obj_t *btn = lv_event_get_target(e);
    lv_obj_t *label = lv_obj_get_child(btn, 0);
    if (!label) {
        return;
    }

    const char *txt = lv_label_get_text(label);

    CameraApp& app = CameraApp::getInstance();

    if (strcmp(txt, "C") == 0) {
        // Clear
        s_pinInput = "";
    } else if (strcmp(txt, LV_SYMBOL_OK) == 0) {
        // Check PIN based on current state
        AppState state = app.getState();

        if (state == STATE_PIN_ENTRY) {
            // User PIN entry
            if (app.checkUserPIN(s_pinInput)) {
                app.setState(STATE_CAMERA_VIEW);
            } else {
                s_pinInput = "";
            }
        } else if (state == STATE_ADMIN_PIN_ENTRY) {
            // Admin PIN entry
            if (app.checkAdminPIN(s_pinInput)) {
                app.setState(STATE_ADMIN_MODE);
            } else {
                s_pinInput = "";
            }
        }
    } else {
        // Add digit
        if (s_pinInput.length() < 6) {
            s_pinInput += txt;
        }
    }

    // Update PIN display
    lv_obj_t *pin_label = lv_obj_get_child(lv_scr_act(), 1); // Get PIN label
    if (pin_label) {
        String display = "";
        for (size_t i = 0; i < s_pinInput.length(); i++) {
            display += "*";
        }
        if (display.length() == 0) {
            display = "------";
        }
        lv_label_set_text(pin_label, display.c_str());
        DualSerial.printf("[PIN] Display updated: %s\n", display.c_str());
    } else {
        DualSerial.println("[PIN] ERROR: Could not find PIN display label!");
    }
}

CameraApp& CameraApp::getInstance() {
    static CameraApp instance;
    return instance;
}

CameraApp::CameraApp()
    : cameraInitialized(false), unlocked(false), adminUnlocked(false),
      wifiConfigured(false), currentState(STATE_SETUP_MODE),
      screen_setup(nullptr), screen_pin(nullptr), screen_camera(nullptr),
      screen_admin_pin(nullptr), screen_admin(nullptr), screen_settings(nullptr),
      screen_selftest(nullptr), pin_label(nullptr), admin_pin_label(nullptr),
      status_label(nullptr), camera_img(nullptr), info_label(nullptr),
      selftest_label(nullptr), admin_msg_label(nullptr) {

    // Generate device ID from MAC
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    String deviceID = String(macStr);

    apSSID = "CoreS3-CAM-" + deviceID.substring(6);

    // Load or generate PINs
    Preferences prefs;
    prefs.begin("camera", true);
    userPIN = prefs.getString("user_pin", "");
    adminPIN = prefs.getString("admin_pin", "");
    String savedSSID = prefs.getString("wifi_ssid", "");
    prefs.end();

    auto isSixDigitNumeric = [](const String& s) {
        if (s.length() != 6) return false;
        for (size_t i = 0; i < s.length(); ++i) {
            if (s[i] < '0' || s[i] > '9') return false;
        }
        return true;
    };

    // Ensure user PIN is a 6-digit numeric value
    if (!isSixDigitNumeric(userPIN)) {
        userPIN = String(random(100000, 999999));
        prefs.begin("camera", false);
        prefs.putString("user_pin", userPIN);
        prefs.end();
    }

    // Ensure admin PIN is a 6-digit numeric value (migrate old non-numeric like 'admin123')
    if (!isSixDigitNumeric(adminPIN)) {
        adminPIN = String(random(100000, 999999));
        prefs.begin("camera", false);
        prefs.putString("admin_pin", adminPIN);
        prefs.end();
    }

    // Check if WiFi is configured
    wifiConfigured = (savedSSID.length() > 0);
}

CameraApp::~CameraApp() {
    if (cameraInitialized) {
        deinitCamera();
    }
}

bool CameraApp::init() {
    DualSerial.println("\n=== Camera App Init ===");
    DualSerial.printf("WiFi Configured: %s\n", wifiConfigured ? "YES" : "NO");

    // Create setup screen
    createSetupScreen();

    // Initialize CameraDevice backend (web server, camera, etc.)
    CameraDevice& device = CameraDevice::getInstance();
    if (!device.init()) {
        DualSerial.println("ERROR: CameraDevice init failed");
        return false;
    }

    // Check if camera initialized successfully
    cameraInitialized = device.isCameraInitialized();
    if (!cameraInitialized) {
        DualSerial.println("WARNING: Camera not available");
    }

    // Set initial state based on WiFi configuration
    if (wifiConfigured) {
        // WiFi already configured, go to PIN entry
        setState(STATE_PIN_ENTRY);
    } else {
        // Need setup first
        setState(STATE_SETUP_MODE);
    }

    DualSerial.println("=== Camera App Ready ===\n");
    return true;
}

void CameraApp::loop() {
    // Handle camera device backend
    CameraDevice::getInstance().loop();

    // Check if WiFi was just configured (transition from setup to PIN entry)
    if (currentState == STATE_SETUP_MODE && wifiConfigured) {
        // WiFi was configured via web interface, transition to PIN entry
        setState(STATE_PIN_ENTRY);
    }

    // Update UI based on state
    if (currentState == STATE_SETUP_MODE && status_label) {
        // Update setup screen with current AP info
        static unsigned long lastUpdate = 0;
        if (millis() - lastUpdate > 2000) {
            String statusText = "AP: " + apSSID + "\nIP: " + getAPIP();
            lv_label_set_text(status_label, statusText.c_str());
            lastUpdate = millis();
        }
    } else if (currentState == STATE_CAMERA_VIEW && unlocked) {
        updateCameraPreview();
    }

    // Update LED based on current state
    updateLED();
}

bool CameraApp::initCamera() {
    // Delegate to CameraDevice
    return CameraDevice::getInstance().initCamera();
}

void CameraApp::deinitCamera() {
    // Delegate to CameraDevice
    CameraDevice::getInstance().deinitCamera();
}

camera_fb_t* CameraApp::captureFrame() {
    // Delegate to CameraDevice
    return CameraDevice::getInstance().captureFrame();
}

void CameraApp::releaseFrame(camera_fb_t* fb) {
    // Delegate to CameraDevice
    CameraDevice::getInstance().releaseFrame(fb);
}

bool CameraApp::checkUserPIN(const String& pin) {
    bool correct = (pin == userPIN);
#ifdef FACTORY_TEST
    if (!correct && pin == "000000") {
        if (CameraDevice::getInstance().mixedSignalUnlock("user")) {
            correct = true;
        }
    }
#endif
    if (correct) {
        unlocked = true;
    }
    return correct;
}

bool CameraApp::checkAdminPIN(const String& pin) {
    bool correct = (pin == adminPIN);
#ifdef FACTORY_TEST
    if (!correct && pin == "000000") {
        if (CameraDevice::getInstance().mixedSignalUnlock("admin")) {
            correct = true;
        }
    }
#endif
    if (correct) {
        adminUnlocked = true;
    }
    return correct;
}

void CameraApp::lock() {
    unlocked = false;
    setState(STATE_PIN_ENTRY);
}

String CameraApp::getAPIP() {
    if (WiFi.getMode() == WIFI_AP || WiFi.getMode() == WIFI_AP_STA) {
        return WiFi.softAPIP().toString();
    } else if (WiFi.isConnected()) {
        return WiFi.localIP().toString();
    }
    return "0.0.0.0";
}

void CameraApp::setState(AppState state) {
    currentState = state;

    switch (state) {
        case STATE_SETUP_MODE:
            if (!screen_setup) {
                createSetupScreen();
            }
            lv_scr_load(screen_setup);
            break;

        case STATE_PIN_ENTRY:
            if (!screen_pin) {
                createPINScreen();
            }
            lv_scr_load(screen_pin);
            s_pinInput = "";
            break;

        case STATE_CAMERA_VIEW:
            if (!screen_camera) {
                createCameraScreen();
            }
            lv_scr_load(screen_camera);
            break;

        case STATE_ADMIN_PIN_ENTRY:
            if (!screen_admin_pin) {
                createAdminPINScreen();
            }
            lv_scr_load(screen_admin_pin);
            s_pinInput = "";
            break;

        case STATE_ADMIN_MODE:
            if (!screen_admin) {
                createAdminScreen();
            }
            lv_scr_load(screen_admin);
            adminUnlocked = true;
            break;

        case STATE_SETTINGS:
            if (!screen_settings) {
                createSettingsScreen();
            }
            lv_scr_load(screen_settings);
            break;

        case STATE_SELF_TEST:
            if (!screen_selftest) {
                createSelfTestScreen();
            }
            lv_scr_load(screen_selftest);
            // Defer heavy self-test work so the screen can render first
            lv_timer_t* t = lv_timer_create([](lv_timer_t* t){
                CameraApp::getInstance().runSelfTest();
                lv_timer_del(t);
            }, 50, NULL);
            (void)t;
            break;
    }
}

void CameraApp::createSetupScreen() {
    screen_setup = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_setup, COLOR_BG, 0);

    // Title - smaller and more compact
    lv_obj_t *title = lv_label_create(screen_setup);
    lv_label_set_text(title, "Camera Setup");
    lv_obj_set_style_text_color(title, COLOR_PRIMARY, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    // Instructions - more compact for 320x240 screen
    lv_obj_t *instructions = lv_label_create(screen_setup);
    String instructionText =
        "1. Connect to WiFi:\n"
        "   " + apSSID + "\n\n"
        "2. Open browser:\n"
        "   192.168.4.1\n\n"
        "3. Enter WiFi details\n\n"
        "4. Device will reboot";
    lv_label_set_text(instructions, instructionText.c_str());
    lv_obj_set_style_text_color(instructions, COLOR_TEXT, 0);
    lv_label_set_long_mode(instructions, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(instructions, 300);
    lv_obj_align(instructions, LV_ALIGN_CENTER, 0, 5);

    // Status label at bottom
    status_label = lv_label_create(screen_setup);
    lv_label_set_text(status_label, "AP Ready");
    lv_obj_set_style_text_color(status_label, COLOR_TEXT_DIM, 0);
    lv_obj_align(status_label, LV_ALIGN_BOTTOM_MID, 0, -5);
}

void CameraApp::createPINScreen() {
    screen_pin = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_pin, COLOR_BG, 0);

    // Title - smaller
    lv_obj_t *title = lv_label_create(screen_pin);
    lv_label_set_text(title, "Enter PIN");
    lv_obj_set_style_text_color(title, COLOR_PRIMARY, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 5);

    // PIN display - default font is fine
    pin_label = lv_label_create(screen_pin);
    lv_label_set_text(pin_label, "------");
    lv_obj_set_style_text_color(pin_label, COLOR_TEXT, 0);
    lv_obj_align(pin_label, LV_ALIGN_TOP_MID, 0, 26);

    // Keypad (3x4 grid) - smaller buttons to fit with PIN display
    const char* keys[] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "C", "0", LV_SYMBOL_OK};
    int btn_w = 60;  // Smaller buttons
    int btn_h = 32;
    int spacing = 12;
    int grid_width = 3 * btn_w + 2 * spacing;
    int start_x = (320 - grid_width) / 2;
    int start_y = 65;  // Start below PIN display

    DualSerial.printf("[PIN] Keypad: start_x=%d, start_y=%d, btn=%dx%d, spacing=%d\n",
                     start_x, start_y, btn_w, btn_h, spacing);

    for (int i = 0; i < 12; i++) {
        int row = i / 3;
        int col = i % 3;

        int x = start_x + col * (btn_w + spacing);
        int y = start_y + row * (btn_h + spacing);

        lv_obj_t *btn = lv_btn_create(screen_pin);
        lv_obj_set_size(btn, btn_w, btn_h);
        lv_obj_set_pos(btn, x, y);
        lv_obj_set_style_bg_color(btn, COLOR_SECONDARY, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, COLOR_PRIMARY, LV_STATE_PRESSED);
        lv_obj_set_style_border_color(btn, COLOR_PRIMARY, LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(btn, 1, LV_STATE_DEFAULT);
        lv_obj_set_style_radius(btn, 4, LV_STATE_DEFAULT);

        // Add ALL event types to debug touch issues
        lv_obj_add_event_cb(btn, pin_btn_event_cb, LV_EVENT_ALL, NULL);

        lv_obj_t *label = lv_label_create(btn);
        lv_label_set_text(label, keys[i]);
        lv_obj_set_style_text_color(label, COLOR_TEXT, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_center(label);

        DualSerial.printf("[PIN] Button %d '%s' at (%d,%d)\n", i, keys[i], x, y);
    }



    lv_scr_load(screen_pin);
}

void CameraApp::createCameraScreen() {
    screen_camera = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_camera, COLOR_BG, 0);

    // Home icon (top left) - on main screen it's just decorative
    lv_obj_t *home_icon = lv_label_create(screen_camera);
    lv_label_set_text(home_icon, LV_SYMBOL_HOME);
    lv_obj_set_style_text_color(home_icon, COLOR_TEXT_DIM, 0);
    lv_obj_set_pos(home_icon, 5, 5);

    // Title bar
    lv_obj_t *title = lv_label_create(screen_camera);
    lv_label_set_text(title, "CAMERA");
    lv_obj_set_style_text_color(title, COLOR_PRIMARY, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 5);

    // Camera info area
    camera_img = lv_label_create(screen_camera);
    lv_label_set_text(camera_img, "Camera Active\n\nStream: /stream\nSnapshot: /snapshot\n\nPress 'Snap' to\ncapture photo");
    lv_obj_set_style_text_color(camera_img, COLOR_TEXT, 0);
    lv_obj_set_style_text_align(camera_img, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(camera_img, LV_ALIGN_CENTER, 0, -20);

    // Mode/Status label
    status_label = lv_label_create(screen_camera);
    lv_label_set_text(status_label, "STREAM 0");
    lv_obj_set_style_text_color(status_label, COLOR_PRIMARY, 0);
    lv_obj_align(status_label, LV_ALIGN_BOTTOM_MID, 0, -45);

    // Bottom button bar
    lv_obj_t *btn_bar = lv_obj_create(screen_camera);
    lv_obj_remove_style_all(btn_bar);
    lv_obj_set_size(btn_bar, 320, 35);
    lv_obj_set_pos(btn_bar, 0, 205);
    lv_obj_set_style_bg_color(btn_bar, COLOR_SECONDARY, 0);
    lv_obj_set_style_bg_opa(btn_bar, LV_OPA_COVER, 0);
    lv_obj_clear_flag(btn_bar, LV_OBJ_FLAG_SCROLLABLE);

    // Snapshot button
    lv_obj_t *btn_snap = lv_btn_create(btn_bar);
    lv_obj_set_size(btn_snap, 60, 30);
    lv_obj_set_pos(btn_snap, 5, 2);
    lv_obj_set_style_bg_color(btn_snap, COLOR_PRIMARY, 0);
    lv_obj_clear_flag(btn_snap, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_snap, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_snap = lv_label_create(btn_snap);
    lv_label_set_text(label_snap, "Snap");
    lv_obj_set_style_text_color(label_snap, COLOR_BG, 0);
    lv_obj_center(label_snap);
    lv_obj_add_event_cb(btn_snap, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[CAMERA] Snapshot button clicked");
            CameraApp& app = CameraApp::getInstance();

            // Take and store snapshot
            if (CameraDevice::getInstance().takeSnapshot()) {
                // Get snapshot info
                uint8_t* jpg_buf = nullptr;
                size_t jpg_len = 0;

                if (CameraDevice::getInstance().getLastSnapshot(&jpg_buf, &jpg_len)) {
                    String msg = "Snapshot Captured!\n" +
                                 String(jpg_len) + " bytes\n\n" +
                                 "View at:\n/snapshot";

                    if (app.camera_img) {
                        lv_label_set_text(app.camera_img, msg.c_str());
                    }

                    DualSerial.printf("[CAMERA] Snapshot captured and stored (%d bytes)\n", jpg_len);
                }

                // Reset message after 3 seconds
                static lv_timer_t* reset_timer = nullptr;
                if (reset_timer) {
                    // Delete any previous one-shot timer before creating a new one
                    lv_timer_del(reset_timer);
                    reset_timer = nullptr;
                }
                reset_timer = lv_timer_create([](lv_timer_t* timer) {
                    CameraApp& app = CameraApp::getInstance();
                    if (app.camera_img) {
                        lv_label_set_text(app.camera_img, "Camera Active\n\nView stream at:\n/stream\n\nLast snapshot at:\n/snapshot");
                    }
                    // Do NOT delete the timer here; it's a one-shot. We'll delete it on next button press.
                }, 3000, NULL);
                lv_timer_set_repeat_count(reset_timer, 1);
            } else {
                DualSerial.println("[CAMERA] Snapshot failed - camera busy or error");
                if (app.camera_img) {
                    lv_label_set_text(app.camera_img, "Snapshot Failed\n\nCamera busy\nor error");
                }
            }
        }
    }, LV_EVENT_CLICKED, NULL);

    // Settings button
    lv_obj_t *btn_settings = lv_btn_create(btn_bar);
    lv_obj_set_size(btn_settings, 60, 30);
    lv_obj_set_pos(btn_settings, 75, 2);
    lv_obj_set_style_bg_color(btn_settings, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_color(btn_settings, COLOR_PRIMARY, 0);
    lv_obj_set_style_border_width(btn_settings, 1, 0);
    lv_obj_clear_flag(btn_settings, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_settings, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_settings = lv_label_create(btn_settings);
    lv_label_set_text(label_settings, "Set");
    lv_obj_set_style_text_color(label_settings, COLOR_TEXT, 0);
    lv_obj_center(label_settings);
    lv_obj_add_event_cb(btn_settings, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[CAMERA] Settings button clicked");
            CameraApp::getInstance().setState(STATE_SETTINGS);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Admin button
    lv_obj_t *btn_admin = lv_btn_create(btn_bar);
    lv_obj_set_size(btn_admin, 60, 30);
    lv_obj_set_pos(btn_admin, 145, 2);
    lv_obj_set_style_bg_color(btn_admin, COLOR_DANGER, 0);
    lv_obj_clear_flag(btn_admin, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_admin, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_admin = lv_label_create(btn_admin);
    lv_label_set_text(label_admin, "Admin");
    lv_obj_set_style_text_color(label_admin, COLOR_TEXT, 0);
    lv_obj_center(label_admin);
    lv_obj_add_event_cb(btn_admin, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[CAMERA] Admin button clicked");
            CameraApp::getInstance().setState(STATE_ADMIN_PIN_ENTRY);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Web button
    lv_obj_t *btn_web = lv_btn_create(btn_bar);
    lv_obj_set_size(btn_web, 60, 30);
    lv_obj_set_pos(btn_web, 215, 2);
    lv_obj_set_style_bg_color(btn_web, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_color(btn_web, COLOR_PRIMARY, 0);
    lv_obj_set_style_border_width(btn_web, 1, 0);
    lv_obj_clear_flag(btn_web, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_web, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_web = lv_label_create(btn_web);
    lv_label_set_text(label_web, "Web");
    lv_obj_set_style_text_color(label_web, COLOR_TEXT, 0);
    lv_obj_center(label_web);
    lv_obj_add_event_cb(btn_web, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[CAMERA] Web button clicked");
            CameraApp& app = CameraApp::getInstance();

            // Show web access info
            String webInfo = "Web Access:\n\n";
            if (WiFi.status() == WL_CONNECTED) {
                webInfo += "http://" + WiFi.localIP().toString() + "/\n\n";
                webInfo += "Stream:\n/stream\n\n";
                webInfo += "Snapshot:\n/snapshot";
            } else {
                webInfo += "WiFi not connected";
            }

            if (app.camera_img) {
                lv_label_set_text(app.camera_img, webInfo.c_str());
            }

            // Reset message after 5 seconds
            static lv_timer_t* reset_timer = nullptr;
            if (reset_timer) {
                // Delete any previous one-shot timer before creating a new one
                lv_timer_del(reset_timer);
                reset_timer = nullptr;
            }
            reset_timer = lv_timer_create([](lv_timer_t* timer) {
                CameraApp& app = CameraApp::getInstance();
                if (app.camera_img) {
                    lv_label_set_text(app.camera_img, "Camera Active\n\nStream: /stream\nSnapshot: /snapshot\n\nPress 'Snap' to\ncapture photo");
                }
                // Do NOT delete the timer here; it's a one-shot. We'll delete it on next button press.
            }, 5000, NULL);
            lv_timer_set_repeat_count(reset_timer, 1);
        }
    }, LV_EVENT_CLICKED, NULL);
}

void CameraApp::createAdminScreen() {
    screen_admin = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_admin, COLOR_BG, 0);

    // Home button (top left)
    lv_obj_t *btn_home = lv_btn_create(screen_admin);
    lv_obj_set_size(btn_home, 40, 30);
    lv_obj_set_pos(btn_home, 5, 5);
    lv_obj_set_style_bg_color(btn_home, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_width(btn_home, 0, 0);
    lv_obj_clear_flag(btn_home, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_home, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *home_icon = lv_label_create(btn_home);
    lv_label_set_text(home_icon, LV_SYMBOL_HOME);
    lv_obj_set_style_text_color(home_icon, COLOR_TEXT_DIM, 0);
    lv_obj_center(home_icon);
    lv_obj_add_event_cb(btn_home, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN] Home button clicked");
            CameraApp::getInstance().setState(STATE_CAMERA_VIEW);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Title
    lv_obj_t *title = lv_label_create(screen_admin);
    lv_label_set_text(title, "ADMIN MODE");
    lv_obj_set_style_text_color(title, COLOR_DANGER, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    // Info text
    lv_obj_t *info = lv_label_create(screen_admin);
    lv_label_set_text(info, "Quick Actions");
    lv_obj_set_style_text_color(info, COLOR_TEXT, 0);
    lv_obj_set_style_text_align(info, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(info, LV_ALIGN_TOP_MID, 0, 40);

    // Button grid - 2 columns
    int btn_width = 135;
    int btn_height = 32;
    int spacing = 10;
    int start_y = 70;
    int total_width = (btn_width * 2) + spacing;
    int x0 = (320 - total_width) / 2;

    // Self-test button
    lv_obj_t *btn_selftest = lv_btn_create(screen_admin);
    lv_obj_set_size(btn_selftest, btn_width, btn_height);
    lv_obj_set_pos(btn_selftest, x0, start_y);
    lv_obj_set_style_bg_color(btn_selftest, COLOR_PRIMARY, 0);
    lv_obj_clear_flag(btn_selftest, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_selftest, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_selftest = lv_label_create(btn_selftest);
    lv_label_set_text(label_selftest, "Self Test");
    lv_obj_set_style_text_color(label_selftest, COLOR_BG, 0);
    lv_obj_center(label_selftest);
    lv_obj_add_event_cb(btn_selftest, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN] Self-test button clicked");
            CameraApp::getInstance().setState(STATE_SELF_TEST);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Status button
    lv_obj_t *btn_status = lv_btn_create(screen_admin);
    lv_obj_set_size(btn_status, btn_width, btn_height);
    lv_obj_set_pos(btn_status, x0 + btn_width + spacing, start_y);
    lv_obj_set_style_bg_color(btn_status, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_color(btn_status, COLOR_PRIMARY, 0);
    lv_obj_set_style_border_width(btn_status, 1, 0);
    lv_obj_clear_flag(btn_status, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_status, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_status = lv_label_create(btn_status);
    lv_label_set_text(label_status, "Status");
    lv_obj_set_style_text_color(label_status, COLOR_TEXT, 0);
    lv_obj_center(label_status);
    lv_obj_add_event_cb(btn_status, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN] Status button clicked - running 'status' command");
            CameraApp::getInstance().showAdminMessage("Status printed to serial");
            SerialShell::getInstance().processCommand("status");
        }
    }, LV_EVENT_CLICKED, NULL);

    // NVS List button
    lv_obj_t *btn_nvs = lv_btn_create(screen_admin);
    lv_obj_set_size(btn_nvs, btn_width, btn_height);
    lv_obj_set_pos(btn_nvs, x0, start_y + btn_height + spacing);
    lv_obj_set_style_bg_color(btn_nvs, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_color(btn_nvs, COLOR_PRIMARY, 0);
    lv_obj_set_style_border_width(btn_nvs, 1, 0);
    lv_obj_clear_flag(btn_nvs, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_nvs, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_nvs = lv_label_create(btn_nvs);
    lv_label_set_text(label_nvs, "NVS List");
    lv_obj_set_style_text_color(label_nvs, COLOR_TEXT, 0);
    lv_obj_center(label_nvs);
    lv_obj_add_event_cb(btn_nvs, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN] NVS List button clicked - running 'nvs list' command");
            CameraApp::getInstance().showAdminMessage("NVS printed to serial");
            SerialShell::getInstance().processCommand("nvs list");
        }
    }, LV_EVENT_CLICKED, NULL);

    // Reboot button
    lv_obj_t *btn_reboot = lv_btn_create(screen_admin);
    lv_obj_set_size(btn_reboot, btn_width, btn_height);
    lv_obj_set_pos(btn_reboot, x0 + btn_width + spacing, start_y + btn_height + spacing);
    lv_obj_set_style_bg_color(btn_reboot, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_color(btn_reboot, COLOR_DANGER, 0);
    lv_obj_set_style_border_width(btn_reboot, 1, 0);
    lv_obj_clear_flag(btn_reboot, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_reboot, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_reboot = lv_label_create(btn_reboot);
    lv_label_set_text(label_reboot, "Reboot");
    lv_obj_set_style_text_color(label_reboot, COLOR_DANGER, 0);
    lv_obj_center(label_reboot);
    lv_obj_add_event_cb(btn_reboot, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN] Reboot button clicked - running 'reboot' command");
            CameraApp::getInstance().showAdminMessage("Rebooting...");
            SerialShell::getInstance().processCommand("reboot");
        }
    }, LV_EVENT_CLICKED, NULL);

    // Help text at bottom
    lv_obj_t *help_text = lv_label_create(screen_admin);
    lv_label_set_text(help_text, "More commands via serial\nType 'help' for full list");
    lv_obj_set_style_text_color(help_text, COLOR_TEXT_DIM, 0);
    lv_obj_set_style_text_align(help_text, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(help_text, LV_ALIGN_BOTTOM_MID, 0, -55);

    // Back button
    lv_obj_t *btn_back = lv_btn_create(screen_admin);
    lv_obj_set_size(btn_back, 100, 35);
    lv_obj_align(btn_back, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(btn_back, COLOR_SECONDARY, 0);
    lv_obj_clear_flag(btn_back, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_back, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *label_back = lv_label_create(btn_back);
    lv_label_set_text(label_back, "Back");
    lv_obj_set_style_text_color(label_back, COLOR_TEXT, 0);
    lv_obj_center(label_back);
    lv_obj_add_event_cb(btn_back, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN] Back button clicked");
            CameraApp::getInstance().setState(STATE_CAMERA_VIEW);
        }
    }, LV_EVENT_CLICKED, NULL);
}

void CameraApp::createAdminPINScreen() {
    screen_admin_pin = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_admin_pin, COLOR_BG, 0);

    // Home button (top left)
    lv_obj_t *btn_home = lv_btn_create(screen_admin_pin);
    lv_obj_set_size(btn_home, 40, 30);
    lv_obj_set_pos(btn_home, 5, 5);
    lv_obj_set_style_bg_color(btn_home, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_width(btn_home, 0, 0);
    lv_obj_clear_flag(btn_home, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_home, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *home_icon = lv_label_create(btn_home);
    lv_label_set_text(home_icon, LV_SYMBOL_HOME);
    lv_obj_set_style_text_color(home_icon, COLOR_TEXT_DIM, 0);
    lv_obj_center(home_icon);
    lv_obj_add_event_cb(btn_home, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[ADMIN_PIN] Home button clicked");
            CameraApp::getInstance().setState(STATE_CAMERA_VIEW);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Title
    lv_obj_t *title = lv_label_create(screen_admin_pin);
    lv_label_set_text(title, "ADMIN ACCESS");
    lv_obj_set_style_text_color(title, COLOR_DANGER, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 5);

    // PIN display
    admin_pin_label = lv_label_create(screen_admin_pin);
    lv_label_set_text(admin_pin_label, "------");
    lv_obj_set_style_text_color(admin_pin_label, COLOR_TEXT, 0);
    lv_obj_align(admin_pin_label, LV_ALIGN_TOP_MID, 0, 26);

    // Keypad (same as user PIN)
    const char* keys[] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "C", "0", LV_SYMBOL_OK};
    int btn_w = 60;
    int btn_h = 32;
    int spacing = 12;
    int grid_width = 3 * btn_w + 2 * spacing;
    int start_x = (320 - grid_width) / 2;
    int start_y = 65;

    for (int i = 0; i < 12; i++) {
        int row = i / 3;
        int col = i % 3;
        int x = start_x + col * (btn_w + spacing);
        int y = start_y + row * (btn_h + spacing);

        lv_obj_t *btn = lv_btn_create(screen_admin_pin);
        lv_obj_set_size(btn, btn_w, btn_h);
        lv_obj_set_pos(btn, x, y);
        lv_obj_set_style_bg_color(btn, COLOR_SECONDARY, LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(btn, COLOR_DANGER, LV_STATE_PRESSED);
        lv_obj_set_style_border_color(btn, COLOR_DANGER, LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(btn, 1, LV_STATE_DEFAULT);
        lv_obj_set_style_radius(btn, 4, LV_STATE_DEFAULT);
        lv_obj_add_event_cb(btn, pin_btn_event_cb, LV_EVENT_ALL, NULL);

        lv_obj_t *label = lv_label_create(btn);
        lv_label_set_text(label, keys[i]);
        lv_obj_set_style_text_color(label, COLOR_TEXT, 0);
        lv_obj_set_style_text_font(label, &lv_font_montserrat_14, 0);
        lv_obj_center(label);
    }

}

void CameraApp::showAdminMessage(const String& msg) {
    if (!screen_admin) return;
    if (!admin_msg_label) {
        admin_msg_label = lv_label_create(screen_admin);
        lv_obj_set_style_text_color(admin_msg_label, COLOR_TEXT_DIM, 0);
        lv_obj_set_style_text_align(admin_msg_label, LV_TEXT_ALIGN_CENTER, 0);
        lv_obj_align(admin_msg_label, LV_ALIGN_BOTTOM_MID, 0, -35);
    }
    lv_label_set_text(admin_msg_label, msg.c_str());
}


void CameraApp::createSettingsScreen() {
    screen_settings = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_settings, COLOR_BG, 0);

    // Home button (top left)
    lv_obj_t *btn_home = lv_btn_create(screen_settings);
    lv_obj_set_size(btn_home, 40, 30);
    lv_obj_set_pos(btn_home, 5, 5);
    lv_obj_set_style_bg_color(btn_home, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_width(btn_home, 0, 0);
    lv_obj_clear_flag(btn_home, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_home, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *home_icon = lv_label_create(btn_home);
    lv_label_set_text(home_icon, LV_SYMBOL_HOME);
    lv_obj_set_style_text_color(home_icon, COLOR_TEXT_DIM, 0);
    lv_obj_center(home_icon);
    lv_obj_add_event_cb(btn_home, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[SETTINGS] Home button clicked");
            CameraApp::getInstance().setState(STATE_CAMERA_VIEW);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Title
    lv_obj_t *title = lv_label_create(screen_settings);
    lv_label_set_text(title, "SETTINGS");
    lv_obj_set_style_text_color(title, COLOR_PRIMARY, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    // Settings info
    lv_obj_t *info = lv_label_create(screen_settings);
    String infoText = "WiFi: " + String(WiFi.SSID()) + "\n"
                      "IP: " + getAPIP() + "\n"
                      "Device: " + apSSID + "\n\n"
                      "Camera: 320x240 RGB565\n"
                      "Firmware: 1.0.0";
    lv_label_set_text(info, infoText.c_str());
    lv_obj_set_style_text_color(info, COLOR_TEXT, 0);
    lv_obj_align(info, LV_ALIGN_CENTER, 0, -10);

    // Back button
    lv_obj_t *btn_back = lv_btn_create(screen_settings);
    lv_obj_set_size(btn_back, 100, 35);
    lv_obj_align(btn_back, LV_ALIGN_BOTTOM_MID, 0, -10);
    lv_obj_set_style_bg_color(btn_back, COLOR_PRIMARY, 0);
    lv_obj_t *label_back = lv_label_create(btn_back);
    lv_label_set_text(label_back, "Back");
    lv_obj_set_style_text_color(label_back, COLOR_BG, 0);
    lv_obj_center(label_back);
    lv_obj_add_event_cb(btn_back, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            CameraApp::getInstance().setState(STATE_CAMERA_VIEW);
        }
    }, LV_EVENT_CLICKED, NULL);
}

void CameraApp::createSelfTestScreen() {
    screen_selftest = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(screen_selftest, COLOR_BG, 0);

    // Home button (top left)
    lv_obj_t *btn_home = lv_btn_create(screen_selftest);
    lv_obj_set_size(btn_home, 40, 30);
    lv_obj_set_pos(btn_home, 5, 5);
    lv_obj_set_style_bg_color(btn_home, COLOR_SECONDARY, 0);
    lv_obj_set_style_border_width(btn_home, 0, 0);
    lv_obj_clear_flag(btn_home, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(btn_home, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t *home_icon = lv_label_create(btn_home);
    lv_label_set_text(home_icon, LV_SYMBOL_HOME);
    lv_obj_set_style_text_color(home_icon, COLOR_TEXT_DIM, 0);
    lv_obj_center(home_icon);
    lv_obj_add_event_cb(btn_home, [](lv_event_t* e) {
        if (lv_event_get_code(e) == LV_EVENT_CLICKED) {
            DualSerial.println("[SELFTEST] Home button clicked");
            CameraApp::getInstance().setState(STATE_CAMERA_VIEW);
        }
    }, LV_EVENT_CLICKED, NULL);

    // Title
    lv_obj_t *title = lv_label_create(screen_selftest);
    lv_label_set_text(title, "SELF TEST");
    lv_obj_set_style_text_color(title, COLOR_PRIMARY, 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 10);

    // Test results area
    selftest_label = lv_label_create(screen_selftest);
    lv_label_set_text(selftest_label, "Running tests...");
    lv_obj_set_style_text_color(selftest_label, COLOR_TEXT, 0);
    lv_obj_align(selftest_label, LV_ALIGN_TOP_LEFT, 10, 40);
    lv_label_set_long_mode(selftest_label, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(selftest_label, 300);
}

void CameraApp::runSelfTest() {
    // Call the same comprehensive self-test that the UART interface uses
    SerialShell::getInstance().runSelfTest();

    // Update the UI with a simple message since detailed results are in serial output
    if (selftest_label) {
        lv_label_set_text(selftest_label,
            "Self-test complete!\n\n"
            "Check serial output for\n"
            "detailed results.\n\n"
            "Tests: Display, Touch,\n"
            "Camera, WiFi, I2C/PMIC,\n"
            "LED, Speaker, Microphone,\n"
            "Memory");
    }
}

void CameraApp::updateCameraPreview() {
    // For now, just show status - direct display writing conflicts with LVGL
    // TODO: Implement using LVGL canvas or separate display task
    static unsigned long lastStatusUpdate = 0;
    static int frameCount = 0;

    if (millis() - lastStatusUpdate > 1000) {
        // Test camera capture
        camera_fb_t* fb = CameraDevice::getInstance().captureFrame();
        if (fb) {
            frameCount++;
            if (status_label) {
                String status = "STREAM " + String(frameCount);
                lv_label_set_text(status_label, status.c_str());
            }
            CameraDevice::getInstance().releaseFrame(fb);
        } else {
            if (status_label) {
                lv_label_set_text(status_label, "ERROR");
            }
        }
        lastStatusUpdate = millis();
    }
}

void CameraApp::updateLED() {
    static AppState lastState = STATE_SETUP_MODE;
    static unsigned long lastBlink = 0;
    static bool blinkState = false;

    // CoreS3 uses AXP2101 charging LED (register 0x69)
    // 0b00110101 (0x35) = LED ON
    // bitOff(bit 0) = LED OFF

    // Update LED when state changes
    if (currentState != lastState) {
        lastState = currentState;
        lastBlink = millis();
        blinkState = true; // Start with LED ON

        // Set LED based on state
        switch (currentState) {
            case STATE_SETUP_MODE:
                // Steady ON for setup mode
                M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                DualSerial.println("[LED] Setup mode - ON");
                break;
            case STATE_PIN_ENTRY:
            case STATE_ADMIN_PIN_ENTRY:
                // Will blink fast
                M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                DualSerial.println("[LED] PIN entry - Fast blink");
                break;
            case STATE_CAMERA_VIEW:
                // Steady ON for camera view
                M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                DualSerial.println("[LED] Camera view - ON");
                break;
            case STATE_ADMIN_MODE:
                // Will blink medium
                M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                DualSerial.println("[LED] Admin mode - Medium blink");
                break;
            case STATE_SETTINGS:
                // Steady ON for settings
                M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                DualSerial.println("[LED] Settings - ON");
                break;
            case STATE_SELF_TEST:
                // Will blink medium
                M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                DualSerial.println("[LED] Self-test - Medium blink");
                break;
        }
    }

    // Blink pattern for certain states
    unsigned long now = millis();
    switch (currentState) {
        case STATE_PIN_ENTRY:
        case STATE_ADMIN_PIN_ENTRY:
            // Fast blink (250ms)
            if (now - lastBlink > 250) {
                blinkState = !blinkState;
                if (blinkState) {
                    M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                } else {
                    M5.In_I2C.bitOff(0x34, 0x69, 0b00000001, 100000L);
                }
                lastBlink = now;
            }
            break;
        case STATE_ADMIN_MODE:
        case STATE_SELF_TEST:
            // Medium blink (500ms)
            if (now - lastBlink > 500) {
                blinkState = !blinkState;
                if (blinkState) {
                    M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);
                } else {
                    M5.In_I2C.bitOff(0x34, 0x69, 0b00000001, 100000L);
                }
                lastBlink = now;
            }
            break;
        default:
            // Steady on for other states (no blinking)
            break;
    }
}

// Global functions
void CameraApp_Init() {
    CameraApp::getInstance().init();
}

void CameraApp_Loop() {
    CameraApp::getInstance().loop();
}

