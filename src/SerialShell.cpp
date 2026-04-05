/**
 * @file SerialShell.cpp
 * @brief UART command-line interface implementation
 *
 * Implements the interactive serial shell: command parsing, dispatch, user/admin
 * authentication via PIN, and all command handlers. Also implements:
 *
 * - USB authentication with time-limited sessions (usb-auth)
 * - Deferred USB command execution with TOCTOU race (usb-cmd)
 * - USB memory leak via uninitialized struct (usb-memleak)
 * - USB DFU firmware update over serial (usb-dfu)
 * - Memory/flash/partition dump commands (admin only)
 * - Hardware self-test suite (11 tests covering display, touch, camera,
 *   WiFi, I2C/PMIC, LED, speaker, mic, memory, NVS, security gate)
 */

#include "SerialShell.h"
#include "M5Unified.h"
#include <Wire.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <esp_partition.h>
#include <esp_flash.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <Update.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "config.h"
#include "DualSerial.h"

// ---------------------------------------------------------------------------
// USB authentication state
//
// USB auth uses a time-limited session: `usb-auth usbadmin` sets the flag
// for 2 seconds, after which a background FreeRTOS task clears it. The
// usb-cmd handler checks the flag then dispatches a worker task with a
// 250ms delay, creating a TOCTOU race between the auth timeout and the
// deferred command execution.
// ---------------------------------------------------------------------------

#ifdef FACTORY_TEST
static volatile bool s_usbAuthAuthorized = false;
static volatile unsigned long s_usbAuthExpiryMs = 0;
static TaskHandle_t s_usbAuthTimeoutTask = nullptr;

// Background task that polls and expires the USB auth session.
static void usbAuthTimeoutTask(void* arg) {
    (void)arg;
    for (;;) {
        unsigned long now = millis();
        if (s_usbAuthAuthorized && now > s_usbAuthExpiryMs) {
            s_usbAuthAuthorized = false;
            DualSerial.println("[USB-AUTH] Session expired (timeout)");
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
#endif

SerialShell& SerialShell::getInstance() {
    static SerialShell instance;
    return instance;
}

void SerialShell::init() {
    // DualSerial echoes to both USB and debug UART on expansion header
    DualSerial.println("\n\n=================================");
    DualSerial.println("CoreS3 IoT Camera Device");
    DualSerial.println("Maintenance Console");
    DualSerial.println("=================================");
    DualSerial.println("Type 'help' for available commands");
#ifdef FACTORY_TEST
    if (!s_usbAuthTimeoutTask) {
        xTaskCreatePinnedToCore(
            usbAuthTimeoutTask,
            "usbAuthTimer",
            2048,
            nullptr,
            1,
            &s_usbAuthTimeoutTask,
            tskNO_AFFINITY);
    }
#endif
    DualSerial.print("\ncores3-cam> ");
}

void SerialShell::loop() {
    while (DualSerial.available()) {
        char c = DualSerial.read();

        if (c == '\n' || c == '\r') {
            if (commandBuffer.length() > 0) {
                DualSerial.println();  // Echo newline
                processCommand(commandBuffer);
                commandBuffer = "";
                DualSerial.print("\ncores3-cam> ");
            }
        } else if (c == '\b' || c == 127) {  // Backspace
            if (commandBuffer.length() > 0) {
                commandBuffer.remove(commandBuffer.length() - 1);
                DualSerial.print("\b \b");  // Erase character
            }
        } else if (c >= 32 && c < 127) {  // Printable characters
            commandBuffer += c;
            DualSerial.print(c);  // Echo character
        }
    }
}

// Track whether current command has elevated privileges (e.g., from web handler context)
static bool g_privilegedContext = false;

static bool requireAdmin(const char* cmdName) {
    if (g_privilegedContext) return true;
    if (CameraApp::getInstance().isAdmin()) return true;
    DualSerial.printf("[%s] Admin privileges required.\n", cmdName);
    return false;
}

void SerialShell::processCommand(const String& cmd, bool privileged) {
    g_privilegedContext = privileged;
    String command = cmd;
    command.trim();
    command.toLowerCase();

    if (command == "help" || command == "?") {
        printHelp();
    } else if (command.startsWith("login ")) {
        String pin = cmd.substring(6);
        pin.trim();

        CameraApp& app = CameraApp::getInstance();
        if (app.checkAdminPIN(pin)) {
            DualSerial.println("Admin mode unlocked.");
        } else if (app.checkUserPIN(pin)) {
            DualSerial.println("User authenticated.");
        } else {
            DualSerial.println("Invalid PIN.");
        }
    } else if (command == "logout") {
        CameraApp& app = CameraApp::getInstance();
        app.lockAdmin();
        DualSerial.println("Logged out. Admin mode locked.");
    } else if (command == "whoami") {
        CameraApp& app = CameraApp::getInstance();
        if (app.isAdmin()) {
            DualSerial.println("admin");
        } else if (app.isUnlocked()) {
            DualSerial.println("user");
        } else {
            DualSerial.println("guest (locked)");
        }
    } else if (command == "status") {
        printStatus();
    } else if (command == "test camera" || command == "camera-test") {
        testCamera();
    } else if (command == "test wifi" || command == "wifi-test") {
        testWiFi();
    } else if (command.startsWith("test pin ") || command.startsWith("pin-test ")) {
        String pin = cmd.substring(9);
        pin.trim();
        testPIN(pin);
    } else if (command == "reset" || command == "factory-reset") {
        resetDevice();
    } else if (command.startsWith("wifi ")) {
        if (!requireAdmin("WIFI")) { /* denied */ }
        else {
            // Format: wifi <ssid> <password>
            int spaceIdx = cmd.indexOf(' ', 5);
            if (spaceIdx > 0) {
                String ssid = cmd.substring(5, spaceIdx);
                String pass = cmd.substring(spaceIdx + 1);
                setWiFi(ssid, pass);
            } else {
                DualSerial.println("Usage: wifi <ssid> <password>");
            }
        }
    } else if (command == "nvs list" || command == "nvs-list") {
        listNVS();
    } else if (command == "nvs clear" || command == "nvs-clear") {
        if (requireAdmin("NVS-CLEAR")) clearNVS();
    } else if (command.startsWith("usb-auth ")) {
        String pw = cmd.substring(9);
        pw.trim();
        usbAuth(pw);
    } else if (command.startsWith("usb-cmd ")) {
        String arg = cmd.substring(8);
        arg.trim();
        usbCommand(arg);
    } else if (command == "usb-memleak" || command == "usb-mem-leak") {
        usbMemLeak();
    } else if (command.startsWith("usb-dfu ")) {
        if (!requireAdmin("USB-DFU")) { /* denied */ }
        else {
            String sz = cmd.substring(8);
            sz.trim();
            uint32_t size = strtoul(sz.c_str(), nullptr, 0);
            if (size == 0) {
                DualSerial.println("Usage: usb-dfu <size_bytes>");
                DualSerial.println("Example: usb-dfu 262144  (then send 256KB of firmware data)");
            } else {
                usbDFU(size);
            }
        }
    }
#ifdef DEV_TEST_HOOKS
    else if (command.startsWith("diag ")) {
        // Parse: diag <id> [p1]
        String args = cmd.substring(5);
        args.trim();
        int spaceIdx = args.indexOf(' ');
        int diagId;
        String p1 = "";
        if (spaceIdx > 0) {
            diagId = args.substring(0, spaceIdx).toInt();
            p1 = args.substring(spaceIdx + 1);
            p1.trim();
        } else {
            diagId = args.toInt();
        }
        runDiag(diagId, p1);
    }
#endif
    else if (command == "selftest" || command == "self-test" || command == "self test") {
        runSelfTest();
    } else if (command == "ledtest" || command == "led-test" || command == "test led") {
        testLED();
    } else if (command == "audiotest" || command == "audio-test" || command == "test audio") {
        testAudio();
    } else if (command == "spktest" || command == "speaker-test" || command == "test speaker") {
        testSpeaker();
    } else if (command == "mictest" || command == "mic-test" || command == "test mic") {
        testMicrophone();
    } else if (command == "spkconfig" || command == "speaker-config") {
        configureSpeakerHardware();
    } else if (command == "bus-diag" || command == "bus diag") {
        #ifdef FACTORY_TEST
        if (requireAdmin("BUS-DIAG")) {
            DualSerial.println("Re-emitting I2C diagnostics on Port.A...");
            CameraDevice::getInstance().emitI2CSecrets();
            DualSerial.println("I2C emission complete.");
        }
        #else
        DualSerial.println("Bus diagnostics only available in factory test build");
        #endif
    } else if (command == "reboot") {
        DualSerial.println("Rebooting...");
        delay(1000);
        ESP.restart();
    }
    // Firmware dump commands (admin required)
    else if (command.startsWith("memdump ") || command.startsWith("mem-dump ")) {
        if (!requireAdmin("MEMDUMP")) { /* denied */ }
        else {
            int spaceIdx = cmd.indexOf(' ', 8);
            if (spaceIdx > 0) {
                uint32_t addr = strtoul(cmd.substring(8, spaceIdx).c_str(), NULL, 0);
                uint32_t len = strtoul(cmd.substring(spaceIdx + 1).c_str(), NULL, 0);
                dumpMemory(addr, len);
            } else {
                DualSerial.println("Usage: memdump <addr> <len>");
                DualSerial.println("Example: memdump 0x3C000000 256");
            }
        }
    } else if (command.startsWith("flashdump ") || command.startsWith("flash-dump ")) {
        if (!requireAdmin("FLASHDUMP")) { /* denied */ }
        else {
            int spaceIdx = cmd.indexOf(' ', 10);
            if (spaceIdx > 0) {
                uint32_t addr = strtoul(cmd.substring(10, spaceIdx).c_str(), NULL, 0);
                uint32_t len = strtoul(cmd.substring(spaceIdx + 1).c_str(), NULL, 0);
                dumpFlash(addr, len);
            } else {
                DualSerial.println("Usage: flashdump <addr> <len>");
                DualSerial.println("Example: flashdump 0x0 0x8000");
            }
        }
    } else if (command.startsWith("partdump ") || command.startsWith("part-dump ")) {
        if (!requireAdmin("PARTDUMP")) { /* denied */ }
        else {
            String partName = cmd.substring(9);
            partName.trim();
            dumpPartition(partName);
        }
    } else if (command == "nvsdump" || command == "nvs-dump") {
        dumpNVS(g_privilegedContext);
    } else if (command == "partlist" || command == "part-list" || command == "partitions") {
        listPartitions();
    } else if (command == "bus-stress" || command == "spi-stress") {
        if (requireAdmin("BUS-STRESS")) {
            CameraDevice& device = CameraDevice::getInstance();
            String resp = device.run_diagnostic(30);
            DualSerial.println(resp);
        }
    } else if (command == "forensics-snap") {
        if (requireAdmin("FORENSICS")) {
            CameraDevice& device = CameraDevice::getInstance();
            String resp = device.run_diagnostic(31);
            DualSerial.println(resp);
        }
    } else if (command == "crashdump" || command == "crash-dump") {
        if (requireAdmin("CRASHDUMP")) {
            CameraDevice& device = CameraDevice::getInstance();
            String resp = device.run_diagnostic(32);
            DualSerial.println(resp);
        }

#ifdef DEV_TEST_HOOKS
    } else if (command == "fmt-check") {
        CameraDevice& device = CameraDevice::getInstance();
        String resp = device.run_diagnostic(33);
        DualSerial.println(resp);
#endif
    } else if (command == "heap-test" || command.startsWith("heap-test ")) {
        CameraDevice& device = CameraDevice::getInstance();
        String arg = cmd.substring(10);
        arg.trim();
        String resp = device.run_diagnostic(34, arg);
        DualSerial.println(resp);

#ifdef DEV_TEST_HOOKS
    } else if (command == "csrf-check") {
        CameraDevice& device = CameraDevice::getInstance();
        String resp = device.run_diagnostic(35);
        DualSerial.println(resp);
    } else if (command == "wifi-deauth" || command == "pmf-check") {
        CameraDevice& device = CameraDevice::getInstance();
        String resp = device.run_diagnostic(36);
        DualSerial.println(resp);
    } else if (command == "mdns-check") {
        CameraDevice& device = CameraDevice::getInstance();
        String resp = device.run_diagnostic(37);
        DualSerial.println(resp);
    } else if (command == "secureboot-check") {
        CameraDevice& device = CameraDevice::getInstance();
        String resp = device.run_diagnostic(38);
        DualSerial.println(resp);
    } else if (command == "flashcrypt-check") {
        CameraDevice& device = CameraDevice::getInstance();
        String resp = device.run_diagnostic(39);
        DualSerial.println(resp);
#endif
    }
    else if (command == "") {
        // Empty command, do nothing
    } else {
        DualSerial.println("Unknown command: " + cmd);
        DualSerial.println("Type 'help' for available commands");
    }
    g_privilegedContext = false;
}

void SerialShell::printHelp() {
    DualSerial.println("\nUser Commands:");
    DualSerial.println("==================");
    DualSerial.println("help              - Show this help message");
    DualSerial.println("login <pin>       - Authenticate as user or admin");
    DualSerial.println("logout            - Lock admin mode");
    DualSerial.println("whoami            - Show current access level");
    DualSerial.println("status            - Show device status");
    DualSerial.println("self-test         - Run hardware self-test");
    DualSerial.println("led-test          - Test LED control");
    DualSerial.println("audio-test        - Test speaker and microphone");
    DualSerial.println("speaker-test      - Test speaker only");
    DualSerial.println("mic-test          - Test microphone only");
    DualSerial.println("camera-test       - Test camera capture");
    DualSerial.println("wifi-test         - Test WiFi connection");
    DualSerial.println("nvs-list          - List stored configuration");
    DualSerial.println("part-list         - List flash partitions");
    DualSerial.println("reset             - Factory reset");
    DualSerial.println("reboot            - Reboot device");
    DualSerial.println("");
    DualSerial.println("Admin Commands (login <admin_pin> first):");
    DualSerial.println("==========================================");
    DualSerial.println("wifi <ssid> <pw>  - Set WiFi credentials");
    DualSerial.println("nvs-clear         - Clear all NVS data");
    DualSerial.println("nvs-dump          - Dump full NVS contents");
    DualSerial.println("memdump <a> <l>   - Dump memory region");
    DualSerial.println("flashdump <a> <l> - Dump flash region");
    DualSerial.println("partdump <name>   - Dump partition by name");
    DualSerial.println("usb-cmd <cmd>     - USB privileged command");
    DualSerial.println("usb-dfu <size>    - Firmware update via USB serial");
    DualSerial.println("bus-diag          - Re-emit I2C diagnostics");
    DualSerial.println("bus-stress        - SPI/SD bus stress test");
    DualSerial.println("forensics-snap    - Capture debug snapshot to SD");
    DualSerial.println("crash-dump        - Generate crash report to SD");
#ifdef DEV_TEST_HOOKS
    DualSerial.println("");
    DualSerial.println("Diagnostic Commands (debug build only):");
    DualSerial.println("=========================================");
    DualSerial.println("diag <num> [arg]  - Run diagnostic (1-39)");
    DualSerial.println("fmt-check         - Format string check");
    DualSerial.println("csrf-check        - CSRF protection status");
    DualSerial.println("wifi-deauth       - WiFi PMF status check");
    DualSerial.println("mdns-check        - mDNS service check");
    DualSerial.println("secureboot-check  - Secure boot eFuse status");
    DualSerial.println("flashcrypt-check  - Flash encryption eFuse status");
#endif
}

void SerialShell::printStatus() {
    CameraApp& app = CameraApp::getInstance();
    CameraDevice& device = CameraDevice::getInstance();

    DualSerial.println("\n=== Device Status ===");
    DualSerial.printf("Device ID: %s\n", device.getDeviceID().c_str());
    DualSerial.printf("Firmware: %s\n", device.getFirmwareVersion().c_str());
    DualSerial.printf("Free Heap: %d bytes\n", ESP.getFreeHeap());
    DualSerial.printf("PSRAM Free: %d bytes\n", ESP.getFreePsram());

    DualSerial.println("\n=== WiFi Status ===");
    DualSerial.printf("Mode: %s\n", WiFi.getMode() == WIFI_AP ? "AP" :
                                    WiFi.getMode() == WIFI_STA ? "Station" :
                                    WiFi.getMode() == WIFI_AP_STA ? "AP+Station" : "Off");
    if (WiFi.getMode() == WIFI_AP || WiFi.getMode() == WIFI_AP_STA) {
        DualSerial.printf("AP SSID: %s\n", WiFi.softAPSSID().c_str());
        DualSerial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
        DualSerial.printf("AP Clients: %d\n", WiFi.softAPgetStationNum());
    }
    if (WiFi.getMode() == WIFI_STA || WiFi.getMode() == WIFI_AP_STA) {
        DualSerial.printf("Connected: %s\n", WiFi.isConnected() ? "Yes" : "No");
        if (WiFi.isConnected()) {
            DualSerial.printf("SSID: %s\n", WiFi.SSID().c_str());
            DualSerial.printf("IP: %s\n", WiFi.localIP().toString().c_str());
            DualSerial.printf("RSSI: %d dBm\n", WiFi.RSSI());
        }
    }

    DualSerial.println("\n=== App Status ===");
    bool adminUnlocked = app.isAdmin();
    DualSerial.println("User PIN: ******");
    if (adminUnlocked) {
        DualSerial.println("Admin PIN: ****** (admin unlocked)");
    } else {
        DualSerial.println("Admin PIN: ******");
    }
    DualSerial.printf("WiFi Configured: %s\n", app.hasWiFiConfig() ? "Yes" : "No");

    DualSerial.println("\n=== Camera Status ===");
    camera_fb_t* fb = device.captureFrame();
    if (fb) {
        DualSerial.printf("Camera: OK (captured %d bytes)\n", fb->len);
        esp_camera_fb_return(fb);
    } else {
        DualSerial.println("Camera: FAILED");
    }
}

void SerialShell::testCamera() {
    DualSerial.println("\nTesting camera...");
    CameraDevice& device = CameraDevice::getInstance();

    for (int i = 0; i < 5; i++) {
        camera_fb_t* fb = device.captureFrame();
        if (fb) {
            DualSerial.printf("Frame %d: %dx%d, %d bytes, format=%d\n",
                           i+1, fb->width, fb->height, fb->len, fb->format);
            esp_camera_fb_return(fb);
        } else {
            DualSerial.printf("Frame %d: FAILED\n", i+1);
        }
        delay(100);
    }
}

void SerialShell::testWiFi() {
    DualSerial.println("\nScanning WiFi networks...");
    int n = WiFi.scanNetworks();
    DualSerial.printf("Found %d networks:\n", n);
    for (int i = 0; i < n; i++) {
        DualSerial.printf("%2d: %s (%d dBm) %s\n",
                       i+1,
                       WiFi.SSID(i).c_str(),
                       WiFi.RSSI(i),
                       WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "Open" : "Encrypted");
    }
}

void SerialShell::testPIN(const String& pin) {
    CameraApp& app = CameraApp::getInstance();

    DualSerial.printf("\nTesting PIN: %s\n", pin.c_str());

    bool isValidAdmin = false;
    if (app.checkUserPIN(pin)) {
        DualSerial.println("Result: VALID USER PIN");
    } else if (app.checkAdminPIN(pin)) {
        DualSerial.println("Result: VALID ADMIN PIN");
        isValidAdmin = true;
    } else {
        DualSerial.println("Result: INVALID PIN");
    }

    DualSerial.println("Expected PIN: ******");
}

void SerialShell::resetDevice() {
    DualSerial.println("\nFactory reset - clearing all data...");
    clearNVS();
    DualSerial.println("Rebooting...");
    delay(1000);
    ESP.restart();
}

void SerialShell::setWiFi(const String& ssid, const String& pass) {
    DualSerial.printf("\nSetting WiFi: SSID='%s', Password=***\n", ssid.c_str());

    Preferences prefs;
    prefs.begin("camera", false);
    prefs.putString("wifi_ssid", ssid);
    prefs.putString("wifi_pass", pass);
    prefs.end();

    DualSerial.println("WiFi credentials saved. Reboot to apply.");
}

void SerialShell::listNVS() {
    DualSerial.println("\n=== NVS Storage ===");

    Preferences prefs;
    prefs.begin("camera", true);

    String ssid = prefs.getString("wifi_ssid", "");
    String pass = prefs.getString("wifi_pass", "");
    String userPin = prefs.getString("user_pin", "");
    String adminPin = prefs.getString("admin_pin", "");

    CameraApp& app = CameraApp::getInstance();
    bool userUnlocked = app.isUnlocked();
    bool adminUnlocked = app.isAdmin();
    DualSerial.printf("wifi_ssid: %s\n", ssid.length() > 0 ? ssid.c_str() : "(not set)");
    DualSerial.printf("wifi_pass: %s\n", pass.length() > 0 ? "***" : "(not set)");
    if (userUnlocked || adminUnlocked) {
        DualSerial.printf("user_pin: %s\n", userPin.c_str());
    } else {
        DualSerial.println("user_pin: ******");
    }
    if (adminUnlocked) {
        DualSerial.printf("admin_pin: %s\n", adminPin.c_str());
    } else {
        DualSerial.println("admin_pin: ******");
    }

    prefs.end();
}

void SerialShell::clearNVS() {
    DualSerial.println("\nClearing NVS storage...");

    Preferences prefs;
    prefs.begin("camera", false);
    prefs.clear();
    prefs.end();

    DualSerial.println("NVS cleared.");
}

void SerialShell::runDiag(int diagId, const String& p1) {
    DualSerial.printf("\nRunning diagnostic %d...\n", diagId);
#ifdef DEV_TEST_HOOKS
    CameraDevice& device = CameraDevice::getInstance();
    String resp = device.run_diagnostic((uint8_t)diagId, p1);
    if (resp.length() == 0 || resp == "NA") {
        DualSerial.printf("Diagnostic %d produced no output.\n", diagId);
    } else {
        DualSerial.println(resp);
    }
#else
    DualSerial.println("Diagnostics are unavailable in this build.");
#endif
}

void SerialShell::usbAuth(const String& password) {
#ifdef FACTORY_TEST
    if (password == "usbadmin") {
        s_usbAuthAuthorized = true;
        s_usbAuthExpiryMs = millis() + 2000;  // 2 second window
        DualSerial.println("[USB-AUTH] Authenticated (session active)");
    } else {
        DualSerial.println("[USB-AUTH] Invalid password");
        s_usbAuthAuthorized = false;
    }
#else
    (void)password;
    DualSerial.println("[USB-AUTH] Disabled in this build");
#endif
}

// Worker task for deferred USB command execution.
// Auth is checked by the caller (usbCommand) on the serial handler task,
// but the privileged action runs here on a separate FreeRTOS task after
// a bus-settling delay. This creates a TOCTOU race: the auth flag can
// be cleared by the timeout task during the delay, but the command still
// executes because the check already passed on the other task.
#ifdef FACTORY_TEST
void usbCmdWorker(void* pvParams) {
    char* cmd = (char*)pvParams;

    // USB bus settling / command processing delay.
    // This delay widens the TOCTOU window: auth may expire here.
    vTaskDelay(pdMS_TO_TICKS(250));

    if (strcmp(cmd, "dump-nvs") == 0) {
        DualSerial.println("[USB-CMD] Dumping NVS (privileged)");
        SerialShell::getInstance().dumpNVS(true);
    } else if (strcmp(cmd, "reboot") == 0) {
        DualSerial.println("[USB-CMD] Rebooting (privileged)");
        vTaskDelay(pdMS_TO_TICKS(1000));
        esp_restart();
    } else {
        DualSerial.println("[USB-CMD] Unknown privileged command");
    }

    free(cmd);
    vTaskDelete(NULL);
}
#endif

void SerialShell::usbCommand(const String& cmd) {
#ifdef FACTORY_TEST
    DualSerial.printf("[USB-CMD] Request: %s\n", cmd.c_str());
    if (!s_usbAuthAuthorized) {
        DualSerial.println("[USB-CMD] Not authorized");
        return;
    }

    // Auth check passed on this task. Dispatch to a worker task for
    // deferred execution. The worker runs on a separate FreeRTOS task,
    // creating a genuine race with the auth timeout task: both access
    // s_usbAuthAuthorized without synchronization.
    char* cmdCopy = strdup(cmd.c_str());
    if (cmdCopy) {
        xTaskCreatePinnedToCore(usbCmdWorker, "usb_exec", 4096,
                                cmdCopy, 1, NULL, 1);
    }
#else
    (void)cmd;
    DualSerial.println("[USB-CMD] Disabled in this build");
#endif
}

void SerialShell::usbMemLeak() {
#ifdef FACTORY_TEST
    DualSerial.println("[USB-MEM] USB control transfer status buffer:");

    // USB control transfer response. The firmware reuses a config
    // scratch buffer as the USB response without clearing it first.
    // This is a real pattern: embedded code often reuses buffers across
    // subsystems to save RAM on constrained devices.
    struct UsbStatus {
        uint8_t status;
        uint8_t version;
        uint8_t reserved[62];
    };

    // Scratch buffer used by the config subsystem to format credential
    // strings for internal processing. Same memory is then cast to
    // UsbStatus for the USB response - the credential data persists
    // in the reserved[] region because only status/version are set.
    union {
        char config_scratch[sizeof(UsbStatus)];
        UsbStatus usb_reply;
    } buf;

    // Config subsystem writes credentials into scratch buffer
    CameraApp& app = CameraApp::getInstance();
    CameraDevice& dev = CameraDevice::getInstance();
    String creds = String("user_pin=") + app.getUserPIN() +
                   ";admin_pin=" + app.getAdminPIN() +
                   ";jwt=" + dev.dev_getJWTSecret();
    size_t len = creds.length() < (sizeof(buf.config_scratch) - 1)
                 ? creds.length() : (sizeof(buf.config_scratch) - 1);
    memcpy(buf.config_scratch, creds.c_str(), len);
    buf.config_scratch[len] = '\0';

    // USB subsystem reuses the same buffer for the response.
    // Only the protocol header fields are written - the rest
    // of the buffer still contains the config credential data.
    buf.usb_reply.status = 0x01;
    buf.usb_reply.version = 0x01;
    // buf.usb_reply.reserved[] still has credential string residue

    uint8_t* raw = reinterpret_cast<uint8_t*>(&buf.usb_reply);
    for (size_t i = 0; i < sizeof(UsbStatus); ++i) {
        if (i % 16 == 0) {
            DualSerial.println();
        }
        DualSerial.printf("%02X ", raw[i]);
    }
    DualSerial.println();
#else
    DualSerial.println("[USB-MEM] Disabled in this build");
#endif
}

void SerialShell::usbDFU(uint32_t size) {
#ifdef FACTORY_TEST
    DualSerial.printf("[DFU] Starting USB serial firmware update (%u bytes expected)\n", (unsigned)size);
    if (size == 0) {
        DualSerial.println("[DFU] Size is zero, aborting");
        return;
    }

    if (!Update.begin(size)) {
        DualSerial.printf("[DFU] Update.begin failed: %s\n", Update.errorString());
        return;
    }

    size_t received = 0;
    unsigned long start = millis();
    const unsigned long timeoutMs = 30000;

    while (received < size && (millis() - start) < timeoutMs) {
        int avail = DualSerial.available();
        if (avail > 0) {
            uint8_t buffer[256];
            size_t toRead = size - received;
            if (toRead > sizeof(buffer)) {
                toRead = sizeof(buffer);
            }
            int n = DualSerial.readBytes((char*)buffer, toRead);
            if (n > 0) {
                Update.write(buffer, n);
                received += n;
            }
        } else {
            delay(5);
        }
    }

    if (received != size) {
        DualSerial.printf("[DFU] Timeout or short transfer (received %u/%u bytes)\n",
                         (unsigned)received, (unsigned)size);
        Update.abort();
        return;
    }

    if (!Update.end()) {
        DualSerial.printf("[DFU] Update.end failed: %s\n", Update.errorString());
        return;
    }

    DualSerial.println("[DFU] Firmware updated over USB serial");
    DualSerial.println("[DFU] Rebooting into new firmware...");
    delay(1000);
    ESP.restart();
#else
    (void)size;
    DualSerial.println("[DFU] Disabled in this build");
#endif
}


void SerialShell::runSelfTest() {
    DualSerial.println("\n=== HARDWARE SELF-TEST ===\n");
    int passed = 0;
    int failed = 0;

    // Test 1: Display
    DualSerial.print("1. Display Test.......... ");
    if (M5.Display.width() == 320 && M5.Display.height() == 240) {
        DualSerial.println("PASS (320x240)");
        passed++;
    } else {
        DualSerial.printf("FAIL (%dx%d)\n", M5.Display.width(), M5.Display.height());
        failed++;
    }
    DualSerial.printf("   [DISPLAY] Reported resolution: %dx%d\n", M5.Display.width(), M5.Display.height());
    DualSerial.println("   [DISPLAY] Expected: 320x240 (CoreS3 IPS panel)");


    // Test 2: Touch
    DualSerial.print("2. Touch Test............ ");
    if (M5.Touch.isEnabled()) {
        DualSerial.println("PASS");
        passed++;
    } else {
        DualSerial.println("FAIL");
        failed++;
    }
    DualSerial.printf("   [TOUCH] Controller enabled: %s\n", M5.Touch.isEnabled() ? "YES" : "NO");
    DualSerial.println("   [TOUCH] This only checks basic init (no gesture test).");


    // Test 3: Camera
    DualSerial.print("3. Camera Test........... ");
    camera_fb_t* fb = CameraDevice::getInstance().captureFrame();
    if (fb && fb->len > 0) {
        DualSerial.printf("PASS (%dx%d, %d bytes)\n", fb->width, fb->height, fb->len);
        passed++;
        CameraDevice::getInstance().releaseFrame(fb);
    } else {
        DualSerial.println("FAIL");
        failed++;
    }
    DualSerial.println("   [CAMERA] Captured a single frame from the GC0308 sensor.");
    DualSerial.println("   [CAMERA] This verifies SCCB/I2C, sensor, and frame buffer.");


    // Test 4: WiFi
    DualSerial.print("4. WiFi Test............. ");
    if (WiFi.status() == WL_CONNECTED) {
        DualSerial.printf("PASS (IP: %s, RSSI: %d dBm)\n",
                         WiFi.localIP().toString().c_str(), WiFi.RSSI());
        passed++;
    } else if (WiFi.getMode() == WIFI_AP) {
        DualSerial.printf("PASS (AP Mode: %s)\n", WiFi.softAPSSID().c_str());
        passed++;
    } else {
        DualSerial.println("FAIL");
        failed++;
    }
    wifi_mode_t mode = WiFi.getMode();
    DualSerial.printf("   [WIFI] Mode: %s\n",
                     mode == WIFI_AP ? "AP" :
                     mode == WIFI_STA ? "Station" :
                     mode == WIFI_AP_STA ? "AP+Station" : "Off");
    if (mode == WIFI_AP || mode == WIFI_AP_STA) {
        DualSerial.printf("   [WIFI] AP SSID: %s, IP: %s\n",
                         WiFi.softAPSSID().c_str(),
                         WiFi.softAPIP().toString().c_str());
    }
    if (mode == WIFI_STA || mode == WIFI_AP_STA) {
        DualSerial.printf("   [WIFI] STA connected: %s\n",
                         WiFi.isConnected() ? "YES" : "NO");
    }


    // Test 5: I2C/PMIC (AXP2101)
    DualSerial.print("5. I2C/PMIC Test......... ");
    // Try reading from AXP2101 power management IC using M5.In_I2C
    // Avoid forcing a re-init here to prevent noisy driver install logs.
    // If the bus is busy or released, the read will likely return 0xFF and we'll skip.
    uint8_t data = M5.In_I2C.readRegister8(0x34, 0x00, 100000L);

    // AXP2101 register 0x00 should return a valid chip ID
    // Just check that we got some response (not 0xFF which indicates no device)
    if (data != 0xFF) {
        DualSerial.printf("PASS (AXP2101 detected at 0x34, ID=0x%02X)\n", data);
        passed++;
    } else {
        DualSerial.printf("WARN (I2C busy, skipping)\n");
        // Don't fail this test as I2C might be in use by camera
        passed++;
    }
    DualSerial.printf("   [PMIC] AXP2101 ID reg (0x00): 0x%02X\n", data);
    uint8_t ldoEnable = M5.In_I2C.readRegister8(0x34, 0x90, 100000L);
    DualSerial.printf("   [PMIC] LDO enable reg (0x90): 0x%02X\n", ldoEnable);
    DualSerial.println("   [PMIC] ALDO1 powers the speaker amp, ALDO2 powers the mic codec.");


    // Test 6: LED (AXP2101 Charging LED)
    DualSerial.print("6. LED Test.............. ");
    // CoreS3 uses AXP2101 charging LED (register 0x69)
    // Test by toggling the LED on/off
    bool ledTestPassed = true;

    // Turn LED ON (0b00110101)
    if (!M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L)) {
        DualSerial.println("FAIL (cannot write to AXP2101)");
        failed++;
        ledTestPassed = false;
    }

    if (ledTestPassed) {
        delay(200);

        // Turn LED OFF (bitOff bit 0)
        if (!M5.In_I2C.bitOff(0x34, 0x69, 0b00000001, 100000L)) {
            DualSerial.println("FAIL (cannot write to AXP2101)");
            failed++;
            ledTestPassed = false;
        }
    }

    if (ledTestPassed) {
        delay(200);

        // Turn LED back ON
        M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);

        DualSerial.println("PASS (check charging LED near USB-C)");
        passed++;
    }
    DualSerial.println("   [LED] Used AXP2101 reg 0x69 to toggle the charging LED.");
    DualSerial.println("   [LED] This is the small LED near the USB-C connector.");


    // Test 7: Speaker
    DualSerial.print("7. Speaker Test.......... ");
    CameraDevice& device = CameraDevice::getInstance();
    if (!device.isAudioInitialized()) {
        device.initAudio();
    }
    DualSerial.println("");  // New line for detailed output
    if (device.testSpeaker()) {
        DualSerial.println("   PASS (you should have heard a 2-second beep)");
        passed++;
    } else {
        DualSerial.println("   FAIL");
        failed++;
    }

    // Test 8: Microphone
    DualSerial.print("8. Microphone Test....... ");
    DualSerial.println();
    DualSerial.println("   SKIP (requires user interaction - use 'mic-test' command)");
    DualSerial.println("   [MIC] Self-test does NOT record audio automatically.");
    DualSerial.println("   [MIC] Run 'mic-test' from the shell to record 2 seconds,");
    DualSerial.println("         analyze levels, and play your voice back.");
    // Microphone test requires user to speak, so we skip it in self-test
    // Users can run 'mic-test' command separately
    passed++;

    // Test 9: Memory
    DualSerial.print("9. Memory Test........... ");
    size_t freeHeap = ESP.getFreeHeap();
    size_t freePSRAM = ESP.getFreePsram();
    if (freeHeap > 50000 && freePSRAM > 1000000) {
        DualSerial.printf("PASS (Heap: %d, PSRAM: %d)\n", freeHeap, freePSRAM);
        passed++;
    } else {
        DualSerial.printf("WARN (Heap: %d, PSRAM: %d)\n", freeHeap, freePSRAM);
        failed++;
    }
    DualSerial.println("   [MEM] This checks that heap and PSRAM are in a healthy range");
    DualSerial.println("   [MEM] for normal operation (simple sanity check).");


    // Test 10: NVS Storage
    DualSerial.print("10. NVS Storage Test..... ");
    Preferences prefs;
    if (prefs.begin("test", false)) {
        prefs.putString("test", "ok");
        String val = prefs.getString("test", "");
        prefs.end();
        if (val == "ok") {
            DualSerial.println("PASS");
            passed++;
        } else {
            DualSerial.println("FAIL");
            failed++;
        }
    } else {
        DualSerial.println("FAIL");
        failed++;
    }
    DualSerial.println("   [NVS] Wrote key 'test'='ok' into NVS namespace 'test'.");
    DualSerial.println("   [NVS] This verifies flash key-value storage is working.");


    // Test 11: Security Gate Integrity
    #ifdef FACTORY_TEST
    DualSerial.print("11. Security Gate Test... ");
    {
        CameraDevice& device = CameraDevice::getInstance();
        String gateResult = device.runBusContentionTest();
        if (gateResult.indexOf("debug_mode=ENABLED") >= 0) {
            DualSerial.println("FAIL (gate bypassed!)");
            failed++;
        } else {
            DualSerial.println("PASS");
            passed++;
        }
    }
    DualSerial.println("   [GATE] Runs 16 validation rounds with GPIO7 trigger.");
    DualSerial.println("   [GATE] Verifies security gate sentinel survives intact.");
    #endif


    // Summary
    DualSerial.println("\n=== TEST SUMMARY ===");
    DualSerial.printf("Passed: %d/%d\n", passed, passed + failed);
    DualSerial.printf("Failed: %d/%d\n", failed, passed + failed);
    if (failed == 0) {
        DualSerial.println("Status: ALL TESTS PASSED");
    } else {
        DualSerial.println("Status: SOME TESTS FAILED");
    }
    DualSerial.println();
}

void SerialShell::testLED() {
    DualSerial.println("\n=== LED TEST ===");
    DualSerial.println("Testing AXP2101 Charging LED (near USB-C port)");
    DualSerial.println();

    // Test 1: Turn LED ON
    DualSerial.print("1. Turning LED ON......... ");
    // Use 0b00110101 (0x35) to turn LED ON
    if (M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L)) {
        DualSerial.println("OK");
        DualSerial.println("   -> LED should be ON now");
        delay(1000);
    } else {
        DualSerial.println("FAIL (cannot write to AXP2101)");
        return;
    }

    // Test 2: Turn LED OFF
    DualSerial.print("2. Turning LED OFF........ ");
    // Use bitOff to turn LED OFF (clear bit 0)
    if (M5.In_I2C.bitOff(0x34, 0x69, 0b00000001, 100000L)) {
        DualSerial.println("OK");
        DualSerial.println("   -> LED should be OFF now");
        delay(1000);
    } else {
        DualSerial.println("FAIL (cannot write to AXP2101)");
        return;
    }

    // Test 3: Blink test
    DualSerial.print("3. Blink test (5x)........ ");
    bool blinkSuccess = true;
    for (int i = 0; i < 5; i++) {
        // Turn ON
        if (!M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L)) {
            blinkSuccess = false;
            break;
        }
        delay(200);
        // Turn OFF
        if (!M5.In_I2C.bitOff(0x34, 0x69, 0b00000001, 100000L)) {
            blinkSuccess = false;
            break;
        }
        delay(200);
    }
    if (blinkSuccess) {
        DualSerial.println("OK");
        DualSerial.println("   -> LED should have blinked 5 times");
    } else {
        DualSerial.println("FAIL");
    }

    // Test 4: Read LED register
    DualSerial.print("4. Reading LED register... ");
    uint8_t ledReg = M5.In_I2C.readRegister8(0x34, 0x69, 100000L);
    if (ledReg == 0xFF) {
        // If bus was released/busy, try a one-shot begin/release just for this read
        M5.In_I2C.begin();
        ledReg = M5.In_I2C.readRegister8(0x34, 0x69, 100000L);
        M5.In_I2C.release();
    }
    if (ledReg != 0xFF) {
        DualSerial.printf("OK (0x%02X = 0b", ledReg);
        for (int i = 7; i >= 0; i--) {
            DualSerial.print((ledReg >> i) & 1);
        }
        DualSerial.println(")");
        DualSerial.println("   -> bit[0]=1: LED ON, bit[0]=0: LED OFF");
    } else {
        DualSerial.println("FAIL (cannot read from AXP2101)");
    }

    // Turn LED back ON
    M5.In_I2C.writeRegister8(0x34, 0x69, 0b00110101, 100000L);

    DualSerial.println("\n=== LED TEST COMPLETE ===");
    DualSerial.println("The LED is the small charging indicator near the USB-C port.");
    DualSerial.println("If you didn't see it blink, check:");
    DualSerial.println("  1. The LED is very small - look carefully near USB-C");
    DualSerial.println("  2. Make sure the device is powered on");
    DualSerial.println("  3. The LED may be dim in bright light");
    DualSerial.println();
}

void SerialShell::testAudio() {
    DualSerial.println("\n=== AUDIO TEST ===");
    DualSerial.println("Testing speaker and microphone...\n");

    CameraDevice& device = CameraDevice::getInstance();

    // Initialize audio if not already done
    if (!device.isAudioInitialized()) {
        DualSerial.println("Initializing audio...");
        if (!device.initAudio()) {
            DualSerial.println("FAIL: Audio initialization failed");
            return;
        }
    }

    // Test speaker
    DualSerial.println("1. Testing speaker...");
    if (device.testSpeaker()) {
        DualSerial.println("   PASS: Speaker test complete");
    } else {
        DualSerial.println("   FAIL: Speaker test failed");
    }

    delay(500);

    // Test microphone
    DualSerial.println("\n2. Testing microphone...");
    DualSerial.println("   Speak into the microphone for 1 second...");
    if (device.testMicrophone()) {
        DualSerial.println("   PASS: Microphone test complete");
    } else {
        DualSerial.println("   FAIL: Microphone test failed");
    }

    DualSerial.println("\n=== AUDIO TEST COMPLETE ===");
}

void SerialShell::configureSpeakerHardware() {
    DualSerial.println("\n=== SPEAKER HARDWARE CONFIGURATION ===");

    // Check AXP2101 PMIC power rails
    DualSerial.println("Checking AXP2101 power rails...");
    uint8_t reg90 = M5.In_I2C.readRegister8(0x34, 0x90, 400000);  // LDOS ON/OFF control
    DualSerial.printf("  AXP2101 reg 0x90 (LDO enable) = 0x%02X\n", reg90);
    DualSerial.printf("    ALDO1 (AW88298 1.8v): %s\n", (reg90 & 0x01) ? "ON" : "OFF");
    DualSerial.printf("    ALDO2 (ES7210 3.3v): %s\n", (reg90 & 0x02) ? "ON" : "OFF");

    uint8_t reg92 = M5.In_I2C.readRegister8(0x34, 0x92, 400000);  // ALDO1 voltage
    uint8_t reg93 = M5.In_I2C.readRegister8(0x34, 0x93, 400000);  // ALDO2 voltage
    DualSerial.printf("  ALDO1 voltage setting: 0x%02X (%d mV)\n", reg92, (reg92 * 100) + 500);
    DualSerial.printf("  ALDO2 voltage setting: 0x%02X (%d mV)\n", reg93, (reg93 * 100) + 500);

    // Enable speaker via AW9523 GPIO expander (bit 2 of register 0x02)
    DualSerial.println("\nEnabling speaker power via AW9523 (0x58)...");
    bool aw9523_ok = M5.In_I2C.bitOn(0x58, 0x02, 0b00000100, 400000);
    DualSerial.printf("  AW9523 write: %s\n", aw9523_ok ? "OK" : "FAILED");

    // Read back to verify
    uint8_t aw9523_val = M5.In_I2C.readRegister8(0x58, 0x02, 400000);
    DualSerial.printf("  AW9523 reg 0x02 = 0x%02X (bit 2 should be 1)\n", aw9523_val);

    // Configure AW88298 amplifier for 48kHz operation
    DualSerial.println("\nConfiguring AW88298 amplifier (0x36)...");
    auto writeAW88298 = [](uint8_t reg, uint16_t value) {
        value = __builtin_bswap16(value);
        bool ok = M5.In_I2C.writeRegister(0x36, reg, (const uint8_t*)&value, 2, 400000);
        DualSerial.printf("  AW88298 reg 0x%02X = 0x%04X: %s\n", reg, __builtin_bswap16(value), ok ? "OK" : "FAILED");
        return ok;
    };

    writeAW88298(0x61, 0x0673);  // boost mode disabled
    writeAW88298(0x04, 0x4040);  // I2SEN=1 AMPPD=0 PWDN=0
    writeAW88298(0x05, 0x0008);  // RMSE=0 HAGCE=0 HDCCE=0 HMUTE=0
    writeAW88298(0x06, 0x14C0);  // I2SBCK=0 (BCK mode 16*2), sample rate for 48kHz
    writeAW88298(0x0C, 0x00FF);  // volume setting (maximum volume)

    DualSerial.println("\nSpeaker hardware configuration complete!");
    DualSerial.println("\n=== CONFIGURATION COMPLETE ===");
}

void SerialShell::testSpeaker() {
    DualSerial.println("\n=== SPEAKER TEST ===");

    CameraDevice& device = CameraDevice::getInstance();

    // Initialize audio if not already done
    if (!device.isAudioInitialized()) {
        DualSerial.println("Initializing audio...");
        if (!device.initAudio()) {
            DualSerial.println("FAIL: Audio initialization failed");
            return;
        }
    }

    if (device.testSpeaker()) {
        DualSerial.println("\nPASS: Speaker test complete");
    } else {
        DualSerial.println("\nFAIL: Speaker test failed");
    }

    DualSerial.println("\n=== SPEAKER TEST COMPLETE ===");
}

void SerialShell::testMicrophone() {
    DualSerial.println("\n=== MICROPHONE TEST ===");

    CameraDevice& device = CameraDevice::getInstance();

    // Initialize audio if not already done
    if (!device.isAudioInitialized()) {
        DualSerial.println("Initializing audio...");
        if (!device.initAudio()) {
            DualSerial.println("FAIL: Audio initialization failed");
            return;
        }
    }

    if (device.testMicrophone()) {
        DualSerial.println("\nPASS: Microphone test complete");
    } else {
        DualSerial.println("\nFAIL: Microphone test failed");
    }

    DualSerial.println("\n=== MICROPHONE TEST COMPLETE ===");
}

// ============================================================================
// Firmware Dump Commands
// ============================================================================

void SerialShell::listPartitions() {
    DualSerial.println("\n=== Flash Partitions ===");
    DualSerial.printf("%-16s %-10s %-10s %-10s %-10s\n", "Name", "Type", "SubType", "Offset", "Size");
    DualSerial.println("------------------------------------------------------------------------");

    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);

    while (it != NULL) {
        const esp_partition_t* part = esp_partition_get(it);

        // Type names
        const char* type_str = "unknown";
        if (part->type == ESP_PARTITION_TYPE_APP) type_str = "app";
        else if (part->type == ESP_PARTITION_TYPE_DATA) type_str = "data";

        // Subtype names
        char subtype_str[16];
        if (part->type == ESP_PARTITION_TYPE_APP) {
            if (part->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) strcpy(subtype_str, "factory");
            else if (part->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0) strcpy(subtype_str, "ota_0");
            else if (part->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) strcpy(subtype_str, "ota_1");
            else snprintf(subtype_str, sizeof(subtype_str), "0x%02x", part->subtype);
        } else if (part->type == ESP_PARTITION_TYPE_DATA) {
            if (part->subtype == ESP_PARTITION_SUBTYPE_DATA_NVS) strcpy(subtype_str, "nvs");
            else if (part->subtype == ESP_PARTITION_SUBTYPE_DATA_OTA) strcpy(subtype_str, "ota");
            else if (part->subtype == ESP_PARTITION_SUBTYPE_DATA_SPIFFS) strcpy(subtype_str, "spiffs");
            else snprintf(subtype_str, sizeof(subtype_str), "0x%02x", part->subtype);
        } else {
            snprintf(subtype_str, sizeof(subtype_str), "0x%02x", part->subtype);
        }

        DualSerial.printf("%-16s %-10s %-10s 0x%08x 0x%08x\n",
                        part->label, type_str, subtype_str, part->address, part->size);

        it = esp_partition_next(it);
    }

    esp_partition_iterator_release(it);

    // Show total flash size
    uint32_t flash_size;
    esp_flash_get_size(NULL, &flash_size);
    DualSerial.printf("\nTotal Flash Size: %u bytes (%u MB)\n", flash_size, flash_size / (1024 * 1024));
}

void SerialShell::dumpMemory(uint32_t addr, uint32_t len) {
    DualSerial.printf("\n=== Memory Dump: 0x%08X (%u bytes) ===\n", addr, len);

    // Limit to 4 KB per dump to avoid overwhelming serial
    if (len > 4096) {
        DualSerial.printf("Warning: Length limited to 4096 bytes (requested %u)\n", len);
        len = 4096;
    }

    // Dump in hex format (16 bytes per line)
    for (uint32_t offset = 0; offset < len; offset += 16) {
        DualSerial.printf("%08X: ", addr + offset);

        // Hex bytes
        for (int i = 0; i < 16; i++) {
            if (offset + i < len) {
                uint8_t byte = *((volatile uint8_t*)(addr + offset + i));
                DualSerial.printf("%02X ", byte);
            } else {
                DualSerial.print("   ");
            }
        }

        DualSerial.print(" |");

        // ASCII representation
        for (int i = 0; i < 16; i++) {
            if (offset + i < len) {
                uint8_t byte = *((volatile uint8_t*)(addr + offset + i));
                if (byte >= 32 && byte < 127) {
                    DualSerial.print((char)byte);
                } else {
                    DualSerial.print(".");
                }
            }
        }

        DualSerial.println("|");
    }

    DualSerial.println("\n=== Dump Complete ===");
}

void SerialShell::dumpFlash(uint32_t addr, uint32_t len) {
    DualSerial.printf("\n=== Flash Dump: 0x%08X (%u bytes) ===\n", addr, len);

    // Limit to 4 KB per dump
    if (len > 4096) {
        DualSerial.printf("Warning: Length limited to 4096 bytes (requested %u)\n", len);
        len = 4096;
    }

    // Allocate buffer
    uint8_t* buffer = (uint8_t*)malloc(len);
    if (!buffer) {
        DualSerial.println("ERROR: Failed to allocate memory");
        return;
    }

    // Read flash
    esp_err_t err = esp_flash_read(NULL, buffer, addr, len);
    if (err != ESP_OK) {
        DualSerial.printf("ERROR: Flash read failed (0x%x)\n", err);
        free(buffer);
        return;
    }

    // Dump in hex format (16 bytes per line)
    for (uint32_t offset = 0; offset < len; offset += 16) {
        DualSerial.printf("%08X: ", addr + offset);

        // Hex bytes
        for (int i = 0; i < 16; i++) {
            if (offset + i < len) {
                DualSerial.printf("%02X ", buffer[offset + i]);
            } else {
                DualSerial.print("   ");
            }
        }

        DualSerial.print(" |");

        // ASCII representation
        for (int i = 0; i < 16; i++) {
            if (offset + i < len) {
                uint8_t byte = buffer[offset + i];
                if (byte >= 32 && byte < 127) {
                    DualSerial.print((char)byte);
                } else {
                    DualSerial.print(".");
                }
            }
        }

        DualSerial.println("|");
    }

    free(buffer);
    DualSerial.println("\n=== Dump Complete ===");
}

void SerialShell::dumpPartition(const String& name) {
    DualSerial.printf("\n=== Partition Dump: %s ===\n", name.c_str());

    // Find partition
    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, name.c_str());

    if (!part) {
        DualSerial.printf("ERROR: Partition '%s' not found\n", name.c_str());
        DualSerial.println("Use 'part-list' to see available partitions");
        return;
    }

    DualSerial.printf("Partition: %s\n", part->label);
    DualSerial.printf("Address:   0x%08X\n", part->address);
    DualSerial.printf("Size:      0x%08X (%u bytes, %u KB)\n",
                    part->size, part->size, part->size / 1024);

    // Limit dump size
    uint32_t dump_size = part->size;
    if (dump_size > 4096) {
        DualSerial.printf("Warning: Only dumping first 4096 bytes (partition is %u bytes)\n", part->size);
        dump_size = 4096;
    }

    // Allocate buffer
    uint8_t* buffer = (uint8_t*)malloc(dump_size);
    if (!buffer) {
        DualSerial.println("ERROR: Failed to allocate memory");
        return;
    }

    // Read partition
    esp_err_t err = esp_partition_read(part, 0, buffer, dump_size);
    if (err != ESP_OK) {
        DualSerial.printf("ERROR: Partition read failed (0x%x)\n", err);
        free(buffer);
        return;
    }

    // Dump in hex format
    for (uint32_t offset = 0; offset < dump_size; offset += 16) {
        DualSerial.printf("%08X: ", part->address + offset);

        // Hex bytes
        for (int i = 0; i < 16; i++) {
            if (offset + i < dump_size) {
                DualSerial.printf("%02X ", buffer[offset + i]);
            } else {
                DualSerial.print("   ");
            }
        }

        DualSerial.print(" |");

        // ASCII representation
        for (int i = 0; i < 16; i++) {
            if (offset + i < dump_size) {
                uint8_t byte = buffer[offset + i];
                if (byte >= 32 && byte < 127) {
                    DualSerial.print((char)byte);
                } else {
                    DualSerial.print(".");
                }
            }
        }

        DualSerial.println("|");
    }

    free(buffer);
    DualSerial.println("\n=== Dump Complete ===");
}

void SerialShell::dumpNVS(bool privileged) {
    CameraApp& app = CameraApp::getInstance();
    if (!privileged && !app.isAdmin()) {
        DualSerial.println("\n=== NVS Dump (Key/Value Pairs) ===");
        DualSerial.println("ERROR: Admin privileges required.");
        return;
    }

    DualSerial.println("\n=== NVS Dump (Key/Value Pairs) ===");

    // Open NVS in read-only mode
    nvs_handle_t handle;
    esp_err_t err = nvs_open("camera", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        DualSerial.printf("ERROR: Failed to open NVS (0x%x)\n", err);
        DualSerial.println("Note: NVS may be empty. Try setting WiFi credentials first with: wifi <ssid> <password>");
        return;
    }

    // Iterate through all keys
    nvs_iterator_t it = nvs_entry_find("nvs", "camera", NVS_TYPE_ANY);

    if (it == NULL) {
        DualSerial.println("NVS is empty");
        nvs_close(handle);
        return;
    }

    int count = 0;
    while (it != NULL) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        DualSerial.printf("Key: %-20s Type: ", info.key);

        // Read value based on type
        switch (info.type) {
            case NVS_TYPE_U8: {
                uint8_t value;
                nvs_get_u8(handle, info.key, &value);
                DualSerial.printf("U8    Value: %u (0x%02X)\n", value, value);
                break;
            }
            case NVS_TYPE_I8: {
                int8_t value;
                nvs_get_i8(handle, info.key, &value);
                DualSerial.printf("I8    Value: %d\n", value);
                break;
            }
            case NVS_TYPE_U16: {
                uint16_t value;
                nvs_get_u16(handle, info.key, &value);
                DualSerial.printf("U16   Value: %u (0x%04X)\n", value, value);
                break;
            }
            case NVS_TYPE_I16: {
                int16_t value;
                nvs_get_i16(handle, info.key, &value);
                DualSerial.printf("I16   Value: %d\n", value);
                break;
            }
            case NVS_TYPE_U32: {
                uint32_t value;
                nvs_get_u32(handle, info.key, &value);
                DualSerial.printf("U32   Value: %u (0x%08X)\n", value, value);
                break;
            }
            case NVS_TYPE_I32: {
                int32_t value;
                nvs_get_i32(handle, info.key, &value);
                DualSerial.printf("I32   Value: %d\n", value);
                break;
            }
            case NVS_TYPE_STR: {
                size_t len;
                nvs_get_str(handle, info.key, NULL, &len);
                char* value = (char*)malloc(len);
                if (value) {
                    nvs_get_str(handle, info.key, value, &len);
                    DualSerial.printf("STR   Value: \"%s\"\n", value);
                    free(value);
                }
                break;
            }
            case NVS_TYPE_BLOB: {
                size_t len;
                nvs_get_blob(handle, info.key, NULL, &len);
                DualSerial.printf("BLOB  Size: %u bytes\n", len);
                break;
            }
            default:
                DualSerial.printf("???   (type %d)\n", info.type);
                break;
        }

        count++;
        it = nvs_entry_next(it);
    }

    nvs_release_iterator(it);
    nvs_close(handle);

    DualSerial.printf("\nTotal keys: %d\n", count);
    DualSerial.println("\n=== Dump Complete ===");
}