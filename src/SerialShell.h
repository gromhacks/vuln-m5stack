/**
 * @file SerialShell.h
 * @brief UART command-line interface with user and admin access tiers
 *
 * Provides an interactive serial console over USB CDC (and mirrored to the
 * debug UART on the expansion header). Commands are organized into tiers:
 *
 * - **User commands** (no login required): help, status, self-test, nvs-list, etc.
 * - **Admin commands** (require `login <admin_pin>`): wifi, nvs-clear, nvs-dump,
 *   memdump, flashdump, partdump, usb-cmd, usb-dfu, bus-diag, forensics-snap, etc.
 * - **Hidden commands** (not in help, discoverable via firmware RE): usb-memleak,
 *   usb-auth, heap-test, pin-test.
 * - **Debug commands** (DEV_TEST_HOOKS builds only): diag, fmt-check, csrf-check, etc.
 *
 * The shell reads one character at a time from DualSerial, echoing input and
 * processing complete lines. Commands dispatched from the web handler context
 * (e.g., command injection via /apply) run with the `privileged` flag set.
 */

#ifndef SERIAL_SHELL_H
#define SERIAL_SHELL_H

#include <Arduino.h>
#include <WiFi.h>
#include <Preferences.h>
#include "CameraApp.h"
#include "CameraDevice.h"

class SerialShell {
    friend void usbCmdWorker(void* pvParams);
public:
    static SerialShell& getInstance();

    void init();
    void loop();
    void processCommand(const String& cmd, bool privileged = false);
    void runSelfTest();  // Public so HTTP UI can call it

private:
    SerialShell() : commandBuffer("") {}
    String commandBuffer;

    void printHelp();
    void printStatus();
    void testCamera();
    void testWiFi();
    void testPIN(const String& pin);
    void resetDevice();
    void setWiFi(const String& ssid, const String& pass);
    void listNVS();
    void clearNVS();
    void runDiag(int diagId, const String& p1 = "");
    void testLED();
    void testAudio();
    void testSpeaker();
    void testMicrophone();
    void configureSpeakerHardware();

    // USB interface helpers
    void usbAuth(const String& password);
    void usbCommand(const String& cmd);
    void usbMemLeak();
    void usbDFU(uint32_t size);

    // Firmware dump commands (UART only)
    void dumpMemory(uint32_t addr, uint32_t len);
    void dumpFlash(uint32_t addr, uint32_t len);
    void dumpPartition(const String& name);
    void dumpNVS(bool privileged = false);
    void listPartitions();
};

#endif

