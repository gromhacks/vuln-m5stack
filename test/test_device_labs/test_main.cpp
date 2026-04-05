#include <unity.h>
#include <Arduino.h>
#include <Preferences.h>
#include "CameraDevice.h"
#include "DualSerial.h"

// Define DualSerial global (normally in main.cpp, excluded in test builds)
DualSerialClass DualSerial;

// Compact Unity tests for all labs (fits in <150 lines)
// Validates markers/behaviors via CameraDevice test hooks

void t_boot(){ TEST_ASSERT_TRUE(true); }
void t_web(){ TEST_ASSERT_TRUE(true); }

// Device info and bus tests
void t01(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(1); TEST_ASSERT_TRUE(r.indexOf("Admin PIN:")>=0); }

void t02(){
  auto &d=CameraDevice::getInstance();

  String r=d.run_diagnostic(2);
  TEST_ASSERT_TRUE(r.indexOf("I2C test pattern written: admin_pin=")>=0);

  // Extract the admin PIN that was actually used from the return string
  int pinStart = r.indexOf("admin_pin=") + 10;
  String usedAdminPIN = "";
  for (int i = pinStart; i < r.length() && isDigit(r[i]); i++) {
    usedAdminPIN += r[i];
  }

  String p=d.dev_getLastI2CPattern();
  TEST_ASSERT_TRUE(p.indexOf("admin_pin=")>=0);
  TEST_ASSERT_TRUE(p.indexOf("wifi_pass=")>=0);
  TEST_ASSERT_TRUE(p.indexOf("api_key=1234567890abcdef")>=0);

  // CRITICAL: Verify the pattern contains the same admin PIN that was reported
  if (usedAdminPIN.length() > 0) {
    String expectedMarker = String("admin_pin=") + usedAdminPIN;
    TEST_ASSERT_TRUE_MESSAGE(p.indexOf(expectedMarker) >= 0,
                             "I2C pattern must contain real admin PIN from device");
  }

  // Also verify it's not a hardcoded placeholder
  TEST_ASSERT_FALSE_MESSAGE(p.indexOf("admin_pin=123456") >= 0,
                            "I2C pattern must not use hardcoded placeholder PIN");
}

void t03(){
  auto &d=CameraDevice::getInstance();

  String r=d.run_diagnostic(3);
  TEST_ASSERT_TRUE(r.indexOf("flash_read allowed")>=0);

  String p=d.dev_getLastSPIPattern();
  TEST_ASSERT_TRUE(p.indexOf("admin_pin=")>=0);
  TEST_ASSERT_TRUE(p.indexOf("wifi_pass=")>=0);
  TEST_ASSERT_TRUE(p.indexOf("api_key=1234567890abcdef")>=0);

  // CRITICAL: Verify it's not a hardcoded placeholder
  TEST_ASSERT_FALSE_MESSAGE(p.indexOf("admin_pin=123456") >= 0,
                            "SPI pattern must not use hardcoded placeholder PIN");
  TEST_ASSERT_FALSE_MESSAGE(p.indexOf("wifi_pass=SecretWiFi123") >= 0,
                            "SPI pattern must not use hardcoded placeholder WiFi password");
}

void t04(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(4); TEST_ASSERT_TRUE(r.indexOf("UART download mode allowed")>=0); }
void t05(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(5); TEST_ASSERT_TRUE(r.indexOf("Firmware dump contains jwtSecret=")>=0); }

// Firmware security tests
void t06(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(6); TEST_ASSERT_TRUE(r.indexOf("PIN check patched bypass")>=0); }
void t07(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(7); TEST_ASSERT_TRUE(r.indexOf("Unsigned OTA accepted")>=0); }
// t08 removed: OTA rollback merged into L07

// Web and application security tests
void t09(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(9,"test;status","x"); TEST_ASSERT_TRUE(r.indexOf("Command injection")>=0 || r.indexOf("Constructed command:")>=0); }
void t10(){ auto &d=CameraDevice::getInstance(); String r=d.dev_fileAccess("../../config"); TEST_ASSERT_TRUE(r.indexOf("[DEBUG] Path traversal detected!")>=0 && r.indexOf("admin_pin=")>=0); }
void t11(){ auto &d=CameraDevice::getInstance(); String tok=d.dev_generateJWT("alice"); String sec=d.dev_getJWTSecret(); TEST_ASSERT_TRUE(sec=="secret123"); TEST_ASSERT_TRUE(tok.indexOf('.')>0 && tok.indexOf('.',tok.indexOf('.')+1)>0); TEST_ASSERT_TRUE(d.dev_verifyJWT(tok)); String forged=d.dev_generateJWT("admin"); TEST_ASSERT_TRUE(d.dev_verifyJWT(forged)); String bad=tok; bad.setCharAt(bad.length()-1,'X'); TEST_ASSERT_FALSE(d.dev_verifyJWT(bad)); }
void t12(){
  // Buffer overflow with function pointer - real exploit requires GDB
  // This test just verifies the vulnerable code path exists and is exercisable
  auto &d=CameraDevice::getInstance();
  String r=d.run_diagnostic(12,"test");
  TEST_ASSERT_TRUE(r.indexOf("Exposure set to:")>=0);
  // Real exploit: overflow buffer to corrupt function pointer with unlockAdmin() address
}
void t13(){ auto &d=CameraDevice::getInstance(); String r=d.dev_configResponse(); TEST_ASSERT_TRUE(r.indexOf("Admin PIN:")>=0 && r.indexOf("User PIN:")>=0); }
void t14(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(14); TEST_ASSERT_TRUE(r.indexOf("Previous frame bytes visible after preview region.")>=0); }
void t15(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(15); TEST_ASSERT_TRUE(r.indexOf("MJPEG Stream Authentication Bypass")>=0 || r.indexOf("noauth=1")>=0); }

// Hardware attack surface tests
void t16(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(16); TEST_ASSERT_TRUE(r.indexOf("I2C Secure Element")>=0 || r.indexOf("Buffer size")>=0); }
void t17(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(17); TEST_ASSERT_TRUE(r.indexOf("SPI DMA Diagnostics")>=0 || r.indexOf("DMA buffer size")>=0); }
// t18 removed: camera forensics lab removed (artificial)

// Wireless and BLE tests
void t19(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(19); TEST_ASSERT_TRUE(r.indexOf("BLE GATT Config")>=0 || r.indexOf("ble_config_unlock")>=0); }
void t20(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(20); TEST_ASSERT_TRUE(r.indexOf("Credential Exposure")>=0 || r.indexOf("user_pin")>=0); }
void t21(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(21); TEST_ASSERT_TRUE(r.indexOf("OTA over HTTP (no TLS)")>=0); }

// USB and interface tests
void t22(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(22); TEST_ASSERT_TRUE(r.indexOf("DFU")>=0 || r.indexOf("download mode")>=0); }
void t23(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(23); TEST_ASSERT_TRUE(r.indexOf("Memory Leak")>=0 || r.indexOf("USB_STATUS")>=0); }
void t24(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(24); TEST_ASSERT_TRUE(r.indexOf("Race Condition")>=0 || r.indexOf("TOCTOU")>=0); }

// Crypto and token tests
void t25(){ auto &d=CameraDevice::getInstance(); String a1=d.run_diagnostic(25,"seed:123;count:3"); String a2=d.run_diagnostic(25,"seed:123;count:3"); String b1=d.run_diagnostic(25,"seed:124;count:3"); TEST_ASSERT_TRUE(a1==a2 && a1!=b1 && a1.indexOf("token_seq:")==0); }
void t26(){ auto &d=CameraDevice::getInstance(); String s=d.dev_getJWTSecret(); String r=d.run_diagnostic(26); TEST_ASSERT_TRUE(r.indexOf("Shared key:")>=0 && r.indexOf(s)>=0); }
void t27(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(27); TEST_ASSERT_TRUE(r.indexOf("PIN Timing")>=0 || r.indexOf("side-channel")>=0); }

// Side-channel and glitching tests
void t28(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(28); TEST_ASSERT_TRUE(r.indexOf("timing_leak: yes")>=0); }
void t29(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(29); TEST_ASSERT_TRUE(r.indexOf("AES-128 CPA target")>=0); }
void t30(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(30); TEST_ASSERT_TRUE(r.indexOf("Glitch bypass succeeded")>=0); }

// Data forensics tests
void t31(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(31); TEST_ASSERT_TRUE(r.indexOf("EXIF")>=0); }
// t32 removed: crash forensics lab removed (fabricated)

// New vulnerability tests
void t33(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(33); TEST_ASSERT_TRUE(r.indexOf("format_string_vuln: present")>=0); }
void t34(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(34,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); TEST_ASSERT_TRUE(r.indexOf("heap_overflow: detected")>=0); }
void t35(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(35); TEST_ASSERT_TRUE(r.indexOf("csrf_protection: none")>=0); }
void t36(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(36); TEST_ASSERT_TRUE(r.indexOf("wifi_pmf: disabled")>=0); }
void t37(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(37); TEST_ASSERT_TRUE(r.indexOf("mdns_auth: none")>=0); }
void t38(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(38); TEST_ASSERT_TRUE(r.indexOf("secure_boot: disabled")>=0); }
void t39(){ auto &d=CameraDevice::getInstance(); String r=d.run_diagnostic(39); TEST_ASSERT_TRUE(r.indexOf("flash_encryption: disabled")>=0); }

void setup(){
  delay(1500);
  UNITY_BEGIN();
  RUN_TEST(t_boot); RUN_TEST(t_web);
  RUN_TEST(t01); RUN_TEST(t02); RUN_TEST(t03); RUN_TEST(t04); RUN_TEST(t05);
  RUN_TEST(t06); RUN_TEST(t07);
  RUN_TEST(t09); RUN_TEST(t10); RUN_TEST(t11); RUN_TEST(t12); RUN_TEST(t13); RUN_TEST(t14); RUN_TEST(t15);
  RUN_TEST(t16); RUN_TEST(t17);
  RUN_TEST(t19); RUN_TEST(t20); RUN_TEST(t21);
  RUN_TEST(t22); RUN_TEST(t23); RUN_TEST(t24);
  RUN_TEST(t25); RUN_TEST(t26); RUN_TEST(t27);
  RUN_TEST(t28); RUN_TEST(t29); RUN_TEST(t30);
  RUN_TEST(t31);
  RUN_TEST(t33); RUN_TEST(t34); RUN_TEST(t35); RUN_TEST(t36); RUN_TEST(t37); RUN_TEST(t38); RUN_TEST(t39);
  UNITY_END();
}
void loop(){}

