/**
 * @file CameraDevice_Auth.cpp
 * @brief JWT token generation/verification, PIN management, and NVS settings
 *
 * JWT tokens use HMAC-SHA256 (HS256) with base64url encoding per RFC 7519.
 * PINs are 6-digit numeric strings generated from esp_random() and persisted
 * in the "camera" NVS namespace. The admin PIN is auto-generated on first boot
 * and never displayed on the web UI (only accessible via serial or NVS dump).
 */

#include "CameraDevice.h"
#include <ArduinoJson.h>
#include <Preferences.h>
#include <esp_random.h>
#include <mbedtls/md.h>
#include "DualSerial.h"

// RFC 4648 base64 alphabet (standard, not URL-safe - converted after encoding)
const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64url encode (RFC 4648 Section 5): replaces +/ with -_, strips padding.
// Used for JWT header, payload, and signature encoding.
String base64UrlEncode(const uint8_t* data, size_t len) {
    String encoded = "";
    int i = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (int j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];
    }

    // Convert to base64url: replace + with -, / with _, remove padding =
    encoded.replace('+', '-');
    encoded.replace('/', '_');
    while (encoded.endsWith("=")) {
        encoded.remove(encoded.length() - 1);
    }
    return encoded;
}

// Base64url decode: converts -_ back to +/, adds padding, then decodes.
String base64UrlDecode(const String& input) {
    String data = input;
    // Convert from base64url to base64
    data.replace('-', '+');
    data.replace('_', '/');
    // Add padding
    while (data.length() % 4 != 0) {
        data += '=';
    }

    // Decode base64
    String decoded = "";
    int i = 0;
    uint8_t char_array_4[4], char_array_3[3];
    int in_len = data.length();
    int in_ = 0;

    while (in_len-- && data[in_] != '=') {
        char c = data[in_++];
        int val = 0;
        if (c >= 'A' && c <= 'Z') val = c - 'A';
        else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
        else if (c >= '0' && c <= '9') val = c - '0' + 52;
        else if (c == '+') val = 62;
        else if (c == '/') val = 63;
        else continue;

        char_array_4[i++] = val;
        if (i == 4) {
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded += (char)char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (int j = i; j < 4; j++)
            char_array_4[j] = 0;

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (int j = 0; j < i - 1; j++)
            decoded += (char)char_array_3[j];
    }

    return decoded;
}

// Compute HMAC-SHA256 over `data` using `key`, return base64url-encoded digest.
// Uses mbedTLS (bundled with ESP-IDF) for the cryptographic operation.
String hmacSha256(const String& data, const String& key) {
    uint8_t hmac_result[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key.c_str(), key.length());
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)data.c_str(), data.length());
    mbedtls_md_hmac_finish(&ctx, hmac_result);
    mbedtls_md_free(&ctx);

    return base64UrlEncode(hmac_result, 32);
}

// Generate a JWT for the given user. Defaults to "user" role.
String CameraDevice::generateJWT(const String& username) {
    return generateJWT(username, "user");
}

// Generate a JWT with explicit role claim. Token format: header.payload.signature
// where header = {"alg":"HS256","typ":"JWT"}, payload includes user, role, and exp.
String CameraDevice::generateJWT(const String& username, const String& role) {
    #ifdef FACTORY_TEST
    // JWT format with HS256 signing
    String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    String payload = String("{\"user\":\"") + username + String("\",\"role\":\"") + role +
                     String("\",\"exp\":") + String(millis() + 3600000) + String("}");

    // Base64url encode header and payload
    String encodedHeader = base64UrlEncode((const uint8_t*)header.c_str(), header.length());
    String encodedPayload = base64UrlEncode((const uint8_t*)payload.c_str(), payload.length());

    // Create signature using HMAC-SHA256 with weak secret
    String signatureInput = encodedHeader + "." + encodedPayload;
    String signature = hmacSha256(signatureInput, jwtSecret);

    // Return proper JWT: header.payload.signature
    String token = encodedHeader + "." + encodedPayload + "." + signature;
    return token;
    #else
    // Hardened: Use strong per-device secret
    // ... (not implemented in this build)
    return "";
    #endif
}


// Verify a JWT by recomputing the HMAC-SHA256 signature and comparing.
// Does NOT check expiration (exp claim) - tokens are valid until device reboot.
bool CameraDevice::verifyJWT(const String& token) {
    #ifdef FACTORY_TEST
    // Parse token parts
    int dot1 = token.indexOf('.');
    if (dot1 < 0) return false;
    int dot2 = token.indexOf('.', dot1 + 1);
    if (dot2 < 0) return false;

    String encodedHeader = token.substring(0, dot1);
    String encodedPayload = token.substring(dot1 + 1, dot2);
    String providedSignature = token.substring(dot2 + 1);

    // Recompute signature
    String signatureInput = encodedHeader + "." + encodedPayload;
    String expectedSignature = hmacSha256(signatureInput, jwtSecret);

    // Verify signature matches
    return (providedSignature == expectedSignature);
    #else
    return false;
    #endif
}

// Parse base64url-encoded JWT payload to extract user/role claims
bool CameraDevice::extractClaims(const String& token, String& user, String& role) {
    int dot1 = token.indexOf('.');
    if (dot1 < 0) return false;
    int dot2 = token.indexOf('.', dot1 + 1);
    if (dot2 < 0) return false;

    String encodedPayload = token.substring(dot1 + 1, dot2);
    String payload = base64UrlDecode(encodedPayload);

    StaticJsonDocument<256> doc;
    DeserializationError err = deserializeJson(doc, payload);
    if (err) return false;
    const char* u = doc["user"] | "";
    const char* r = doc["role"] | "";
    user = String(u);
    role = String(r);
    return true;
}

// Verify user PIN. Returns true on exact match.
// NOTE: Non-constant time comparison
bool CameraDevice::checkPIN(const String& pin) {
    #ifdef FACTORY_TEST
    // Character-by-character PIN comparison
    if (pin.length() != userPIN.length()) {
        return false;
    }
    for (size_t i = 0; i < pin.length(); i++) {
        if (pin[i] != userPIN[i]) {
            return false;
        }
        delayMicroseconds(100);  // Timing leak
    }
    return true;
    #else
    // Secure version - constant time comparison
    return pin == userPIN;
    #endif
}

// Generate a random 6-digit numeric PIN using hardware RNG and persist to NVS.
void CameraDevice::generateUserPIN() {
    char pin[7];
    for (int i = 0; i < 6; i++) {
        pin[i] = '0' + (esp_random() % 10);
    }
    pin[6] = '\0';
    userPIN = String(pin);
    saveSettings();
}

String CameraDevice::getUserPIN() {
    return userPIN;
}

void CameraDevice::setAdminPIN(const String& pin) {
    adminPIN = pin;
    saveSettings();
}

bool CameraDevice::isAdminMode() {
    return adminMode;
}

void CameraDevice::setAdminMode(bool enabled) {
    adminMode = enabled;
}

void CameraDevice::saveSettings() {
    prefs.begin("camera", false);
    prefs.putString("user_pin", userPIN);
    prefs.putString("admin_pin", adminPIN);
    prefs.putBool("debug_mode", debugMode);
    prefs.end();
}

void CameraDevice::loadSettings() {
    prefs.begin("camera", true);
    userPIN = prefs.getString("user_pin", "");
    adminPIN = prefs.getString("admin_pin", "");
    debugMode = prefs.getBool("debug_mode", false);
    prefs.end();

    // Generate a strong default Admin PIN on first boot (no weak defaults)
    if (adminPIN.length() == 0) {
        char pin[7];
        for (int i = 0; i < 6; i++) {
            pin[i] = '0' + (esp_random() % 10);
        }
        pin[6] = '\0';
        adminPIN = String(pin);
        saveSettings();
    }
}

bool CameraDevice::getDebugMode() {
    return debugMode;
}

void CameraDevice::setDebugMode(bool enabled) {
    debugMode = enabled;
    saveSettings();
}

String CameraDevice::getDeviceID() {
    return deviceID;
}

String CameraDevice::getFirmwareVersion() {
    return "1.0.0";
}
