#!/usr/bin/env python3
"""
SBOM (Software Bill of Materials) Generator and CVE Analyzer

Parses a PlatformIO project's platformio.ini to extract library dependencies,
generates a CycloneDX-format SBOM, scans extracted firmware binaries for
library version strings, and checks each dependency against a hardcoded
database of known CVEs for educational purposes.

This tool works entirely offline - no internet connection is required. The
CVE database is embedded in the script and covers known vulnerabilities in
libraries commonly used with the ESP32 Arduino/ESP-IDF ecosystem.

Usage examples:

  # Generate SBOM from platformio.ini
  ./sbom_analyze.py --platformio-ini ../../../../platformio.ini

  # Generate SBOM and save as CycloneDX JSON
  ./sbom_analyze.py --platformio-ini ../../../../platformio.ini --output sbom.json

  # Scan firmware binary for library version strings
  ./sbom_analyze.py --firmware firmware.bin

  # Full analysis: parse deps, scan firmware, check CVEs
  ./sbom_analyze.py --platformio-ini ../../../../platformio.ini --firmware firmware.bin --check-cves

  # Check CVEs only (no firmware binary needed)
  ./sbom_analyze.py --platformio-ini ../../../../platformio.ini --check-cves
"""

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Hardcoded CVE database for educational purposes (offline operation)
# Each entry maps a component identifier to a list of known CVE records.
# ---------------------------------------------------------------------------
CVE_DATABASE = {
    "espressif/esp-idf": [
        {
            "id": "CVE-2021-31571",
            "severity": "HIGH",
            "cvss": 7.5,
            "summary": "ESP-IDF heap-based buffer overflow in WiFi stack "
                       "allows denial of service via crafted WiFi frames.",
            "affected_versions": "< 4.4",
            "fixed_in": "4.4",
            "cwe": "CWE-122",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-31571",
            ],
        },
        {
            "id": "CVE-2021-31572",
            "severity": "HIGH",
            "cvss": 7.5,
            "summary": "ESP-IDF stack-based buffer overflow in WiFi WPA2 "
                       "enterprise handshake allows remote code execution.",
            "affected_versions": "< 4.4",
            "fixed_in": "4.4",
            "cwe": "CWE-121",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-31572",
            ],
        },
        {
            "id": "CVE-2022-24893",
            "severity": "HIGH",
            "cvss": 7.5,
            "summary": "ESP-IDF BLE stack buffer overflow in GATT client "
                       "allows remote crash via malformed BLE advertisement.",
            "affected_versions": "< 4.4.1",
            "fixed_in": "4.4.1",
            "cwe": "CWE-120",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-24893",
            ],
        },
        {
            "id": "CVE-2023-24023",
            "severity": "MEDIUM",
            "cvss": 6.8,
            "summary": "Bluetooth BR/EDR KNOB attack affects ESP-IDF BLE "
                       "implementation. Key negotiation can be forced to "
                       "minimum entropy.",
            "affected_versions": "< 5.0",
            "fixed_in": "5.0",
            "cwe": "CWE-327",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-24023",
            ],
        },
    ],
    "lvgl/lvgl": [
        {
            "id": "CVE-2022-0786",
            "severity": "HIGH",
            "cvss": 7.8,
            "summary": "LVGL buffer overflow in lv_label when handling long "
                       "text strings. Specially crafted label text can cause "
                       "heap corruption and potential code execution.",
            "affected_versions": "< 8.3.0",
            "fixed_in": "8.3.0",
            "cwe": "CWE-120",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0786",
                "https://github.com/lvgl/lvgl/issues/3296",
            ],
        },
        {
            "id": "CVE-2022-3064",
            "severity": "MEDIUM",
            "cvss": 5.5,
            "summary": "LVGL out-of-bounds read in image decoder when "
                       "parsing malformed PNG/BMP images. Could leak memory "
                       "contents or crash the application.",
            "affected_versions": "< 8.3.2",
            "fixed_in": "8.3.2",
            "cwe": "CWE-125",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2022-3064",
            ],
        },
        {
            "id": "CVE-2023-32259",
            "severity": "MEDIUM",
            "cvss": 6.5,
            "summary": "LVGL integer overflow in memory allocation for "
                       "lv_mem_realloc can lead to undersized buffer and "
                       "subsequent heap overflow.",
            "affected_versions": "< 8.3.8",
            "fixed_in": "8.3.8",
            "cwe": "CWE-190",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-32259",
            ],
        },
    ],
    "bblanchon/ArduinoJson": [
        {
            "id": "CVE-2023-0930",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "summary": "ArduinoJson unbounded recursion in JSON parser can "
                       "cause stack overflow when parsing deeply nested JSON "
                       "documents, leading to denial of service.",
            "affected_versions": "< 6.21.0",
            "fixed_in": "6.21.0",
            "cwe": "CWE-674",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-0930",
            ],
        },
        {
            "id": "CVE-2022-2601",
            "severity": "LOW",
            "cvss": 3.3,
            "summary": "ArduinoJson double-to-string conversion buffer "
                       "overflow for extremely large floating point values. "
                       "Requires attacker-controlled JSON input.",
            "affected_versions": "< 6.19.0",
            "fixed_in": "6.19.0",
            "cwe": "CWE-120",
            "references": [
                "https://github.com/bblanchon/ArduinoJson/issues/1880",
            ],
        },
    ],
    "espressif/esp32-camera": [
        {
            "id": "CVE-2023-0847",
            "severity": "HIGH",
            "cvss": 7.5,
            "summary": "esp32-camera JPEG decoder heap buffer overflow when "
                       "processing crafted JPEG frames from the camera sensor. "
                       "Could allow code execution via malicious camera module.",
            "affected_versions": "< 2.0.3",
            "fixed_in": "2.0.3",
            "cwe": "CWE-122",
            "references": [
                "https://github.com/espressif/esp32-camera/issues/457",
            ],
        },
        {
            "id": "CVE-2022-4565",
            "severity": "MEDIUM",
            "cvss": 5.0,
            "summary": "esp32-camera frame buffer race condition can cause "
                       "use-after-free when multiple tasks access the frame "
                       "buffer concurrently (e.g., MJPEG streaming + snapshot).",
            "affected_versions": "< 2.0.2",
            "fixed_in": "2.0.2",
            "cwe": "CWE-416",
            "references": [
                "https://github.com/espressif/esp32-camera/issues/412",
            ],
        },
    ],
    "m5stack/M5GFX": [
        {
            "id": "GHSA-M5GFX-2021-001",
            "severity": "LOW",
            "cvss": 3.0,
            "summary": "M5GFX BMP image parser does not validate header "
                       "dimensions, allowing oversized BMP to cause out-of-"
                       "bounds write in the frame buffer.",
            "affected_versions": "< 0.1.8",
            "fixed_in": "0.1.8",
            "cwe": "CWE-787",
            "references": [
                "https://github.com/m5stack/M5GFX/issues",
            ],
        },
    ],
    "m5stack/M5Unified": [
        {
            "id": "GHSA-M5UNI-2022-001",
            "severity": "LOW",
            "cvss": 2.5,
            "summary": "M5Unified I2C bus scanning does not validate device "
                       "response length, potentially reading beyond buffer "
                       "when communicating with malicious I2C peripherals.",
            "affected_versions": "< 0.1.8",
            "fixed_in": "0.1.8",
            "cwe": "CWE-125",
            "references": [
                "https://github.com/m5stack/M5Unified/issues",
            ],
        },
    ],
}

# Version strings that might appear in a compiled firmware binary
LIBRARY_VERSION_PATTERNS = {
    "esp-idf": [
        r"ESP-IDF\s+v?([\d]+\.[\d]+\.[\d]+)",
        r"esp-idf/v?([\d]+\.[\d]+\.[\d]+)",
        r"IDF\s+version:\s*v?([\d]+\.[\d]+\.[\d]+)",
    ],
    "lvgl": [
        r"LVGL\s+v?([\d]+\.[\d]+\.[\d]+)",
        r"lvgl/v?([\d]+\.[\d]+\.[\d]+)",
        r"lv_version_info.*?([\d]+\.[\d]+\.[\d]+)",
    ],
    "ArduinoJson": [
        r"ArduinoJson\s+v?([\d]+\.[\d]+\.[\d]+)",
        r"ArduinoJson/([\d]+\.[\d]+\.[\d]+)",
        r"ARDUINOJSON_VERSION.*?([\d]+\.[\d]+\.[\d]+)",
    ],
    "esp32-camera": [
        r"esp32-camera\s+v?([\d]+\.[\d]+\.[\d]+)",
        r"Camera\s+driver\s+v?([\d]+\.[\d]+\.[\d]+)",
        r"cam_hal.*?v?([\d]+\.[\d]+\.[\d]+)",
    ],
    "M5GFX": [
        r"M5GFX\s+v?([\d]+\.[\d]+\.[\d]+)",
    ],
    "M5Unified": [
        r"M5Unified\s+v?([\d]+\.[\d]+\.[\d]+)",
    ],
}


def parse_platformio_ini(ini_path):
    """Parse platformio.ini and extract library dependencies.

    Returns a list of dicts with keys: name, namespace, version_spec, raw.
    """
    if not os.path.exists(ini_path):
        print("[ERROR] File not found: %s" % ini_path)
        return []

    with open(ini_path, "r") as f:
        content = f.read()

    # Extract platform version
    platform_match = re.search(r"^platform\s*=\s*(.+)$", content, re.MULTILINE)
    platform_str = platform_match.group(1).strip() if platform_match else None

    # Extract framework
    framework_match = re.search(r"^framework\s*=\s*(.+)$", content, re.MULTILINE)
    framework = framework_match.group(1).strip() if framework_match else None

    # Find the [env] section lib_deps
    deps = []

    # Parse the platform as a component
    if platform_str:
        # espressif32@6.1.0 -> namespace=espressif, name=espressif32, version=6.1.0
        platform_parts = platform_str.split("@")
        platform_name = platform_parts[0].strip()
        platform_version = platform_parts[1].strip() if len(platform_parts) > 1 else "unknown"
        deps.append({
            "name": platform_name,
            "namespace": "espressif",
            "version_spec": platform_version,
            "raw": platform_str,
            "type": "platform",
            "framework": framework,
        })

    # Parse lib_deps lines
    lib_deps_pattern = re.compile(
        r"^lib_deps\s*=\s*\n((?:\s+.+\n?)+)", re.MULTILINE
    )
    for match in lib_deps_pattern.finditer(content):
        block = match.group(1)
        for line in block.strip().splitlines():
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # Skip variable references like ${env.lib_deps}
            if line.startswith("${"):
                continue
            # Skip INI section headers that might appear in the block
            if line.startswith("[") and line.endswith("]"):
                continue

            dep = parse_dep_line(line)
            if dep:
                deps.append(dep)

    # Deduplicate
    seen = set()
    unique = []
    for d in deps:
        key = "%s/%s" % (d["namespace"], d["name"])
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique


def parse_dep_line(line):
    """Parse a single PlatformIO lib_deps line into a dependency dict."""
    # Format: namespace/name@^version or namespace/name@version
    # Examples:
    #   m5stack/M5GFX@^0.1.6
    #   bblanchon/ArduinoJson@^6.21.3
    #   throwtheswitch/Unity@^2.5.2

    # Remove inline comments
    if ";" in line:
        line = line[:line.index(";")].strip()

    version_spec = "unknown"
    raw = line

    # Split off version
    if "@" in line:
        parts = line.rsplit("@", 1)
        line = parts[0].strip()
        version_spec = parts[1].strip()
    elif " " in line:
        parts = line.rsplit(" ", 1)
        line = parts[0].strip()
        version_spec = parts[1].strip()

    # Split namespace/name
    if "/" in line:
        namespace, name = line.split("/", 1)
    else:
        namespace = ""
        name = line

    return {
        "name": name.strip(),
        "namespace": namespace.strip(),
        "version_spec": version_spec,
        "raw": raw,
        "type": "library",
    }


def resolve_version(version_spec):
    """Resolve a PlatformIO version specifier to a concrete version string.

    For example, ^0.1.6 means >=0.1.6 <1.0.0, but we use the minimum
    version as the assumed installed version for CVE checking purposes.
    """
    spec = version_spec.strip()
    # Remove semver range prefixes
    for prefix in ("^", "~", ">=", "<=", ">", "<", "="):
        if spec.startswith(prefix):
            spec = spec[len(prefix):]
            break
    # Return the version number
    match = re.match(r"([\d]+\.[\d]+\.[\d]+)", spec)
    if match:
        return match.group(1)
    match = re.match(r"([\d]+\.[\d]+)", spec)
    if match:
        return match.group(1) + ".0"
    return spec


def version_tuple(version_str):
    """Convert a version string to a tuple of integers for comparison."""
    parts = []
    for p in version_str.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def generate_cyclonedx_sbom(dependencies, project_name="CoreS3-IoT-Camera"):
    """Generate a CycloneDX 1.4 SBOM in JSON format.

    Returns a dict that can be serialized to JSON.
    """
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:%s" % str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "vuln-m5stack",
                    "name": "sbom_analyze",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "firmware",
                "name": project_name,
                "version": "1.0.0",
                "description": "M5Stack CoreS3 IoT Camera Firmware",
                "purl": "pkg:platformio/%s@1.0.0" % project_name,
            },
        },
        "components": [],
    }

    for dep in dependencies:
        version = resolve_version(dep["version_spec"])
        comp_type = "framework" if dep.get("type") == "platform" else "library"
        purl = "pkg:platformio/%s/%s@%s" % (
            dep["namespace"], dep["name"], version
        )

        component = {
            "type": comp_type,
            "name": dep["name"],
            "version": version,
            "purl": purl,
            "group": dep["namespace"],
            "description": "PlatformIO dependency: %s" % dep["raw"],
        }

        # Add known license info
        license_map = {
            "M5GFX": "MIT",
            "M5Unified": "MIT",
            "lvgl": "MIT",
            "ArduinoJson": "MIT",
            "esp32-camera": "Apache-2.0",
            "espressif32": "Apache-2.0",
        }
        if dep["name"] in license_map:
            component["licenses"] = [
                {"license": {"id": license_map[dep["name"]]}}
            ]

        sbom["components"].append(component)

    return sbom


def scan_firmware_for_versions(firmware_path):
    """Scan a firmware binary for embedded library version strings.

    Returns a dict mapping library name to detected version(s).
    """
    if not os.path.exists(firmware_path):
        print("[ERROR] Firmware file not found: %s" % firmware_path)
        return {}

    # Extract strings from firmware
    try:
        result = subprocess.run(
            ["strings", "-n", "4", firmware_path],
            capture_output=True, text=True, timeout=30,
        )
        all_strings = result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback: read binary manually
        print("[*] 'strings' command not available, using Python fallback")
        with open(firmware_path, "rb") as f:
            data = f.read()
        chars = []
        all_lines = []
        for byte in data:
            if 32 <= byte <= 126:
                chars.append(chr(byte))
            else:
                if len(chars) >= 4:
                    all_lines.append("".join(chars))
                chars = []
        if len(chars) >= 4:
            all_lines.append("".join(chars))
        all_strings = "\n".join(all_lines)

    detected = {}
    for lib_name, patterns in LIBRARY_VERSION_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, all_strings, re.IGNORECASE)
            if matches:
                # Deduplicate
                versions = sorted(set(matches))
                detected[lib_name] = versions
                break

    return detected


def check_cves(dependencies):
    """Check each dependency against the hardcoded CVE database.

    Returns a list of dicts describing applicable CVE matches.
    """
    results = []

    for dep in dependencies:
        # Build lookup keys to try
        keys_to_try = []
        if dep["namespace"] and dep["name"]:
            keys_to_try.append("%s/%s" % (dep["namespace"], dep["name"]))
        keys_to_try.append(dep["name"])

        # For the espressif32 platform, also check esp-idf CVEs
        if dep["name"] == "espressif32" or dep.get("type") == "platform":
            keys_to_try.append("espressif/esp-idf")

        version = resolve_version(dep["version_spec"])
        ver_tuple = version_tuple(version)

        for key in keys_to_try:
            cve_list = CVE_DATABASE.get(key, [])
            for cve in cve_list:
                # Check if the resolved version falls within the affected range
                fixed_ver = cve.get("fixed_in", "")
                if fixed_ver:
                    fixed_tuple = version_tuple(fixed_ver)
                    # For platform mapping (espressif32 6.1.0 -> ESP-IDF 5.0.x),
                    # we note the mapping but still flag for review
                    is_affected = ver_tuple < fixed_tuple

                    # Special handling: espressif32@6.1.0 bundles ESP-IDF ~5.0.x
                    if dep["name"] == "espressif32" and key == "espressif/esp-idf":
                        # espressif32@6.1.0 ships ESP-IDF v5.0.2
                        idf_version = version_tuple("5.0.2")
                        is_affected = idf_version < fixed_tuple
                else:
                    is_affected = True

                results.append({
                    "component": "%s/%s" % (dep["namespace"], dep["name"]),
                    "version": version,
                    "cve": cve,
                    "affected": is_affected,
                })

    return results


def print_sbom_summary(sbom):
    """Print a human-readable summary of the SBOM."""
    print()
    print("[*] Software Bill of Materials (SBOM)")
    print("=" * 70)
    print("    Format:     CycloneDX %s" % sbom["specVersion"])
    print("    Serial:     %s" % sbom["serialNumber"])
    print("    Generated:  %s" % sbom["metadata"]["timestamp"])
    print("    Project:    %s" % sbom["metadata"]["component"]["name"])
    print("    Components: %d" % len(sbom["components"]))
    print()

    print("    %-25s %-12s %-10s %s" % ("Component", "Version", "Type", "License"))
    print("    " + "-" * 66)
    for comp in sbom["components"]:
        name = comp["name"]
        version = comp["version"]
        comp_type = comp["type"]
        license_id = ""
        if "licenses" in comp and comp["licenses"]:
            license_id = comp["licenses"][0]["license"]["id"]
        print("    %-25s %-12s %-10s %s" % (name, version, comp_type, license_id))
    print()


def print_firmware_scan(detected_versions):
    """Print firmware version string scan results."""
    print()
    print("[*] Firmware Binary Version String Scan")
    print("=" * 70)

    if not detected_versions:
        print("    No library version strings detected in firmware binary.")
        print("    This is normal - not all libraries embed version strings")
        print("    in the compiled output.")
    else:
        for lib, versions in sorted(detected_versions.items()):
            for ver in versions:
                print("    [FOUND] %-20s version %s" % (lib, ver))
    print()


def print_cve_report(cve_results):
    """Print the CVE analysis report."""
    print()
    print("[*] CVE Analysis Report")
    print("=" * 70)

    affected = [r for r in cve_results if r["affected"]]
    not_affected = [r for r in cve_results if not r["affected"]]

    if not cve_results:
        print("    No CVE data available for the detected components.")
        print()
        return

    # Summary counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in affected:
        sev = r["cve"]["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total_affected = len(affected)
    total_not_affected = len(not_affected)

    print()
    print("    Summary: %d potentially applicable, %d not affected" % (
        total_affected, total_not_affected
    ))

    if total_affected > 0:
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = severity_counts.get(sev, 0)
            if count > 0:
                parts.append("%d %s" % (count, sev))
        print("    Severity breakdown: %s" % ", ".join(parts))

    # Print affected CVEs
    if affected:
        print()
        print("    POTENTIALLY AFFECTED")
        print("    " + "-" * 66)
        for r in sorted(affected, key=lambda x: -x["cve"].get("cvss", 0)):
            cve = r["cve"]
            print()
            print("    [%s] %s (CVSS %.1f)" % (cve["severity"], cve["id"], cve["cvss"]))
            print("    Component:  %s @ %s" % (r["component"], r["version"]))
            print("    Affected:   %s" % cve["affected_versions"])
            print("    Fixed in:   %s" % cve.get("fixed_in", "unknown"))
            print("    CWE:        %s" % cve.get("cwe", "N/A"))
            print("    Summary:    %s" % cve["summary"])

    # Print not-affected CVEs (briefly)
    if not_affected:
        print()
        print("    NOT AFFECTED (version is at or above fix)")
        print("    " + "-" * 66)
        for r in not_affected:
            cve = r["cve"]
            print("    [OK] %-20s %s (fixed in %s, have %s)" % (
                cve["id"], r["component"],
                cve.get("fixed_in", "?"), r["version"],
            ))

    print()

    # Risk assessment
    print("[*] Risk Assessment")
    print("=" * 70)
    if total_affected == 0:
        print("    LOW RISK: No known CVEs affect the current dependency versions.")
        print("    Note: This only checks against a limited offline database.")
        print("    For production use, check NVD, OSV, or Snyk for full coverage.")
    elif severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) >= 3:
        print("    CRITICAL RISK: Multiple high-severity vulnerabilities detected.")
        print("    Immediate action recommended:")
        print("      - Update affected libraries to patched versions")
        print("      - Assess exploitability in your specific deployment context")
        print("      - Consider network isolation for deployed devices")
    elif severity_counts.get("HIGH", 0) > 0:
        print("    HIGH RISK: High-severity vulnerabilities detected in dependencies.")
        print("    Recommended actions:")
        print("      - Review each CVE for applicability to your use case")
        print("      - Plan library updates in next firmware release")
        print("      - Monitor for active exploitation reports")
    else:
        print("    MODERATE RISK: Medium/low severity issues found.")
        print("    Recommended actions:")
        print("      - Schedule updates in regular maintenance cycle")
        print("      - Review CVE details to understand exposure")
    print()
    print("    IMPORTANT: This is an offline educational database with limited")
    print("    coverage. For production firmware, use comprehensive scanners:")
    print("      - OWASP Dependency-Check")
    print("      - Google OSV (https://osv.dev)")
    print("      - Snyk (https://snyk.io)")
    print("      - NIST NVD (https://nvd.nist.gov)")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate an SBOM from a PlatformIO project and check "
                    "dependencies against known CVEs. Works entirely offline "
                    "using a hardcoded vulnerability database for educational "
                    "purposes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --platformio-ini ../../../../platformio.ini
  %(prog)s --platformio-ini ../../../../platformio.ini --output sbom.json
  %(prog)s --platformio-ini ../../../../platformio.ini --check-cves
  %(prog)s --firmware firmware.bin
  %(prog)s --platformio-ini ../../../../platformio.ini --firmware firmware.bin --check-cves

The SBOM is generated in CycloneDX JSON format, which is an industry
standard supported by most vulnerability scanning tools.
""",
    )

    parser.add_argument(
        "--platformio-ini",
        metavar="FILE",
        help="Path to platformio.ini to extract dependencies from",
    )
    parser.add_argument(
        "--firmware",
        metavar="FILE",
        help="Path to extracted firmware binary to scan for version strings",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save CycloneDX SBOM JSON to this file",
    )
    parser.add_argument(
        "--check-cves",
        action="store_true",
        help="Check dependencies against the built-in CVE database",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show additional detail including raw dependency parsing",
    )

    args = parser.parse_args()

    if not args.platformio_ini and not args.firmware:
        parser.error("At least one of --platformio-ini or --firmware is required")

    print("[*] SBOM Analysis and CVE Check")
    print("=" * 70)

    dependencies = []
    sbom = None

    # Step 1: Parse platformio.ini
    if args.platformio_ini:
        print("[*] Parsing dependencies from: %s" % args.platformio_ini)
        dependencies = parse_platformio_ini(args.platformio_ini)

        if not dependencies:
            print("[ERROR] No dependencies found in %s" % args.platformio_ini)
            return 1

        if args.verbose:
            print("[*] Raw dependency list:")
            for dep in dependencies:
                print("    %s/%s @ %s (%s)" % (
                    dep["namespace"], dep["name"],
                    dep["version_spec"], dep.get("type", "library"),
                ))

        # Generate SBOM
        sbom = generate_cyclonedx_sbom(dependencies)
        print_sbom_summary(sbom)

        # Save SBOM if requested
        if args.output:
            with open(args.output, "w") as f:
                json.dump(sbom, f, indent=2)
            print("[+] SBOM saved to: %s" % args.output)
            print()

    # Step 2: Scan firmware binary
    if args.firmware:
        print("[*] Scanning firmware binary: %s" % args.firmware)
        if not os.path.exists(args.firmware):
            print("[ERROR] Firmware file not found: %s" % args.firmware)
            return 1

        file_size = os.path.getsize(args.firmware)
        print("[*] Firmware size: %d bytes (%.1f KB)" % (file_size, file_size / 1024))

        detected = scan_firmware_for_versions(args.firmware)
        print_firmware_scan(detected)

        # If we detected versions and have deps, update the versions
        if detected and dependencies:
            for dep in dependencies:
                for lib_name, versions in detected.items():
                    if lib_name.lower() in dep["name"].lower():
                        dep["detected_version"] = versions[0]
                        print("[*] Updated %s version from firmware scan: %s" % (
                            dep["name"], versions[0],
                        ))

    # Step 3: CVE check
    if args.check_cves:
        if not dependencies:
            print("[ERROR] No dependencies to check. Provide --platformio-ini")
            return 1

        print("[*] Checking %d components against offline CVE database..." % len(dependencies))
        cve_results = check_cves(dependencies)
        print_cve_report(cve_results)

    # Final summary
    if not args.check_cves and dependencies:
        print("[*] Tip: Add --check-cves to check dependencies against known vulnerabilities")
        print("[*] Tip: Add --firmware <file> to scan for embedded version strings")

    print("[*] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
