# PART 3 — THREAT MODEL & ATTACK VECTORS

---

## 3.1 Wear OS Threat Model

### Attacker Models

```
┌─────────────────────────────────────────────────────────────────────┐
│                    WEAR OS ATTACKER MODELS                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  MODEL A — MALICIOUS WATCH APP (Primary, CVE-2025-12080 class)     │
│  ├─ Attacker installs a seemingly benign app on the watch          │
│  ├─ App requires NO special permissions                            │
│  ├─ App sends crafted intents to system/Google apps                │
│  ├─ Exploits: confused deputy, silent actions, data exfiltration   │
│  └─ Impact: SMS sending, calls, health data theft, payments        │
│                                                                     │
│  MODEL B — COMPANION PHONE APP (Lateral Movement)                  │
│  ├─ Attacker has app on paired phone                               │
│  ├─ Uses Wearable Data Layer to reach watch components             │
│  ├─ Exploits: cross-device trust, MessageClient abuse              │
│  └─ Impact: Remote control of watch, sensor exfiltration           │
│                                                                     │
│  MODEL C — PROXIMITY BLE ATTACKER                                  │
│  ├─ Attacker within BLE range (~30m)                               │
│  ├─ Uses BLE sniffing / MITM tools                                 │
│  ├─ Exploits: weak pairing, unauthenticated GATT services          │
│  └─ Impact: Data interception, notification spoofing               │
│                                                                     │
│  MODEL D — MALICIOUS TILE/COMPLICATION PROVIDER                    │
│  ├─ Attacker registers as Tile or Complication data provider       │
│  ├─ Tiles run in a separate process (no Activity lifecycle)        │
│  ├─ Exploits: intent launch from tiles, UI redressing              │
│  └─ Impact: Silent privileged actions, data spoofing               │
│                                                                     │
│  MODEL E — NETWORK/CLOUD ATTACKER                                  │
│  ├─ Attacker intercepts watch HTTP/S traffic                       │
│  ├─ Watch makes direct API calls (bypassing phone)                 │
│  ├─ Exploits: weak cert pinning, over-scoped OAuth tokens          │
│  └─ Impact: Token theft, API abuse, account takeover               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Wear OS vs Android — Unique Attack Surface Gaps

```
AGENT_INSTRUCTION: These gaps are the PRIMARY reason Wear OS is under-researched
and likely to yield novel vulnerabilities. Focus on these differentiators.

GAP 1: NO CONFIRMATION UX ON TILES
  - Tiles (TileService) run outside the Activity lifecycle
  - Intent launch from a Tile has no natural place for a confirmation dialog
  - Phone Android apps rely on Activity-based confirmation → not available on Wear
  - CVE-2025-12080 PROVEN this gap exists in production

GAP 2: HEALTH SERVICES PERMISSION IMMATURITY
  - Health Services is a privileged Wear OS system service
  - Permission model for HR, ECG, SpO2, body temp is newer than phone's Health Connect
  - Passive monitoring vs active exercise sessions may use different permission paths
  - Race condition: permission revoked but listener still receiving data

GAP 3: DATA LAYER TRUST BOUNDARY
  - Wearable Data Layer tunnels data over BLE between watch ↔ phone
  - Many phone-side WearableListenerService handlers are exported
  - Phone apps implicitly trust messages from "their" watch
  - A malicious watch app can impersonate messages to any phone-side listener

GAP 4: STRIPPED-DOWN APP PORTS
  - Many Wear OS apps are simplified ports of phone apps
  - Developers copy intent handlers from phone code but skip Wear-specific UX adaptation
  - Permission checks present on phone may be absent on Wear version
  - Smaller QA teams test Wear variants

GAP 5: LIMITED SECURITY TOOLING
  - Few researchers test Wear OS → known Android bug classes often unpatched
  - drozer, Frida, Objection all work but require manual setup on watch
  - Automated scanners (MobSF, QARK) don't have Wear-specific rulesets
```

---

## 3.2 Attack Vector Catalog — With Validation Steps

### VECTOR 1: Intent/IPC Abuse (CRITICAL — Proven by CVE-2025-12080)

```
SEVERITY: CRITICAL
ATTACKER MODEL: A (Malicious Watch App), D (Malicious Tile)
CWE: CWE-927 (Use of Implicit Intent for Sensitive Communication)
REFERENCE: CVE-2025-12080

TARGET APPS:
- com.google.android.apps.messaging  (PROVEN VULNERABLE)
- com.google.android.dialer
- com.google.android.apps.maps
- com.google.android.gm (Gmail)
- com.google.android.calendar
- Any app with exported Activities handling ACTION_SENDTO/ACTION_VIEW

VALIDATION STEPS:

Step 1 — Identify exported intent handlers
  $ grep -rn 'exported="true"' ./disassembled/<TARGET>/AndroidManifest.xml
  $ grep -rn 'intent-filter' ./disassembled/<TARGET>/AndroidManifest.xml

Step 2 — Test each URI scheme via ADB
  # SMS (CVE-2025-12080 pattern)
  $ adb shell am start -a android.intent.action.SENDTO \
    -d "smsto:+1234567890" --es sms_body "test_message"
  
  # Phone call
  $ adb shell am start -a android.intent.action.CALL \
    -d "tel:+1234567890"
  
  # Email
  $ adb shell am start -a android.intent.action.SENDTO \
    -d "mailto:test@example.com" --es android.intent.extra.SUBJECT "test"
  
  # Maps navigation
  $ adb shell am start -a android.intent.action.VIEW \
    -d "google.navigation:q=destination"

Step 3 — Check for user confirmation
  CRITICAL CHECK: Does the action execute WITHOUT showing a confirmation dialog?
  - If YES → VULNERABILITY CONFIRMED (confused deputy)
  - If NO → Note the confirmation mechanism for bypass attempts

Step 4 — Test from Tile context
  Build a PoC TileService that launches the same intent from onTileRequest
  (Tiles run outside Activity lifecycle — confirmation may be bypassed)

Step 5 — Verify no permission required
  $ adb shell am start -a android.intent.action.SENDTO \
    -d "smsto:+1234567890" --es sms_body "test" \
    --user 0
  # If this works without SEND_SMS permission → exploitable by any app
```

### VECTOR 2: Health Services Data Leakage (HIGH)

```
SEVERITY: HIGH
ATTACKER MODEL: A (Malicious Watch App)
CWE: CWE-862 (Missing Authorization)

TARGET SERVICES:
- com.google.android.wearable.healthservices
- com.google.android.apps.fitness
- com.google.android.apps.healthdata

VALIDATION STEPS:

Step 1 — Check Health Services IPC surface
  $ adb shell dumpsys activity service HealthServicesService
  $ adb shell service list | grep -i health

Step 2 — Test passive monitoring without permission
  Build a PoC app that registers as PassiveMonitoringClient
  WITHOUT requesting BODY_SENSORS permission
  
  # Check if health data callbacks fire:
  # - Heart rate
  # - Step count  
  # - SpO2
  # - Skin temperature

Step 3 — Test permission revocation race
  1. Grant BODY_SENSORS to PoC app
  2. Register PassiveMonitoringClient listener
  3. Revoke BODY_SENSORS permission via Settings
  4. Check if listener STILL receives health data updates
  
  $ adb shell pm revoke <POC_PACKAGE> android.permission.BODY_SENSORS
  # Monitor logcat for continued health data delivery

Step 4 — Check broadcast receivers for health data
  $ adb shell dumpsys activity broadcasts | grep -i health
  # Look for implicit broadcasts that leak health data to any receiver

Step 5 — Inspect health data storage
  $ adb shell run-as com.google.android.apps.fitness ls /data/data/com.google.android.apps.fitness/
  $ adb shell content query --uri content://com.google.android.apps.fitness
```

### VECTOR 3: Wearable Data Layer Abuse (HIGH)

```
SEVERITY: HIGH
ATTACKER MODEL: A (Watch App), B (Phone App)
CWE: CWE-306 (Missing Authentication for Critical Function)

VALIDATION STEPS:

Step 1 — Find WearableListenerService handlers
  $ grep -rn "WearableListenerService" ./disassembled/*/AndroidManifest.xml
  $ grep -rn "onMessageReceived\|onDataChanged" ./decompiled/*/sources/ --include="*.java"

Step 2 — Enumerate Data Layer capabilities
  $ adb shell dumpsys activity service com.google.android.gms/.wearable.service.WearableService

Step 3 — Test message injection
  Build a PoC watch app that sends crafted MessageClient messages:
  - Use same message paths as legitimate apps
  - Test if phone-side handlers validate sender node ID
  - Check if sensitive data (auth tokens, health) is sent in plaintext over BLE

Step 4 — BLE traffic capture (if nRF dongle available)
  # Start Wireshark with nRF sniffer
  # Filter: btatt (BLE ATT protocol)
  # Look for: plaintext health data, auth tokens, notification content
```

### VECTOR 4: Tile/Complication UI Redressing (MEDIUM)

```
SEVERITY: MEDIUM
ATTACKER MODEL: D (Malicious Tile/Complication Provider)
CWE: CWE-451 (User Interface Misrepresentation of Critical Information)

VALIDATION STEPS:

Step 1 — Register malicious Complication provider
  Build PoC app that implements ComplicationProviderService
  Return spoofed data mimicking Google Fit / Health

Step 2 — Build tapjacking Tile
  Create a Tile that visually mimics:
  - Google Wallet payment confirmation
  - System unlock dialog
  - Permission grant dialog
  Test if user can be tricked into tapping on the small watch screen

Step 3 — Test Tile data access
  Check if TileService.onTileRequest can access:
  - Clipboard content
  - Notification data
  - Sensor readings
  WITHOUT declared permissions

Step 4 — Watch Face Format (WFF) XML injection
  $ grep -rn "XmlPullParser\|SAXParser\|DocumentBuilder" \
    ./decompiled/*/sources/ --include="*.java" | grep -i "watchface\|wff"
  # Test for XXE if WFF engine parses third-party XML
```

### VECTOR 5: Permission Model Gaps & Privilege Escalation (HIGH)

```
SEVERITY: HIGH
ATTACKER MODEL: A (Malicious Watch App)
CWE: CWE-269 (Improper Privilege Management)

VALIDATION STEPS:

Step 1 — Full permission audit
  $ adb shell dumpsys package | grep -A2 "declared permissions" > ./findings/all_declared_perms.txt
  $ adb shell dumpsys package | grep "grantedPermissions\|runtime permissions" > ./findings/granted_perms.txt

Step 2 — Test Wear-specific permissions
  # Check if these can be requested by third-party apps:
  $ adb shell pm grant <POC_PKG> com.google.android.wearable.permission.BIND_TILE_PROVIDER
  $ adb shell pm grant <POC_PKG> com.google.android.wearable.permission.BIND_COMPLICATION_PROVIDER

Step 3 — ContentProvider audit
  $ for provider in $(adb shell dumpsys package providers | grep -oP 'com\.\S+/\S+'); do
      echo "=== $provider ==="
      adb shell content query --uri "content://$provider/" 2>&1 | head -5
    done

Step 4 — Test ambient mode permission transitions
  # Put watch into ambient mode
  # Check if foreground app gains temporary capabilities
  $ adb shell dumpsys activity top  # in ambient mode
  $ adb shell dumpsys activity top  # in active mode
  # Compare granted permissions/capabilities

Step 5 — SQLi in ContentProviders
  $ adb shell content query --uri "content://<PROVIDER_AUTHORITY>/" \
    --where "1=1) UNION SELECT sql FROM sqlite_master--"
```

### VECTOR 6: Bluetooth/GATT Exploitation (HIGH)

```
SEVERITY: HIGH  
ATTACKER MODEL: C (Proximity BLE)
CWE: CWE-287 (Improper Authentication)

VALIDATION STEPS:

Step 1 — Enumerate GATT services
  # Using nRF Connect app on a second phone:
  # Scan → Connect to Pixel Watch
  # List all GATT services and characteristics
  # Flag: any characteristic with READ/WRITE without AUTH requirement

Step 2 — Test pairing security
  # Attempt pairing from a new device
  # Check if watch enforces:
  # - Passkey Entry (SECURE) vs Just Works (WEAK)
  # - Numeric Comparison
  # - LE Secure Connections vs Legacy Pairing

Step 3 — GATT write replay
  # Capture legitimate GATT writes with Wireshark
  # Replay them from a different device
  # Check if values are accepted (no sequence number / nonce)

Step 4 — BLE MITM test
  $ sudo btlejuice-proxy  # on nRF dongle
  # Intercept watch ↔ phone BLE traffic
  # Check for plaintext sensitive data
```

### VECTOR 7: Network/API Surface (MEDIUM)

```
SEVERITY: MEDIUM
ATTACKER MODEL: E (Network)
CWE: CWE-295 (Improper Certificate Validation)

VALIDATION STEPS:

Step 1 — Set up proxy
  # Configure watch Wi-Fi with manual proxy to Burp Suite
  # Install Burp CA cert on watch:
  $ adb push burp_cert.pem /sdcard/
  # Settings → Security → Install from storage

Step 2 — Capture and analyze API traffic
  # Monitor in Burp for:
  # - API endpoints returning more data than watch UI shows
  # - OAuth tokens with broader scopes than needed
  # - API keys or secrets in request headers

Step 3 — Test certificate pinning
  # Use Frida to bypass cert pinning:
  $ frida -U -l ssl_pinning_bypass.js -f <TARGET_PACKAGE>

Step 4 — Check OTA update mechanism
  $ adb shell dumpsys activity service UpdateService
  # Inspect: Is firmware signature verified? Can a crafted OTA be pushed?
```
