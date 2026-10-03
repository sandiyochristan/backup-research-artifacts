# PART 4 — DYNAMIC ANALYSIS & RUNTIME INSTRUMENTATION

---

## 4.1 Frida Setup on Wear OS

### Install Frida Server on Watch

```bash
# ── Download correct Frida server for watch architecture ──
FRIDA_VERSION=$(frida --version)
ARCH=$(adb shell getprop ro.product.cpu.abi)  # Usually arm64-v8a for Pixel Watch
echo "Frida version: $FRIDA_VERSION, Watch arch: $ARCH"

# Download from: https://github.com/frida/frida/releases
# Example:
curl -L -o frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-arm64.xz"
xz -d frida-server.xz

# ── Push to watch ──
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# ── Start Frida server (needs root or debug build) ──
# Option A: If watch is rooted
adb shell su -c '/data/local/tmp/frida-server -D &'

# Option B: If not rooted, use frida-gadget injection
# (See section 4.2 for gadget approach)

# ── Verify Frida is running ──
frida-ps -U  # Should list watch processes
```

### Frida Gadget Injection (No Root Required)

```bash
# ── For non-rooted watches: inject frida-gadget into target APK ──

inject_gadget() {
  local APK=$1
  local OUTPUT_DIR="./gadget_injected"
  mkdir -p "$OUTPUT_DIR"
  
  # 1. Disassemble
  apktool d "$APK" -o "$OUTPUT_DIR/temp_disasm" -f
  
  # 2. Download frida-gadget
  GADGET_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-gadget-${FRIDA_VERSION}-android-arm64.so.xz"
  curl -L -o gadget.so.xz "$GADGET_URL"
  xz -d gadget.so.xz
  
  # 3. Inject gadget library
  mkdir -p "$OUTPUT_DIR/temp_disasm/lib/arm64-v8a/"
  cp gadget.so "$OUTPUT_DIR/temp_disasm/lib/arm64-v8a/libfrida-gadget.so"
  
  # 4. Add System.loadLibrary call to main activity smali
  # (Manual step — inject into the main activity's onCreate)
  
  # 5. Rebuild
  apktool b "$OUTPUT_DIR/temp_disasm" -o "$OUTPUT_DIR/target_gadget.apk"
  
  # 6. Sign
  keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA \
    -keysize 2048 -validity 10000 -storepass android -keypass android \
    -dname "CN=Debug"
  apksigner sign --ks debug.keystore --ks-pass pass:android \
    "$OUTPUT_DIR/target_gadget.apk"
  
  # 7. Install on watch
  adb install -r "$OUTPUT_DIR/target_gadget.apk"
}
```

---

## 4.2 Frida Scripts for Wear OS Vulnerability Hunting

### Script 1: Intent Monitor — Catch All Intent Activity

```javascript
// ── intent_monitor.js ──
// Monitors all intent-based activity launches on the watch
// Use: frida -U -l intent_monitor.js -f <target_package>

Java.perform(function() {
    console.log("[*] Intent Monitor loaded — watching all startActivity calls");

    // Hook Activity.startActivity
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
        var action = intent.getAction();
        var data = intent.getData();
        var extras = intent.getExtras();
        var component = intent.getComponent();
        
        console.log("\n[INTENT] ==========================================");
        console.log("  Action:    " + action);
        console.log("  Data:      " + data);
        console.log("  Component: " + component);
        if (extras) {
            var keys = extras.keySet().iterator();
            while (keys.hasNext()) {
                var key = keys.next();
                console.log("  Extra:     " + key + " = " + extras.get(key));
            }
        }
        console.log("  Caller:    " + this.getClass().getName());
        console.log("[INTENT] ==========================================\n");
        
        // Check for sensitive actions WITHOUT confirmation
        if (action === "android.intent.action.SENDTO" || 
            action === "android.intent.action.CALL" ||
            action === "android.intent.action.SEND") {
            console.log("[!!!] SENSITIVE ACTION DETECTED — Check for confirmation dialog!");
        }
        
        return this.startActivity(intent);
    };
    
    // Hook Context.startActivity (catches service-launched intents)
    var Context = Java.use("android.content.Context");
    Context.startActivity.overload("android.content.Intent").implementation = function(intent) {
        console.log("[CONTEXT-INTENT] Action: " + intent.getAction() + 
                    " Data: " + intent.getData() +
                    " Caller: " + this.getClass().getName());
        return this.startActivity(intent);
    };
    
    // Hook startService
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.startService.overload("android.content.Intent").implementation = function(intent) {
        console.log("[SERVICE] " + intent.getAction() + " → " + intent.getComponent());
        return this.startService(intent);
    };
    
    // Hook sendBroadcast
    ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
        console.log("[BROADCAST] " + intent.getAction() + " Data: " + intent.getData());
        return this.sendBroadcast(intent);
    };
});
```

### Script 2: Health Services Data Interceptor

```javascript
// ── health_interceptor.js ──
// Intercepts Health Services API calls and data callbacks
// Use: frida -U -l health_interceptor.js -f com.google.android.apps.fitness

Java.perform(function() {
    console.log("[*] Health Services Interceptor loaded");
    
    // Hook HealthServicesClient
    try {
        var HealthServicesClient = Java.use("com.google.android.gms.fitness.HealthServicesClient");
        console.log("[+] HealthServicesClient found");
    } catch(e) {
        console.log("[-] HealthServicesClient not found, trying alternatives...");
    }
    
    // Hook PassiveMonitoringClient callbacks
    try {
        var PassiveListenerCallback = Java.use(
            "androidx.health.services.client.PassiveListenerCallback"
        );
        PassiveListenerCallback.onNewDataPointsReceived.implementation = function(dataPoints) {
            console.log("\n[HEALTH-DATA] ============================");
            console.log("  DataPoints received: " + dataPoints.toString());
            console.log("  Caller package: " + this.getClass().getName());
            console.log("[HEALTH-DATA] ============================\n");
            return this.onNewDataPointsReceived(dataPoints);
        };
    } catch(e) {
        console.log("[-] PassiveListenerCallback hook failed: " + e);
    }
    
    // Hook SensorManager for raw sensor access
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.registerListener.overload(
        "android.hardware.SensorEventListener",
        "android.hardware.Sensor",
        "int"
    ).implementation = function(listener, sensor, rate) {
        console.log("[SENSOR] Registering: " + sensor.getName() + 
                    " Type: " + sensor.getType() +
                    " Rate: " + rate);
        return this.registerListener(listener, sensor, rate);
    };
    
    // Monitor permission checks
    var ContextCompat = Java.use("androidx.core.content.ContextCompat");
    ContextCompat.checkSelfPermission.implementation = function(context, permission) {
        var result = this.checkSelfPermission(context, permission);
        if (permission.indexOf("BODY_SENSORS") !== -1 || 
            permission.indexOf("ACTIVITY_RECOGNITION") !== -1) {
            console.log("[PERM-CHECK] " + permission + " → " + 
                        (result === 0 ? "GRANTED" : "DENIED"));
        }
        return result;
    };
});
```

### Script 3: Data Layer Bridge Monitor

```javascript
// ── datalayer_monitor.js ──
// Monitors Wearable Data Layer communications (watch ↔ phone)
// Use: frida -U -l datalayer_monitor.js -f com.google.android.gms

Java.perform(function() {
    console.log("[*] Data Layer Monitor loaded");
    
    // Hook MessageClient.sendMessage
    try {
        var MessageClient = Java.use("com.google.android.gms.wearable.MessageClient");
        // Hook via interface implementation patterns
    } catch(e) {}
    
    // Hook WearableListenerService.onMessageReceived
    try {
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.indexOf("WearableListenerService") !== -1) {
                    try {
                        var cls = Java.use(className);
                        cls.onMessageReceived.implementation = function(messageEvent) {
                            console.log("\n[DATA-LAYER-MSG] ========================");
                            console.log("  Path:     " + messageEvent.getPath());
                            console.log("  SourceID: " + messageEvent.getSourceNodeId());
                            var data = messageEvent.getData();
                            if (data) {
                                console.log("  Data:     " + bytesToString(data));
                                console.log("  DataHex:  " + bytesToHex(data));
                            }
                            console.log("  Handler:  " + className);
                            console.log("[DATA-LAYER-MSG] ========================\n");
                            return this.onMessageReceived(messageEvent);
                        };
                        console.log("[+] Hooked: " + className);
                    } catch(e) {}
                }
            },
            onComplete: function() {}
        });
    } catch(e) {
        console.log("[-] Data Layer hook failed: " + e);
    }
    
    function bytesToString(bytes) {
        try {
            var StringClass = Java.use("java.lang.String");
            return StringClass.$new(bytes, "UTF-8");
        } catch(e) { return "<binary>"; }
    }
    
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < Math.min(bytes.length, 64); i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2) + " ";
        }
        return hex + (bytes.length > 64 ? "..." : "");
    }
});
```

### Script 4: Permission Bypass Detector

```javascript
// ── permission_bypass.js ──
// Detects when apps access protected resources without proper permission checks
// Use: frida -U -l permission_bypass.js -f <target_package>

Java.perform(function() {
    console.log("[*] Permission Bypass Detector loaded");
    
    var findings = [];
    
    // Hook checkPermission/checkCallingPermission
    var Context = Java.use("android.content.Context");
    
    Context.checkPermission.overload("java.lang.String", "int", "int").implementation = function(perm, pid, uid) {
        var result = this.checkPermission(perm, pid, uid);
        console.log("[PERM] checkPermission(" + perm + ") → " + 
                    (result === 0 ? "GRANTED" : "DENIED") +
                    " pid=" + pid + " uid=" + uid);
        return result;
    };
    
    Context.checkCallingPermission.overload("java.lang.String").implementation = function(perm) {
        var result = this.checkCallingPermission(perm);
        if (result !== 0) {
            console.log("[!!!] DENIED calling permission: " + perm);
            findings.push({permission: perm, result: "DENIED", type: "calling"});
        }
        return result;
    };
    
    // Hook enforcePermission (throws SecurityException)
    Context.enforcePermission.overload("java.lang.String", "int", "int", "java.lang.String")
        .implementation = function(perm, pid, uid, message) {
        console.log("[ENFORCE] " + perm + " pid=" + pid + " uid=" + uid);
        try {
            return this.enforcePermission(perm, pid, uid, message);
        } catch(e) {
            console.log("[!!!] SecurityException for: " + perm);
            throw e;
        }
    };
    
    // Hook ContentResolver.query to detect unprotected provider access
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.overload(
        "android.net.Uri", "[Ljava.lang.String;",
        "java.lang.String", "[Ljava.lang.String;", "java.lang.String"
    ).implementation = function(uri, proj, sel, selArgs, sort) {
        console.log("[PROVIDER-QUERY] " + uri.toString());
        return this.query(uri, proj, sel, selArgs, sort);
    };
});
```

### Script 5: SSL Pinning Bypass for Wear OS

```javascript
// ── ssl_bypass_wear.js ──
// Bypasses SSL/TLS certificate pinning on Wear OS apps
// Use: frida -U -l ssl_bypass_wear.js -f <target_package>

Java.perform(function() {
    console.log("[*] SSL Pinning Bypass for Wear OS loaded");
    
    // TrustManager bypass
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustManager = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var sslCtx = SSLContext.getInstance("TLS");
    sslCtx.init(null, TrustManagers, null);
    SSLContext.getInstance.overload("java.lang.String").implementation = function(type) {
        var ctx = this.getInstance(type);
        ctx.init(null, TrustManagers, null);
        return ctx;
    };
    
    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCerts) {
            console.log("[SSL-BYPASS] Bypassed pin for: " + hostname);
        };
    } catch(e) {}
    
    // Network security config bypass
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityConfig"
        );
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
            return true;
        };
    } catch(e) {}
    
    console.log("[+] SSL pinning bypassed");
});
```

---

## 4.3 ADB Dynamic Testing Commands

### Intent Fuzzing via ADB

```bash
#!/bin/bash
# ── intent_fuzz.sh ──
# Fuzzes exported components with various intent configurations

TARGET_PKG=$1
RESULTS_DIR="./findings/dynamic/${TARGET_PKG}"
mkdir -p "$RESULTS_DIR"

echo "=== Intent Fuzzing: $TARGET_PKG ===" > "$RESULTS_DIR/fuzz_log.txt"

# ── Get all exported activities ──
ACTIVITIES=$(adb shell dumpsys package "$TARGET_PKG" | \
  grep -A1 "exported=true" | grep "Activity" | awk '{print $NF}')

for activity in $ACTIVITIES; do
  echo "[TEST] $activity" | tee -a "$RESULTS_DIR/fuzz_log.txt"
  
  # Test 1: Basic launch
  adb shell am start -n "$TARGET_PKG/$activity" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 2: With SMS URI
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.SENDTO -d "smsto:+0000000000" \
    --es sms_body "FUZZ_TEST" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 3: With tel: URI
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.VIEW -d "tel:+0000000000" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 4: With file:// URI (path traversal)
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.VIEW \
    -d "file:///data/data/$TARGET_PKG/databases/" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Test 5: With content:// URI
  adb shell am start -n "$TARGET_PKG/$activity" \
    -a android.intent.action.VIEW \
    -d "content://$TARGET_PKG.provider/" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
  sleep 1
  
  # Capture screenshot after each test
  adb shell screencap -p /sdcard/screen.png
  adb pull /sdcard/screen.png "$RESULTS_DIR/${activity}_screenshot.png" 2>/dev/null
done

# ── Test broadcast receivers ──
RECEIVERS=$(adb shell dumpsys package "$TARGET_PKG" | \
  grep -A1 "exported=true" | grep "Receiver" | awk '{print $NF}')

for receiver in $RECEIVERS; do
  echo "[BROADCAST-TEST] $receiver" | tee -a "$RESULTS_DIR/fuzz_log.txt"
  adb shell am broadcast -n "$TARGET_PKG/$receiver" \
    -a "android.intent.action.BOOT_COMPLETED" 2>&1 | tee -a "$RESULTS_DIR/fuzz_log.txt"
done

echo "=== Fuzzing Complete ===" | tee -a "$RESULTS_DIR/fuzz_log.txt"
```

### ContentProvider Exploitation

```bash
#!/bin/bash
# ── provider_audit.sh ──
# Tests all accessible ContentProviders for data leaks and injection

TARGET_PKG=$1
RESULTS_DIR="./findings/dynamic/providers"
mkdir -p "$RESULTS_DIR"

# ── Get provider authorities ──
PROVIDERS=$(adb shell dumpsys package "$TARGET_PKG" | \
  grep "Provider{" | grep -oP 'authority=\K\S+' | tr -d '}')

for authority in $PROVIDERS; do
  echo "=== Testing: content://$authority ===" | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 1: Basic query
  adb shell content query --uri "content://$authority/" \
    2>&1 | head -20 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 2: Path traversal
  adb shell content query --uri "content://$authority/../../etc/passwd" \
    2>&1 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 3: SQL injection in selection
  adb shell content query --uri "content://$authority/" \
    --where "'1'='1'" 2>&1 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  # Test 4: Read file via openFile
  adb shell content read --uri "content://$authority/test" \
    2>&1 | tee -a "$RESULTS_DIR/provider_audit.txt"
  
  echo "" >> "$RESULTS_DIR/provider_audit.txt"
done
```

### Logcat Monitoring During Tests

```bash
# ── Start logcat capture during dynamic testing ──
LOG_DIR="./findings/dynamic/logs"
mkdir -p "$LOG_DIR"

# Capture all security-relevant logs
adb logcat -c  # Clear existing logs
adb logcat -v time \
  | grep -iE "permission|denied|security|exception|intent|broadcast|sensor|health" \
  > "$LOG_DIR/security_logcat.txt" &
LOGCAT_PID=$!

echo "Logcat monitoring started (PID: $LOGCAT_PID)"
echo "Run your tests now. Press Ctrl+C to stop."

# When done testing:
# kill $LOGCAT_PID
```

### Screen Recording During Validation

```bash
# ── Record the watch screen during PoC execution ──
# This is CRITICAL for the Google MVRP report

# Start recording (max 3 minutes on Wear OS)
adb shell screenrecord /sdcard/poc_demo.mp4 --time-limit 180 &
RECORD_PID=$!

echo "Recording started. Execute your PoC now."
echo "Recording will stop after 180 seconds or press Ctrl+C"

# Pull recording when done
# kill $RECORD_PID
# adb pull /sdcard/poc_demo.mp4 ./findings/poc_demo.mp4
```
