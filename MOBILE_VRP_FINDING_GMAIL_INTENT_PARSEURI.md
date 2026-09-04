# Mobile VRP Finding: Gmail Unsafe Intent.parseUri in SmartMail Actions

## Summary

Gmail for Android uses `Intent.parseUri(str, 0)` (flag 0 = no safety restrictions) to parse intent URIs from SmartMail card action data, while the same function correctly uses `Intent.parseUri(str, 1)` with additional sanitization for other action types. The unsafe pattern allows construction of arbitrary intents targeting any component with any extras, potentially enabling a confused deputy attack when the URI data originates from email content parsed server-side.

## Affected App

- **Package**: `com.google.android.gm` (Gmail)
- **Version**: Installed on Pixel 6a running Android 15 (AP4A.250605.002)
- **VRP Tier**: Tier 1

## Vulnerability Details

### Location

**File**: `SmartMailActionExtensions.kt` (decompiled: `p000/wdd.java`)  
**Method**: `m103403c` (getIntent)  
**Action type**: `bezw.URI_INTENT` (ordinal 15)

### Unsafe Pattern (ordinal 15 — URI_INTENT)

```java
// wdd.java:105-106
} else if (iOrdinal == 15) {  // URI_INTENT
    bfci bfciVar = bfbwVar instanceof bfci ? (bfci) bfbwVar : null;
    if (bfciVar != null) {
        intent = Intent.parseUri(bfciVar.m34814i(), 0);  // FLAG 0 = NO SAFETY
        intent.getClass();
    }
}
```

No `setComponent(null)`, no `setSelector(null)`, no `addCategory(BROWSABLE)`.

### Safe Pattern (ordinal 0 — GOTO) — Same Function

```java
// wdd.java:54-59
if (iOrdinal == 0) {  // GOTO
    bfax bfaxVar = bfbwVar instanceof bfax ? (bfax) bfbwVar : null;
    if (bfaxVar != null) {
        Intent uri = Intent.parseUri(bfaxVar.m34787i(), 1);  // FLAG 1 = URI_INTENT_SCHEME (safer)
        uri.addCategory("android.intent.category.BROWSABLE");
        uri.setComponent(null);   // Prevents targeting non-exported components
        uri.setSelector(null);    // Prevents selector-based targeting
        intent = uri;
    }
}
```

### Additional Unsafe Instances

1. **`rdx.java:233`** — Package tracking card click handler (AdViewController.setOnClickListener):
   ```java
   ((yja) obj15).getContext().startActivity(Intent.parseUri(this.f265980a.mo34504c(), 0));
   ```
   
2. **`wew.java:79`** — OtherSourceViewHolder (Related Emails "openHelpPage"):
   ```java
   this.f253780a.getContext().startActivity(Intent.parseUri(str, 0));
   ```

## Data Flow

```
Email Content → Google Server Parsing → Protobuf SmartMail Cards (byqp) 
  → Gmail Client → URI_INTENT action → Intent.parseUri(uri_string, 0)
  → startActivity(intent)
```

1. `bfci` class implements the URI_INTENT action type
2. `bfci.m34814i()` returns `this.f91728b.f161117e` — a field from protobuf class `byqp`
3. `byqp` extends `cfmp` (GeneratedMessageLite) — server-generated protobuf
4. The URI string is parsed with `Intent.parseUri(str, 0)` and launched via `startActivity()`

## Impact

With `Intent.parseUri(str, 0)`:
- **Arbitrary component targeting**: Can specify any package/component, including non-exported activities
- **Arbitrary extras injection**: Can include any extras (Parcelable, String, etc.)
- **Scheme unrestricted**: Can use `intent://`, `#Intent;...end`, or any scheme
- **No BROWSABLE category filter**: Can target non-browsable activities

### Attack Scenario

If an attacker can influence the URI_INTENT SmartMail card data (through crafted email content that Google's server-side parser interprets as a SmartMail action):

1. Attacker sends crafted email to victim (e.g., mimicking package tracking format)
2. Google servers parse email and generate SmartMail card with URI_INTENT action
3. URI_INTENT action contains attacker-controlled intent:// URI
4. Victim opens email → taps SmartMail card action button
5. Gmail calls `Intent.parseUri(attacker_uri, 0)` → arbitrary intent launch

**Potential impacts**:
- Launch non-exported Gmail activities (e.g., TripsWebViewActivity with attacker URL)
- Access Gmail's internal content providers via FLAG_GRANT_READ_URI_PERMISSION
- Trigger internal state changes in Gmail or other Google apps
- Chain with other vulnerabilities for privilege escalation

## CWE Classification

- **CWE-926**: Improper Export of Android Application Components (via confused deputy)
- **CWE-927**: Use of Implicit Intent for Sensitive Communication

## CVSS Score

- **Base Score**: 7.1 (High)
- **Vector**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N
- Requires: Network (email delivery), user interaction (tap on card), no privileges

## Evidence

### Static Analysis Evidence

1. Decompiled source shows flag 0 vs. flag 1 discrepancy in same function
2. Action type enum confirms ordinal 15 = `URI_INTENT` (bezw.java static init)
3. Data origin confirmed as protobuf (`byqp extends cfmp/GeneratedMessageLite`)
4. Server-side IntentMatcher validation (bgta.java) only applies when configured

### Device Testing

- **Device**: Pixel 6a (bluejay), Android 15, Build AP4A.250605.002
- **Gmail version**: Latest from Play Store (confirmed active with emails)
- **Account**: sandiyotest@gmail.com (confirmed active)
- Gmail successfully opened to inbox with real SmartMail card content (Google Flights tracking, etc.)

### PoC App Results

- Built and installed `com.vrppoc` PoC app (targetSdk 34)
- Confirmed Gmail's exported components are accessible
- Confirmed Gmail deep links launch successfully from untrusted app
- Gmail compose activity accepts SEND/SENDTO from untrusted apps

## Remediation

Replace `Intent.parseUri(bfciVar.m34814i(), 0)` with the safe pattern used for GOTO actions:

```java
Intent uri = Intent.parseUri(bfciVar.m34814i(), Intent.URI_INTENT_SCHEME);
uri.addCategory(Intent.CATEGORY_BROWSABLE);
uri.setComponent(null);
uri.setSelector(null);
```

Apply the same fix to `rdx.java:233` and `wew.java:79`.

## Timeline

- 2026-07-09: Vulnerability discovered through static analysis of decompiled Gmail APK
- 2026-07-09: PoC app built and tested on Pixel 6a
- 2026-07-09: Report drafted

## Files

- **Decompiled source**: `/Users/sandiyochristan/Documents/vulnerabilityRes/google_apks/gmail/decompiled/sources/p000/wdd.java`
- **PoC app**: `/Users/sandiyochristan/Documents/vulnerabilityRes/vrp_poc_app/`
- **APK**: `/Users/sandiyochristan/Documents/vulnerabilityRes/vrp_poc_app/build_manual/apk/vrppoc.apk`
