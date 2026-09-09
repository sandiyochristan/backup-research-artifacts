# Google Maps Security Analysis

## Attack Surface

### Exported Components (no permission)
- **MapsActivity**: 25+ intent filters, handles geo:, google.navigation:, google.streetview:, google.maps: schemes, plus HTTP/HTTPS for 200+ maps.google.* domains
- **SpotifyAuthCallbackActivity**: Dead end — redirect scheme/host are empty strings
- **GmmCarProjectionService**: Car projection, no permission
- **GmmWearableListenerService**: Wearable data listener, no permission

### JavaScript Bridge Interfaces (6 found)
1. **`AGMM`** (whi.java) — CRITICAL: `openUrl()` method takes URL, parses 2 path segments as packageName/className, calls `setClassName()` + `startActivity()` with JSON extras. Attached in decommissioning/Lighter webview flow (ndy.java:3767 → whg.java:29)
2. **`hostRequest`** (badl.java) — Protobuf-based request/response bridge. Posts Base64-encoded protobuf messages. Routes to registered handlers.
3. **`clientResponse`** (badh.java) — Companion to hostRequest for response handling
4. **`LighterEmbeddedWebBridge`** (buco.java/bubg.java:219) — Used in the Lighter Embedded WebView
5. **`localpage_ext_NAAPI`** (NativeApiImpl.java/baba.java:220) — Native API for local pages. Has `callFunction()` method that dispatches to registered native functions
6. **`_402m_native`** (aqak.java:95) — Telemetry/logging bridge

### GENERIC_WEBVIEW_NOTIFICATION Flow
- Intent action: `com.google.android.apps.gmm.GENERIC_WEBVIEW_NOTIFICATION`
- Registered on exported MapsActivity with http/https schemes
- Handler (aqcj.java): Extracts URL from `intent.getData()` and passes to webview
- WebView (oal.java): JavaScript enabled, loads URL directly
- URL filtering (oaj.java): HTTPS URLs ALWAYS load without filtering
- Does NOT have AGMM bridge attached (only cache clearing via bjbr.ac)

### AGMM Bridge openUrl() Analysis (whi.java:126-161)
```
openUrl(String str):
  1. Parses str as URI
  2. Extracts "extras" query param (JSON parsed to Intent extras)  
  3. If path has exactly 2 segments: treats as packageName/className
  4. Calls intent.setClassName(segment[0], segment[1])
  5. If resolveActivity succeeds: starts the activity with JSON extras
  6. Otherwise: falls back to ACTION_VIEW intent
```
This is a JavaScript-to-native intent redirect. Any JS code running in a WebView with this bridge can launch arbitrary app activities with attacker-controlled extras.

**Exploitation requirement**: Need to get attacker-controlled JavaScript to run in a WebView that has the AGMM bridge attached. The AGMM bridge is attached in the decommissioning/Lighter webview flow, not the generic webview. Would need to find a way to inject content into that specific webview.

## Verdict
- **GENERIC_WEBVIEW_NOTIFICATION**: Loads attacker-controlled HTTPS URLs in Maps WebView with JS enabled. No AGMM bridge, but potential for phishing within Maps UI.
- **AGMM openUrl()**: Powerful intent redirect primitive, but only available in specific WebView instances that load Google-controlled URLs.
- **Maps has no exported ContentProviders** — unusual for a Google app this large.

## Potential for further investigation
- Trace exactly what URLs the decommissioning webview loads (are any attacker-influenceable?)
- Check if NativeApiImpl.callFunction() can be chained to sensitive operations
- Test GENERIC_WEBVIEW_NOTIFICATION dynamically — does it actually load attacker URLs?
