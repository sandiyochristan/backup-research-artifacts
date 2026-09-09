# Bluetooth Stack Security Analysis

## Package: com.google.android.bluetooth
## Build: SDK 36 (Android 16/17)

## Exported Components (No Permission)

| Component | Type | Permission | Risk |
|-----------|------|-----------|------|
| BluetoothMediaBrowserService | Service | NONE | HIGH — Same vulnerability as VRP #39/#40 |
| AvrcpCoverArtProvider | Provider | NONE | LOW — Only album art, enabled=false by default |
| BluetoothOppReceiver | Receiver | NONE | LOW — OPP event handling |
| BluetoothOppLauncherActivity | Activity | NONE | LOW — File share launcher |
| BluetoothOppTransferHistory | Activity | NONE | LOW — Transfer history UI |
| PbapClientAccountAuthenticatorService | Service | NONE | LOW — Account authenticator, standard Android pattern |

## Key Findings

### 1. BluetoothMediaBrowserService (CONFIRMED — Systemic Pattern)
- **File**: BluetoothMediaBrowserService.java:229
- `onGetRoot()` accepts ALL callers, returns `BrowseTree.ROOT`
- Any app can connect, get MediaSession token, monitor BT audio playback
- Same vulnerability class as YouTube (VRP #39) and YouTube Music (VRP #40)
- This makes 3 Google apps with unprotected MediaBrowserService

### 2. BluetoothOppProvider — SQL Query (MITIGATED)
- Exported with path-permission on `/btopp` requiring ACCESS_BLUETOOTH_SHARE
- Uses `setStrict(true)` — SQL injection mitigated
- Contains OPP transfer records (filenames, MAC addresses, timestamps)

### 3. AvrcpCoverArtProvider — Exported ContentProvider
- Exported=true, no permission, grantUriPermissions=true
- BUT enabled=false by default — only active when AVRCP controller is active
- `openFile()` takes `device` MAC and `uuid` query params
- Returns cover art bitmaps only — limited data sensitivity

### 4. SAP Service — Unprotected Broadcast
- SapService.java:636 — `sendBroadcast(new Intent(USER_CONFIRM_TIMEOUT_ACTION))` without permission
- Any app can register a receiver for `com.android.bluetooth.sap.USER_CONFIRM_TIMEOUT`
- LOW impact — only reveals SAP connection timeout events

### 5. HeadsetSystemInterface — Unprotected Broadcast
- Line 243: `sendBroadcast(intent)` for `android.intent.action.STOP_VOICE_COMMAND`
- No permission protection — any app can listen for voice command stop events

### 6. No TLPE Pattern Found
- No `createPackageContext` with flag 3 (CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)
- No FLAG_MUTABLE PendingIntents

## Verdict
- **BluetoothMediaBrowserService**: Already documented as systemic issue (VRP #39/#40)
- **Overall**: Bluetooth stack is reasonably well-secured for the attack surface size
- **No novel high-impact vulnerabilities found beyond the known MediaBrowserService pattern**
