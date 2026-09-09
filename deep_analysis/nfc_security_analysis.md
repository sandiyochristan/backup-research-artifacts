# NFC Stack Security Analysis

## Packages Analyzed
- `com.android.nfc` — Migration stub (3 files, not interesting)
- `com.google.android.nfc` — Main NFC stack (923 Java files)
- `com.google.android.pixelnfc` — Pixel-specific NFC (327 Java files)

## Exported Components
| Component | Type | Permission | Risk |
|-----------|------|-----------|------|
| NfcBootCompletedReceiver | Receiver | None (BOOT only) | LOW — only BOOT_COMPLETED |
| ProfileInstallReceiver | Receiver | android.permission.DUMP | LOW — requires DUMP |
| DeviceInfoContentProvider (pixelnfc) | Provider | Signature allowlist | NONE — SHA-256 signature check |

No exported activities, no exported services (PeripheralHandoverService is NOT exported).

## createPackageContext Audit (TLPE Pattern)
All calls use flag 0, target "android" framework:
- `NfcDispatcher.java:756` — `createPackageContextAsUser("android", 0, ...)`
- `NfcDispatcher.java:831` — same pattern
- `RegisteredComponentCache.java:131` — same
- `RegisteredServicesCache.java:423` — same
- `CardEmulationManager.java:506` — same

**Result: NO TLPE-like vulnerability. All flag=0, all targeting "android" package.**

## PendingIntent Analysis
- No FLAG_MUTABLE PendingIntents created by NFC code
- Foreground dispatch uses caller-supplied PendingIntent (standard API)

## NfcService Binder Methods
All protected by either:
- `NfcPermissions.enforceUserPermissions()` — requires NFC permission
- `NfcPermissions.enforceAdminPermissions()` — requires NFC admin
- `NfcPermissions.enforceSetControllerAlwaysOnPermissions()`
- Foreground check: `mForegroundUtils.isInForeground(callingUid)`

## NFC Tag Dispatch (Zero-Click Surface)
1. **Web links**: `showWebLinkConfirmation()` — user must confirm
2. **WiFi WPS tokens**: `ConfirmConnectToWifiNetworkActivity` — user must confirm
3. **Bluetooth handover**: `ConfirmConnectActivity` — user must confirm
4. **NDEF dispatch**: Uses Android's implicit intent resolution → only targets exported activities
5. **AAR (Android Application Record)**: Can specify package → opens app or Play Store

## PixelNFC DeviceInfoContentProvider
- Authority: `com.google.android.pixelnfc.provider.DeviceInfoContentProvider`
- Only URI: `/isJapanSku`
- Protected by `isCallingPackageAllowlisted()` — SHA-256 signature check against hardcoded hash
- Returns only a boolean (Japan SKU or not)

## Verdict: NO EXPLOITABLE VULNERABILITIES
The NFC stack is well-hardened:
- All dangerous operations require user confirmation
- All binder methods enforce permissions
- No TLPE pattern
- No mutable PendingIntents
- ContentProvider signature-gated
- Standard Android intent resolution for tag dispatch
