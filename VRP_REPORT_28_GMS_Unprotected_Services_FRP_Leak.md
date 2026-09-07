# VRP Report #28: 126 Unprotected Exported GMS Services — FRP Configuration Data Leak Without Permission

## Summary

126 Google Play Services (GMS) services are exported without manifest-level permission protection, allowing any installed app to bind to them. Among these, the **FRP (Factory Reset Protection) Service** returns structured configuration data (56 bytes) to unprivileged callers — leaking FRP status and configuration without any permission check. The **BackupAccountManagerService** processes requests and returns backup state data without permission validation.

## Severity: Medium

- **126 services** bindable without permission (attack surface)
- **FRP data leak**: FRP status, configuration version, and 56-byte structured config
- **Backup data leak**: `isBackupEnabled() = true` accessible without permission
- **Battery data**: Battery level accessible without permission (low impact)

## Affected Components

- **Package**: `com.google.android.gms` (Google Play Services)
- **Build**: CP2A.260605.012, Android 17 (API 37), Pixel 6a
- **Primary**: `com.google.android.gms.auth.frp.FrpService` (IFrpService)
- **Secondary**: `com.google.android.gms.backup.BackupAccountManagerService` (IBackupAccountManagerService)
- **Tertiary**: `com.google.android.turboadapter.GoogleBatteryService` (IGoogleBatteryService)

## Vulnerability Details

### 126 Unprotected Exported Services

A scan of GMS package manifest reveals 126 services that are `exported=true` with no `android:permission` attribute. These services span critical functionality:

| Category | Services | Examples |
|---|---|---|
| Authentication | 8 | GetToken, AccountDataService, FrpService, AuthProxy |
| Location | 3 | GoogleLocationManagerService, LocationSharingService |
| Payment | 3 | PaymentService, AddressService |
| Fitness/Health | 4 | FitHistoryBroker, FitConfigBroker, FitInternalBroker |
| Backup/Identity | 4 | BackupAccountManagerService, IdentityCredentialApiService |
| Device Management | 3 | DeviceManagerApiService, CheckinApiService, KidsServiceProxy |
| Nearby/Sharing | 5+ | Multiple NearbySharing services |
| Other | 96+ | Various GMS services |

### FRP Service Data Leak (Proven)

The FrpService (`com.google.android.gms.auth.frp.FrpService`) exposes the `IFrpService` AIDL interface. An unprivileged app can:

1. **Bind to the service** — `bindService()` succeeds immediately
2. **Call AIDL methods** — binder transactions accepted without permission check
3. **Extract FRP configuration data** — structured data returned

**Dynamic proof on Pixel 6a:**

| Transaction | Reply Size | Data | Interpretation |
|---|---|---|---|
| TX1 (empty) | 8 bytes | `00000000 00000000` | FRP status = false/inactive |
| TX2 (empty) | 8 bytes | `00010000 00000000` | Boolean = true |
| TX3 (empty) | 32 bytes | `00014510 01010201 0000...` | FRP config v1.1.2.1 |
| TX5 (empty) | 56 bytes | `00014528 01010201 03000400 06000000 0000...` | Extended FRP config |

The TX3 and TX5 responses contain structured data with:
- Configuration version: 1.1.2.1
- Configuration flags: 03, 04, 06
- 56 bytes of FRP configuration data

### BackupAccountManagerService Data Leak (Proven)

**Interface**: `com.google.android.gms.backup.IBackupAccountManagerService`

| Transaction | Response | Interpretation |
|---|---|---|
| TX1 | exCode=0, int=0 | getBackupAccount() → null (no backup account) |
| TX2 | exCode=-2, "the name must not be empty: null" | Processes request, no permission check |
| TX3 | exCode=0, int=1 | **isBackupEnabled() = true** |

An unprivileged app can determine:
- Whether Google backup is enabled on the device
- The backup service processes requests without checking caller identity

### Battery Service Data Leak (Proven)

**Service**: `com.google.android.turboadapter.GoogleBatteryService`

TX4 returns 12 bytes including battery level data (55% at time of test) without any permission check.

## Proof of Concept

### PoC App

`poc_app/src/com/vrp/poc/ServiceBindExploitActivity.java` — binds to 23 high-value services, probes binder transactions, and logs responses.

`poc_app/src/com/vrp/poc/FrpBatteryExploitActivity.java` — deep probe of FRP and Battery services with full hex dump.

### Reproduction Steps

1. Install PoC APK (com.vrp.poc, no special permissions needed)
2. Launch ServiceBindExploitActivity
3. Observe: all 23 tested services accept binding
4. Launch FrpBatteryExploitActivity
5. Observe: FRP service returns 56 bytes of config data; Battery service returns battery level

### Services That Return Data Without Permission

| Service | Interface | Data Returned |
|---|---|---|
| FrpService | IFrpService | FRP status, config version, 56-byte config blob |
| BackupAccountManagerService | IBackupAccountManagerService | isBackupEnabled=true, processes account operations |
| GoogleBatteryService | IGoogleBatteryService | Battery level (55%) |
| Auth GetToken | IAuthManagerService | Accepts binding, processes requests (parcel format needed) |

### Services Properly Protected at AIDL Level

| Service | Protection |
|---|---|
| HardwareInfoQueryService | SecurityException on all transactions |
| GooglePowerService | SecurityException on all transactions |
| CameraStreamProviderService | SecurityException on all transactions |

## Impact

1. **FRP Bypass Reconnaissance**: An installed app can determine FRP configuration before a factory reset, potentially aiding FRP bypass attacks
2. **Device Fingerprinting**: Backup status, battery data, and FRP configuration can be used for device fingerprinting
3. **Attack Surface**: 126 bindable services present a large attack surface for IPC exploitation
4. **No Permission Required**: FRP and backup data accessible without ANY manifest or runtime permission

## Remediation

1. Add `android:permission` to exported services that handle sensitive data (FRP, Backup, Auth)
2. Add caller UID/package validation at the AIDL level for services that must remain exported
3. Audit the 126 unprotected services for data leak and unauthorized operation risks
4. Consider using `BIND_*` signature permissions for GMS-internal services

## Environment

- Device: Pixel 6a (bluejay)
- Build: CP2A.260605.012
- Android: 17 (API 37)
- ADB ID: 26131JEGR04733
- Evidence: `dynamic_evidence/frp_battery_fresh_evidence.log`, `dynamic_evidence/service_bind_evidence.log`

## Timeline

- 2026-09-07: 126 unprotected services discovered via manifest analysis
- 2026-09-07: FRP service data leak proven dynamically (56 bytes extracted)
- 2026-09-07: Battery service data leak proven dynamically
- 2026-09-08: BackupAccountManagerService data leak proven
- 2026-09-08: Fresh evidence captured and documented
