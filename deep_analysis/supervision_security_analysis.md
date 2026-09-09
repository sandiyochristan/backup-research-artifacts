# GMS Supervision Security Analysis

## Package: com.google.android.gms.supervision
## Component: Parental Controls / Family Link

## Architecture
GMS Supervision uses Google's Chimera module-loading framework. Most activities and services are thin proxies (`jdr` extends `GmsActivityProxy`) that load their real implementation from the main GMS APK at runtime. This means the actual business logic is in `com.google.android.gms`, not in this APK.

## Exported Components (No Permission)

### Activities
| Component | Intent Actions | Risk Assessment |
|-----------|---------------|-----------------|
| KidSetupActivity | DM_PRE_ADD_ACCOUNT, DM_PRE_REMOVE_ACCOUNT, ENFORCE_LAUNCHER, VIEW_ULP_APP_BLOCK, CONTINUE_FROM_SETTINGS, ADD_SECONDARY_ACCOUNT, HANDLE_MANAGED | MEDIUM — Any app can launch these flows |
| SettingsActivity | MANAGE_SUPERVISOR_RESTRICTED_SETTING | MEDIUM — Any app can trigger settings management UI |
| TransparencyActivity | SHOW_PARENTAL_CONTROLS | LOW — Informational only |

### Services
| Component | Intent Actions | Protection |
|-----------|---------------|------------|
| GmsApiService | supervision.service.START, kids.service.START | ZeroPartyBinder validates caller UID is GMS + signature check |
| PersistentDirectBootAwareApiService | kids.parentalcontrols.service.START | ZeroPartyBinder + visibleToInstantApps=true |
| KidsServiceProxy | (exported, no filter) | ZeroPartyBinder |

### Receivers
- `PersistentTrustedReceiver`: Handles PACKAGE_ADDED/REMOVED, ACCOUNT_REMOVED, BOOT_COMPLETED, DEVICE_OWNER_CHANGED, etc.
- `PersistentInternalReceiver`: Handles GOOGLE_ACCOUNT_CHANGE, SUPERVISION_ACCOUNT_CHANGE, Phenotype flags

## Key Findings

### 1. Service Layer: WELL PROTECTED
The `ZeroPartyBinder` (wig.java) wraps service binders with:
- UID check: `lbc.a(context, Binder.getCallingUid(), "com.google.android.gms")` — only GMS can bind
- Signature check: `checkSignatures(callingUid, a)` — must have matching GMS signatures
- Exception: `kyn.j(context)` — some bypass condition (likely for testing/debug, needs device verification)

The IKidsService binder interface (mal.java) exposes ~30+ methods including:
- `z()` → `revokeSupervision` — removes parental controls
- `y(String, boolean)` → removes supervised account from device
- Various restriction management methods

All of these are behind ZeroPartyBinder validation.

### 2. Activity Layer: MODERATE RISK — Exported Without Permission
`KidSetupActivity` accepts 7 different actions without any manifest-level permission. While the actual implementation is in GMS's Chimera module (so we can't trace the full flow), the exported actions include:
- **DM_PRE_REMOVE_ACCOUNT**: Could potentially trigger the account removal flow
- **ENFORCE_LAUNCHER**: Could trigger launcher enforcement
- **ADD_SECONDARY_ACCOUNT**: Could trigger secondary account addition

**Potential Attack**: A malicious app could:
1. Launch `KidSetupActivity` with `DM_PRE_REMOVE_ACCOUNT` action
2. This presents the account removal UI to the user
3. If the user (especially a child) is confused, they might proceed with removing supervision

This is a **UI confusion/social engineering** attack rather than a direct bypass.

### 3. Feature Flag (kyn.j) Bypass in ZeroPartyBinder
```java
if (!kyn.j(context)) {
    // UID and signature checks
}
```
If `kyn.j(context)` returns true, the ZeroPartyBinder SKIPS all caller validation. This appears to be a debug/testing flag. **Needs device testing** to determine if this flag is enabled in production.

### 4. ACTION_START_RING — Not Directly Accessible
The `ACTION_START_RING` service intent is only sent internally via `context.startService()` from within the supervision code. The SupervisionChimeraService is NOT directly exported in the manifest (it runs inside the Chimera module proxy).

## Verdict
- **Service layer**: Well-protected by ZeroPartyBinder (signature + UID checks)
- **Activity layer**: Exported without permissions — UI confusion attacks possible
- **Priority**: LOW-MEDIUM for VRP — the actual operations require authentication/authorization in the GMS module layer
- **Needs device testing**: The `kyn.j()` flag bypass in ZeroPartyBinder could be significant if it's enabled in production builds

## Recommendations for Further Analysis
1. **Device test**: Check if `kyn.j()` flag bypasses ZeroPartyBinder in production
2. **GMS module analysis**: Decompile GMS to trace the actual KidSetupActivity Chimera module implementation
3. **Intent parameter injection**: Test if extra parameters in the DM_PRE_REMOVE_ACCOUNT intent affect the flow behavior
