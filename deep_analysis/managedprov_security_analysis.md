# ManagedProvisioning Security Analysis

## Package: com.android.managedprovisioning
## Purpose: Device management provisioning (work profile, device owner, NFC enrollment)

## Exported Components

### Activities (exported=true, NO permission)
| Component | Actions | Risk |
|-----------|---------|------|
| PreProvisioningActivity | PROVISION_MANAGED_PROFILE, PROVISION_MANAGED_DEVICE | LOW — caller validation enforced in code |

### Activities (exported=true, WITH permission)
| Component | Permission | Actions |
|-----------|-----------|---------|
| PreProvisioningActivityViaTrustedApp | DISPATCH_PROVISIONING_MESSAGE (signature) | PROVISION_MANAGED_DEVICE_FROM_TRUSTED_SOURCE, PROVISION_FINANCED_DEVICE |
| PreProvisioningActivityViaNfc | DISPATCH_NFC_MESSAGE (system) | NFC NDEF discovery |
| SilentDeviceOwnerProvisioningReceiver | PROVISION_MANAGED_DEVICE_SILENTLY (signature) | Silent provisioning |

## Key Findings

### 1. PreProvisioningActivity Caller Validation
Despite being exported without manifest permission, the controller (`PreProvisioningActivityController.java`) enforces:
- `verifyActionAndCaller()` → `verifyCaller()` (line 632): requires `getCallingPackage()` == admin package
- If started with `startActivity()` (not `startActivityForResult()`), `getCallingPackage()` is null → fails
- `PROVISION_MANAGED_DEVICE` action explicitly blocked (line 315: `isIntentActionValid()` returns false)
- `checkDevicePolicyPreconditions()` calls `DevicePolicyManager.checkProvisioningPrecondition()` — framework enforcement
- `checkFactoryResetProtection()` — blocks if FRP is active

### 2. Flow Sequence
`initiateProvisioning()` → `tryParseParameters()` → skips pre-provisioning checks → goes to either:
- `startAppropriateProvisioning()` — delegates to role holder (Google-controlled)
- `performPlatformProvidedProvisioning()` — calls `passesPreProvisioningChecks()` which enforces ALL validation

### 3. NFC/QR Provisioning
Protected by `DISPATCH_NFC_MESSAGE` permission (system-level). Cannot be triggered by third-party app.

### 4. IMEI/Serial Leak (line 499-504)
`getAdditionalExtrasForGetProvisioningModeIntent()` passes IMEI and serial number to the admin app's GET_PROVISIONING_MODE activity. However, this only happens when `shouldPassPersonalDataToAdminApp()` returns true (initiator requested device owner mode), and the admin app must be the one specified in the provisioning params.

## Verdict
**NOT EXPLOITABLE** — all critical paths have proper caller validation despite the exported activity.
- Manifest-level permission is missing but code-level checks compensate
- Framework-level DevicePolicyManager enforces provisioning preconditions
- NFC path requires system permission
- No bypasses found in the validation chain
