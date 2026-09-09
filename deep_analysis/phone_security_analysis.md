# com.android.phone Security Analysis

## Package Details
- **Package**: com.android.phone
- **UID**: android.uid.phone (shared)
- **Permissions**: 80+ privileged permissions (SEND_SMS, CALL_PRIVILEGED, MODIFY_PHONE_STATE, etc.)
- **Process**: Runs as system phone process

## Exported Components

### ContentProviders (exported=true)
| Provider | Permissions | Risk |
|----------|-----------|------|
| IccProvider (authority: "icc") | READ_CONTACTS / WRITE_CONTACTS | LOW — standard SIM contacts, perm-gated |
| SimPhonebookProvider | READ_CONTACTS / WRITE_CONTACTS | LOW — perm-gated |
| ServiceStateProvider | MODIFY_PHONE_STATE | LOW — signature-level perm |

### Activities (exported=true, NO permission)
| Activity | Actions | Assessment |
|----------|---------|-----------|
| EmergencyDialer | DIAL, CALL_EMERGENCY, CALL_PRIVILEGED | LOW — by design, pre-fills emergency number |
| SimContacts | VIEW | LOW — requires READ_CONTACTS to view data |
| FdnList | - | LOW — requires SIM PIN |
| SatelliteConfigViewer | VIEW | MEDIUM — leaks satellite config JSON, country codes, PLMN lists, Starlink/Skylo versions |
| EnableIccPinScreen | - | LOW — requires SIM PIN knowledge to operate |
| ChangeIccPinScreen | - | LOW — requires current SIM PIN |
| CallFeaturesSetting | - | LOW — UI only, no direct call forwarding API |
| AccessibilitySettingsActivity | - | LOW — informational |
| EuiccPublicActionUiDispatcherActivity | START_EUICC_ACTIVATION | LOW — only handles activation flow |
| EmergencyCallbackModeExitDialog | - | LOW — UI dialog |
| PhoneAccountSettingsActivity | - | LOW — settings UI |
| VoicemailSettingsActivity | - | LOW — settings UI |
| RadioInfo | - | MEDIUM — has network type, SMSC, radio power controls (see below) |
| PhoneInformationV2 | MAIN | MEDIUM — hidden dev menu with carrier config override, network type change, satellite controls |

### Receivers (exported=true, NO permission)
| Receiver | Assessment |
|----------|-----------|
| VvmSmsReceiver | LOW — processes VVM SMS parcels, not directly injectable |
| SafetySourceReceiver | LOW — only triggers `refreshSafetySources()` on REFRESH action |

## Key Analysis

### RadioInfo (MEDIUM risk)
Exported activity with NO permission protection. Contains:
- **Preferred network type selector**: `mTelephonyManager.setAllowedNetworkTypesForReason()` — NO mSystemUser guard, but requires user UI interaction to select from spinner
- **Radio power toggle**: `phone.setRadioPower(z)` — gated by `mSystemUser` check
- **SMSC update**: Hidden when `!mSystemUser`
- **Mock signal strength**: Hidden when `!Build.isDebuggable() || !mSystemUser`
- **Data toggle**: Gated by `mSystemUser` (line 462)
- **Simulate OOS**: Hidden when `!Build.isDebuggable()`

**Verdict**: On production user builds, most dangerous operations are hidden or gated. The preferred network type spinner is accessible but requires physical user interaction. Not exploitable programmatically from another app beyond opening the UI.

### TLPE Pattern Search
Only `createPackageContextAsUser()` calls found in NotificationMgr.java with flag 0 (not INCLUDE_CODE) and using own package name. No TLPE-like patterns.

### GsmUmtsCallForwardOptions
`onActivityResult()` queries `intent.getData()` but this is from an activity result (contact picker), not directly injectable from an attacker app.

## Verdict
com.android.phone is well-hardened for a system-privileged app:
- All ContentProviders require permissions
- Dangerous RadioInfo features gated by build type and system user checks
- No SQL injection surfaces found (IccProvider delegates to framework)
- No TLPE patterns
- No zero-permission data leaks

**Priority: LOW for VRP**
