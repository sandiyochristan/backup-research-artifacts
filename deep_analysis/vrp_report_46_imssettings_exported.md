# VRP Report #46: ImsSettings Exported Activity — Unauthorized IMS Configuration Modification

## Summary

The Qualcomm IMS settings app (`com.qualcomm.qti.ims`) exports `ImsSettings` activity with an intent filter and **no permission protection**. Any zero-permission app can launch this activity, which runs in the context of a privileged system app (`WRITE_SECURE_SETTINGS`, `MODIFY_PHONE_STATE`) and allows modification of IMS provisioning values and `Settings.Global` entries.

## Affected Component

| Component | Value |
|---|---|
| Package | `com.qualcomm.qti.ims` |
| Activity | `ImsSettings` |
| Exported | `true` |
| Permission | **NONE** |
| Install Path | `/system_ext/app/imssettings/` |
| Granted Permissions | `WRITE_SECURE_SETTINGS`, `MODIFY_PHONE_STATE`, `READ_PRIVILEGED_PHONE_STATE` |

## Proof of Concept

```bash
# Launch ImsSettings from any context — no SecurityException
adb shell am start -a org.codeaurora.IMS_SETTINGS --ei phoneId 0
# Result: Starting: Intent { act=org.codeaurora.IMS_SETTINGS (has extras) }
# Activity launches and appears in task stack
```

## Impact

The activity allows modifying:
- IMS provisioning values via `ProvisioningManager.setProvisioningIntValue()`: auto-reject mode (key 1000), call composer (1004), B2C enriched calling (1005), data channel (1006), video quality (55), RTT mode (66)
- `Settings.Global` writes: `qti.settings.cs_retry`, `ims_vt_call_static_image`
- Call deflection number

User interaction is required to change values (toggle/buttons), but on a 384x384 watch screen, accidental changes are likely.

## Severity Assessment

| Factor | Assessment |
|---|---|
| Attack Vector | Local |
| Attack Complexity | LOW |
| Privileges Required | NONE |
| User Interaction | REQUIRED |
| Integrity | MEDIUM (IMS/telephony config modification) |

## Device / Build
- Pixel Watch 2, Wear OS, Build CP2A.260603.001
- Source: `deep_analysis/qti_ims_decompiled/sources/com/qualcomm/qti/ims/ImsSettings.java`
