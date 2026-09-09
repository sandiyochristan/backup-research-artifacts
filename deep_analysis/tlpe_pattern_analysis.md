# TLPE (CVE-2026-49881) Pattern Analysis

## Known Vulnerability Confirmed on Device

**InCallController.java:2277** — VULNERABLE (unpatched)
```java
Class.forName(serviceInfo.name, false, 
    this.mContext.createPackageContextAsUser(serviceInfo.packageName, 3, userHandle).getClassLoader());
```
- Device build: CP2A.260605.012 (June 2026)
- Fix: September 2026 Android Security Bulletin
- Flag 3 = CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY
- Runs in system_server (UID 1000)
- Triggered via TelecomManager.addCall() with MANAGE_OWN_CALLS permission

## Variant Hunt Results

### createPackageContext with flag 3 + variable package name (App-level, NOT system_server):

| File | Package Variable | Resolves To | Exploitable? |
|------|-----------------|-------------|-------------|
| maps/npf.java:26 | bixt.a(context, ...) | Android Auto SDK | No — Google-signed |
| maps/ctcn.java:47 | ((ctco)this.c).a | VR Core | No — Google-signed |
| camera/vov.java:40 | this.c.a | VR Core | No — Google-signed |
| searchlens/uxz.java:59 | packageName | GMS dynamite | No — Google-signed |
| searchlens/ghdq.java:42 | this.c.a | VR Core | No — Google-signed |
| recorder/nky.java:133 | sXcYWpZGeU.XaPbag | GMS dynamite | No — Google-signed |

All run in app context, not system_server. Package names resolve to Google-signed system apps.

### createPackageContextAsUser (cross-user, all flag 0 — safe):

Settings, CalendarProvider, MediaProvider, Launcher — all use flag 0, meaning resources only, no code loading. No TLPE risk.

### DynamiteModule pattern (flag 3, hardcoded GMS):

~20+ apps use `createPackageContext("com.google.android.gms", 3)` for GMS Dynamite module loading. This is Google's standard dynamic code loading from Play Services. Not exploitable — package name is hardcoded to GMS which is system-signed.

## Conclusion

No novel TLPE variants found. The only system_server-level `createPackageContextAsUser` with CONTEXT_INCLUDE_CODE on an attacker-controllable package name is the known CVE-2026-49881 in InCallController. The device IS vulnerable to this CVE but it's already public knowledge.
