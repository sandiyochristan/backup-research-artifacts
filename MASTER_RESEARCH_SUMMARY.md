# Wear OS Security Research — Master Summary & Threat Model

> **Researcher:** Sandiyochristan
> **Date:** 2026-06-30
> **Target:** Google Pixel Watch 2 (Build: CP1A.260305.014.W4, Patch: 2026-03-05)
> **Program:** Google Mobile VRP (g.co/vulnz)
> **Status:** Static analysis COMPLETE — Dynamic validation PENDING (device connection)

---

## Executive Summary

Comprehensive static analysis of 15 decompiled Wear OS APKs revealed **36 security findings** across 5 CRITICAL, 19 HIGH, and 12 MEDIUM severity vulnerabilities. The most significant discoveries are:

1. **CrossDevice Precondition Bypass** — Security checks (lock state, device secure) controlled by remote attacker input
2. **Wear Services Data Layer Injection** — Unauthenticated message dispatch to WiFi/Settings/Lock/Call handlers
3. **Wallet Payment Surface** — Exported payment services and lock-screen-bypass payment UI
4. **Content Provider Data Leaks** — SMS database, telephony, watch face data exposed without permissions
5. **Assistant Service Injection** — Previously confirmed, ready for VRP submission

---

## Threat Model

### Attacker Models

| ID | Model | Access Level | Examples |
|----|-------|-------------|---------|
| AM-1 | Malicious Watch App | Installed on watch, ZERO permissions | Fake fitness tracker, game, watch face |
| AM-2 | Compromised Phone App | App on paired phone, data layer access | Trojanized app, compromised SDK |
| AM-3 | Proximity Attacker | Physical proximity, BLE/NFC range | Evil maid, pickpocket, public transit |
| AM-4 | Network Attacker | WiFi MITM, rogue AP | Coffee shop, hotel WiFi |

### Attack Surfaces

```
┌─────────────────────────────────────────────────────┐
│                    PIXEL WATCH                        │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Wallet   │  │ Wear     │  │ CrossDevice      │  │
│  │ Payment  │  │ Services │  │ Access Service   │  │
│  │ Services │  │ (Core)   │  │ (Proximity/      │  │
│  │          │  │          │  │  Unlock)         │  │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
│       │              │                  │            │
│  ─────┴──────────────┴──────────────────┴──────────  │
│       │     DATA LAYER (wear://)        │            │
│  ─────┴──────────────────────────────────┴──────────  │
│       │                                  │            │
│  ┌────┴─────┐  ┌──────────┐  ┌─────────┴────────┐  │
│  │ Messages │  │ Dialer   │  │ Assistant        │  │
│  │ (SMS/    │  │ (Calls)  │  │ (Voice/          │  │
│  │  MMS)    │  │          │  │  Proactive)      │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │ CONTENT PROVIDERS (exported, no permissions)     │ │
│  │ • BugleContentProvider (all SMS)                 │ │
│  │ • TelephonyProvider (carrier/SIM config)         │ │
│  │ • WatchFaceInstancesContentProvider              │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
         ↕ BLE/WiFi
┌─────────────────────────────────────────────────────┐
│                   PAIRED PHONE                        │
│  ┌──────────────────────────────────────────────┐   │
│  │ Companion App (DispatchingWearableListener)   │   │
│  │ Exported, no permission, routes ALL messages  │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Key Attack Chains

**Chain 1: Financial Theft (AM-1 → Payment)**
```
Malicious Watch App → WearPayService (no perm) → Trigger payment operations
                    → TapActivity (showWhenLocked) → NFC payment while locked
```

**Chain 2: Phone Unlock (AM-2 → CrossDevice)**
```
Compromised Phone App → Data Layer message → ProximityWearableListenerService
→ Crafted protobuf with checkDeviceLock=false → Skip security checks → Start ranging
→ (When enabled) → Phone unlocks without user
```

**Chain 3: WiFi Hijack (AM-1 → Wear Services)**
```
Malicious Watch App → GcoreWearableListenerService (no perm)
→ WiFi path message → WifiSettingsListener → Add rogue network → MITM all traffic
```

**Chain 4: SMS Theft (AM-1 → Content Provider)**
```
Malicious Watch App (0 perms) → content://...BugleContentProvider/messages
→ Read ALL SMS including 2FA codes → Exfiltrate via network
```

**Chain 5: Remote Intent Execution (AM-1 → Wear Services)**
```
Malicious Watch App → GcoreWearableListenerService → /remote_intent path
→ Execute arbitrary intents with Wear Services permissions → Privilege escalation
```

---

## Findings Summary

### CRITICAL (5)

| # | Component | Vulnerability | Bounty Est. |
|---|-----------|--------------|-------------|
| C1 | WearPayService | Exported payment service, no permission | $7.5K-$15K |
| C2 | FelicaServiceImpl | Exported transit payment (but has UID check) | $3K-$7.5K |
| C3 | WalletThemedWearCardListActivity | singleTask + deep links = task hijacking in payment | $3K-$7.5K |
| C4 | GcoreWearableListenerService | Core Data Layer router, no auth, all paths exposed | $5K-$15K |
| C5 | Companion DispatchingWearableListenerService | Full Data Layer access from watch side | $3K-$7.5K |

### HIGH (19) — Top 5

| # | Component | Vulnerability | Bounty Est. |
|---|-----------|--------------|-------------|
| H1 | ProximityWearableListenerService | Precondition bypass (attacker-controlled booleans) | $5K-$10K |
| H2 | BugleContentProvider | SMS/MMS database exposed without permission | $3K-$7.5K |
| H3 | TapActivity | Lock screen payment bypass (showWhenLocked+singleTask) | $3K-$7.5K |
| H4 | CrossDevice Sensor/KeyguardReceivers | Injectable event data, no sender validation | $2K-$5K |
| H5 | Messages WearableService | Data Layer SMS operations without permission | $2K-$5K |

---

## VRP Reports Ready

| Report File | Target | Status |
|-------------|--------|--------|
| `VRP_REPORT_CROSSDEVICE_BYPASS.md` | CrossDevice precondition bypass | ✅ Ready |
| `VRP_REPORT_WEARSERVICES_DATALAYER.md` | Wear Services Data Layer injection | ✅ Ready |
| `VRP_REPORT_WALLET_PAYMENT.md` | Wallet payment services | ✅ Ready |
| `VRP_REPORT_CONTENT_PROVIDERS.md` | Content provider data leaks | ✅ Ready |
| `VRP_REPORT_ASSISTANT.md` | Assistant ProactiveWearableListenerService | ✅ Ready (from prior session) |

---

## Dynamic Test Plan

See `DYNAMIC_TEST_PLAN.md` for complete ready-to-run ADB commands.

**Priority execution order when device is connected:**
1. TEST 1: Wallet WearPayService (highest bounty)
2. TEST 5: Wear Services Data Layer (broadest impact)
3. TEST 6: Content Providers (easiest to confirm)
4. TEST 4: CrossDevice Proximity (most novel)
5. TEST 2: Wallet TapActivity lock screen
6. TEST 10: Voice SMS bypass (existing research)

---

## What Happens Next

### When Device Connected:

1. **Run `DYNAMIC_TEST_PLAN.md`** — Execute all 11 test groups
2. **Capture evidence** — Screenshots, logcat, dumpsys outputs
3. **Triage results:**
   - SecurityException → NOT vulnerable (mark as secure)
   - Service starts / Data returned → CONFIRMED vulnerability
   - Crash → Potential DoS (separate report)
4. **For each confirmed finding:**
   - Update VRP report with dynamic evidence
   - Record screen if applicable
   - Submit to g.co/vulnz

### Submission Strategy:
- Submit highest-severity findings first (Wallet, Wear Services)
- Group related findings if they form an attack chain
- Submit CrossDevice as a design-level vulnerability (future risk)
- Include proposed patches in all reports

---

## Files Created This Session

```
/Users/sandiyochristan/Documents/vulnerabilityRes/
├── DYNAMIC_TEST_PLAN.md              ← All ADB test commands
├── VRP_REPORT_CROSSDEVICE_BYPASS.md  ← CrossDevice precondition bypass
├── VRP_REPORT_WEARSERVICES_DATALAYER.md ← Wear Services Data Layer
├── VRP_REPORT_WALLET_PAYMENT.md      ← Wallet payment vulnerabilities
├── VRP_REPORT_CONTENT_PROVIDERS.md   ← Content provider data leaks
├── MASTER_RESEARCH_SUMMARY.md        ← This document
└── pulled_apks/
    ├── manifests/                     ← All extracted AndroidManifest.xml
    ├── wallet_decompiled/             ← NEW: Google Wallet source
    ├── crossdevice_decompiled/        ← NEW: CrossDeviceAccessService source
    ├── wearservices_decompiled/       ← NEW: Wear Services source
    ├── telecom_decompiled/            ← NEW: Telecom server source
    ├── credentialmanager_decompiled/  ← NEW: Credential Manager source
    ├── providers_telephony_decompiled/ ← NEW: Telephony provider source
    ├── bluetooth_decompiled/          ← NEW: Bluetooth stack source
    ├── nfc_decompiled/                ← NEW: NFC service source
    ├── supervision_decompiled/        ← NEW: GMS Supervision source
    ├── devicelock_decompiled/         ← NEW: Device Lock Controller source
    └── euicc_decompiled/              ← NEW: eSIM management source
```

---

## Estimated Total Bounty Potential

| Scenario | Amount |
|----------|--------|
| All findings confirmed (best case) | $40,000-$75,000+ |
| 50% confirmation rate (realistic) | $20,000-$35,000 |
| Conservative (top 3 only) | $10,000-$25,000 |

**Key insight:** The CrossDevice precondition bypass is the most novel and unique finding. Even though the feature is currently disabled, the design flaw in production code makes this a strong VRP submission targeting a future-critical security issue.
