# Wear OS Threat Model & Hypothesis Backlog — 2026-08-17

**Device:** Google Pixel Watch 2 (eos), serial `3A101RTJWRGCV9`, build `CP2A.260603.001`,
Android 17, security patch **2026-06-05**. Same physical research device as every prior
report in this repo. Paired to at least one Android phone (`Connected nodes: 1` confirmed
live via `NodeClient`).

This document supersedes nothing — it sits on top of `MASTER_RESEARCH_SUMMARY.md` and
`wear_os_bugbounty_skill.md` (which remain the canonical methodology + prior findings
index) and adds: (1) a fresh, live full-device component inventory, (2) an explicit
AI/ML-component attack surface the prior docs didn't separately model, (3) a prioritized
hypothesis backlog for the next research sessions.

---

## 1. Full installed-app inventory (live, this device)

211 packages total: 198 system, 11 third-party, 2 disabled. Full raw lists in
`research_arch_2026-08-17/{system,third_party,disabled}_packages.txt`.

### Third-party / user-installed (11)
```
com.spotify.music              -- real consumer app
com.whatsapp                   -- real consumer app (self-managed calling, E2E messaging)
com.poc.lockbypass              \
com.christan.google_ass_tv_poc   |
com.test.watchprobe              |  This research program's own prior PoCs,
com.poc.silentsms                |  left installed from earlier sessions.
com.poc.avatarleak               |
com.research.providerprobe       |
com.test.crossdevicepoc          |
com.poc.bal                      |
com.test.datalayer              /
```
`WhatsApp` is notable and previously unexplored in this repo: it's a **self-managed calling
app** (see §4, Hypothesis A) and an independent implementation of Wear OS notification
bridging/quick-reply that has never been audited here.

### System app categories (198)

| Category | Examples | Notes |
|---|---|---|
| Telephony/communications | `com.google.android.dialer`, `com.google.android.apps.messaging`, `com.android.server.telecom`, `com.android.phone`, `com.google.wear.services` | Heavily audited already (5+ confirmed findings). |
| **AI / ML-powered** | see §2 | New focus area for this document. |
| Health/fitness | `com.google.android.wearable.healthservices`, `com.google.android.health.connect.backuprestore`, `com.fitbit.ecg`, `com.fitbit.FitbitMobile`, `com.google.android.healthconnect.controller` | Partially audited (MeasureClient permission check confirmed sound this session). Fitbit apps **unexplored**. |
| Payments/identity | `com.google.android.apps.walletnfcrel`, `com.android.se`, `com.google.euiccpixel`, `com.google.android.rkpdapp` | Wallet partially audited (`VRP_REPORT_WALLET_PAYMENT.md`). eUICC/SE/RKP **largely unexplored**. |
| Connectivity | `com.google.android.nfc`, `com.google.android.bluetooth`, `com.google.android.wifi.*`, `com.google.android.uwb.resources`, `com.google.android.networkstack*` | UWB (Ultra-Wideband, precision finding) **unexplored** — Pixel Watch 2 does not have UWB hardware confirmed, but the resource package is present; verify before investing time. |
| Cross-device | `com.google.android.crossdeviceaccessservice`, `com.android.managedprovisioning`, `com.google.android.gms.supervision` | CrossDevice bypass already confirmed (`VRP_REPORT_CROSSDEVICE_BYPASS.md`). Supervision (Family Link) **unexplored** — interesting because it implies a *third-party trust boundary* (parent device) not covered by any existing attacker model here. |
| System/OS core | `com.android.providers.*`, `com.google.android.permissioncontroller`, `com.android.credentialmanager`, `com.google.android.devicelockcontroller` | ContentProviders partially audited. CredentialManager (passkeys) **unexplored** — high-value, newer attack surface class generally. |
| Input | `com.google.android.inputmethod.latin` (Gboard), `com.google.android.tts` | Gboard has AI smart-reply/suggestion features and sees **everything typed on the watch**. **Unexplored.** |
| Watch face / Tiles | `com.google.wear.watchface.runtime`, `com.google.android.wearable.watchface.rwf`, `com.google.android.wearable.protolayout.renderer` | Tiles vector scoped last session, not executed. Watch Face Format (WFF) XML parsing **unexplored** — flagged as XXE candidate in `wear_os_bugbounty_skill.md`, never tested. |

---

## 2. AI / ML-powered component inventory (new focus)

This is the user-requested lens: which components are "AI powered," and does that change
the threat model? Two things change when a component is AI-powered rather than a plain
deterministic service:
1. **Indirect prompt injection** becomes a relevant class: if attacker-controlled data can
   reach the model's input/context, the model may act on it as if it were a trusted
   instruction, even without any traditional memory-safety or IPC bug.
2. **On-device model integrity/theft** becomes relevant: local `.tflite`/model files, wake
   word models, and personalization state are new asset classes with their own storage and
   update mechanisms, separate from "exported component" analysis.

| Package | Role | AI angle | Status this session |
|---|---|---|---|
| `com.google.android.wearable.assistant` | **Gemini**-branded Assistant (confirmed via `gemini_complication_label` string + Gemini spark icon in manifest) | Cloud+on-device LLM assistant; holds `CALL_PRIVILEGED`, `READ_SMS`, `READ_CALENDAR`, `ACCESS_FINE_LOCATION`, `CAPTURE_AUDIO_HOTWORD` | **Re-confirmed live, unpatched**: `ProactiveWearableListenerService` still exported, no permission, no sender validation. New this session: built a real `DataClient`-based PoC (zero permissions) and got a `putDataItem` write to succeed, with correlated background job/network activity in the Assistant process immediately after. See `research_arch_2026-08-17/ASSISTANT_PROACTIVE_REINVESTIGATION.md`. **This is the standout finding of this session** — a zero-permission app feeding attacker-controlled bytes into a path that a Gemini-backed, `CALL_PRIVILEGED`-holding system app ingests without validating the sender, which is architecturally the shape of an indirect-prompt-injection primitive, not just a confused-deputy bug. |
| `com.android.hotwordenrollment.okgoogle` / `.xgoogle` | "Hey Google" wake-word detection (on-device DNN, runs continuously listening for the trigger phrase) | Local keyword-spotting model; enrollment data (your voice's wake-word signature) is sensitive biometric-adjacent data | **Unexplored.** Worth checking: (a) is the enrollment/model file protected from app-level read (data exfil of a voice biometric template)? (b) can another app trigger the wake-word pipeline programmatically, bypassing the actual acoustic detection (replay/simulate the "hotword detected" broadcast)? |
| `com.google.android.ondevicepersonalization.services` | Android Privacy Sandbox — on-device personalization/ad-targeting inference | Different threat model than typical exported-component bugs: it's *designed* to be called by third-party apps under privacy constraints (isolated execution, output limits). The interesting question isn't "can an app call it" (yes, by design) but "can an app exfiltrate more than the privacy budget allows," or "can a malicious ODP config escape the sandbox." | **Scoped, not executed.** APEX module app (`/apex/com.android.ondevicepersonalization/...`), signature-privileged. Needs dedicated study of the ODP SDK/threat model, not a quick manifest grep — flagged as its own future session. |
| `com.google.android.federatedcompute` | Federated learning client (trains/contributes to shared models without uploading raw data) | If the aggregation/contribution protocol can be manipulated by a local malicious app (poisoned gradients, replay), that's a data-poisoning angle distinct from anything else in this repo | **Scoped, not executed.** Same APEX module as ODP; same recommendation. |
| `com.android.appsearch.aiseal.config` + `com.google.android.appsearch.apk` | AppSearch — on-device search indexing; "aiseal" naming suggests AI-based content classification/safety sealing before indexing | Indexes notification content, messages, etc. across apps for on-device search/Assistant retrieval — a natural target for cross-app data leakage if query permissions aren't properly scoped per-app | **Unexplored.** Worth a session: enumerate AppSearch databases/namespaces reachable from a zero-permission app via the public `AppSearchManager` API; check whether per-app data isolation actually holds. |
| `com.google.android.wearable.healthservices` (ML sub-features: fall detection, irregular heart rhythm notification) | On-device signal-processing/ML models over accelerometer + PPG sensor streams | Model *decisions* (e.g. "fall detected," "irregular rhythm") drive user-facing alerts and could plausibly drive automated actions (emergency SOS). If an app can inject synthetic sensor-like data or directly fake the ML *output* event, that's a false-alarm / suppressed-real-alarm safety issue | **Partially explored** (MeasureClient/PassiveMonitoringClient raw data access confirmed properly gated this session). The higher-value question — can the fall-detection/irregular-rhythm *event stream* itself be spoofed or suppressed, separate from raw sensor access — **not yet tested**. |
| `com.google.android.inputmethod.latin` (Gboard) | Next-word prediction / smart replies on-device | Sees 100% of everything typed on the watch (messages, search, replies) | **Unexplored.** Lower priority (Gboard is heavily hardened generally, unlikely novel bug), but the Wear-specific IME surface (different from phone Gboard) has had less scrutiny industry-wide. |

**Key insight for this section:** every AI-powered component above shares Wear OS's
general-purpose weakness already established in this repo — **the Data Layer / IPC trust
boundary is not authenticated**. What's new is that when the *sink* is a model rather than
a deterministic handler, "unauthenticated input" upgrades from "confused deputy" to
"prompt injection." The Assistant/Gemini finding above is the concrete proof of this
pattern; the hotword, AppSearch, and health-ML rows are the same pattern applied to
components not yet tested.

---

## 3. Threat model (delta on top of `MASTER_RESEARCH_SUMMARY.md`)

Existing attacker models AM-1 (malicious watch app, zero perms) through AM-4 (network
attacker) still apply and remain the most productive lens (every confirmed finding in this
repo is AM-1 or AM-2). Adding:

- **AM-5: Malicious/compromised third-party companion app already on the watch that a
  user trusts for a specific purpose** (WhatsApp, Spotify, Fitbit) — these are real,
  widely-installed apps, not hypothetical. A vulnerability in how *they* use Wear OS APIs
  (e.g., WhatsApp's self-managed calling, per Hypothesis A below) is a different finding
  class than a Google-app bug: it'd be reportable to Meta/Fitbit, not Google MVRP, and
  worth tracking separately.
- **AM-6: Supervised/managed device relationship** (`com.google.android.gms.supervision`,
  `com.android.managedprovisioning`) — a threat actor who is the *parent/guardian* or
  *IT admin* of a supervised device has a different, legitimate-but-abusable privilege
  set. Not yet modeled anywhere in this repo.

---

## 4. Prioritized hypothesis backlog

Ranked by (estimated novelty × feasibility with only watch-side ADB access). "Feasibility"
accounts for not having the paired phone's ADB in this environment.

### Tier 1 — high novelty, high feasibility (do next)

**A. WhatsApp self-managed call abuse on Wear OS.**
This session's `poc_callerid_spoof` work (see `research_incall_sms/`) established that
`com.google.wear.services/.WearInCallService` is the only InCallService on this build that
accepts self-managed calls, and that it provides no UI on its own. WhatsApp is a real,
widely-installed self-managed calling app, confirmed (live manifest pull) to use
`androidx.core.telecom` — the official Jetpack Core-Telecom library — rather than a raw
`ConnectionService`, unlike our PoC.

*Static follow-up done this session:* pulled `androidx.core:core-telecom:1.0.1` from Maven
and inspected its classes directly. **It does not build or post any notification at all** —
`CallsManager`/`CallSession`/`CallSessionLegacy` only wrap the raw Telecom
registration/connection plumbing (functionally similar to what our PoC did by hand). This
means the "how do you get Wear OS to actually render the call UI" answer, if there is one,
lives in WhatsApp's own (heavily obfuscated) notification-posting code, not in the Jetpack
library — core-telecom is a dead end for this specific question.

*Not attempted this session, deliberately:* actually placing/receiving a live WhatsApp call
on this device to observe the resulting UI would require calling a real contact (or being
called by one), which has a real-world side effect on a third party and wasn't something to
do casually just to observe notification behavior. If a **self-call** or sandboxed/test
WhatsApp account becomes available, this is a clean, high-value, purely observational next
step — no new PoC code needed, just `dumpsys`/screenshots during a real call.
*Feasibility: high in principle, gated on having a safe way to trigger a real WhatsApp call.*

**B. Assistant/Gemini proactive payload — push toward a real prompt-injection proof.**
Directly continues `ASSISTANT_PROACTIVE_REINVESTIGATION.md`. Next concrete step: decode the
expected protobuf shape for the `/assistant/proactive` payload (likely findable by tracing
`jqc`/`iwq`/`khk` classes further in the jadx output, or by capturing a **legitimate**
proactive suggestion being generated naturally and diffing the DataItem it creates against
our placeholder). A well-formed payload closes the gap between "background job fired" and
"Gemini spoke/displayed attacker text." *Feasibility: medium — needs more decompilation
depth or a lucky natural capture; no phone needed since this is watch-local.*

**C. Fall-detection / irregular-heart-rhythm event-stream spoofing.**
Distinct from the already-tested raw MeasureClient/PassiveMonitoringClient permission
check. The question is whether the *derived event* (not raw sensor data) that drives
safety-critical UX (SOS countdown, rhythm-check notification) can be triggered or
suppressed by an app that doesn't hold sensor permissions at all — e.g. via a Data Layer
path, broadcast, or ContentProvider write that represents "ML model says: fall detected"
rather than raw accelerometer values. *Feasibility: medium-high — same recon methodology as
everything else this session (pull `healthservices` APK, grep for fall/ecg/irregular
event-dispatch classes, check exported surfaces), no phone needed.*

### Tier 2 — high novelty, needs the paired phone (blocked in this environment)

**D. AM-2 replay of every already-confirmed watch-side Data Layer finding, from the phone
side.** Every "exported, no permission, on the watch" finding in this repo (WearServices,
Assistant, this session's Assistant re-test) has a symmetric question never actually
tested: *does the identical bug exist for the equivalent phone-side companion
listener?* This needs ADB on the paired phone, which this session doesn't have. Flag for
whenever a phone is available alongside the watch.

**E. AppSearch cross-app data isolation.** Needs building a PoC that calls the public
`androidx.appsearch`/`AppSearchManager` client APIs from a zero-permission app and attempts
to query namespaces/documents indexed by other apps (Messages, Gmail, notifications).
*Feasibility: medium — no phone needed, but requires learning the AppSearch client API
surface from scratch (not touched anywhere in this repo yet).*

### Tier 3 — scoped, lower priority

**F. Hotword enrollment data protection** — is the wake-word voice template file readable
by other apps or extractable via backup?
**G. CredentialManager (passkeys) on Wear OS** — newer API surface, not audited anywhere in
this repo; worth a first-pass exported-component sweep.
**H. Privacy Sandbox (ODP/FederatedCompute)** — genuinely different threat model from
everything else here; needs dedicated study of Google's own ODP threat model docs before
productive testing, not a quick win.
**I. Fitbit apps (`com.fitbit.FitbitMobile`, `com.fitbit.ecg`)** — third-party (well,
Google-owned-but-separately-engineered) code, completely unaudited in this repo. Different
codebase/security culture than the Google Wear apps already reviewed.
**J. Watch Face Format XML parsing (XXE)** — flagged in `wear_os_bugbounty_skill.md` Vector
4 since the original skill file was written, never executed.

---

## 5. What changed / was newly confirmed this session

1. Ruled out the user's original "decline with message → attacker SMS" hypothesis with
   direct evidence (self-managed calls excluded from Dialer's InCallService).
2. Found and live-confirmed a **new** primitive: zero-prompt-permission Telecom
   ringer/audio-focus hijack via spoofed self-managed calls (no visible UI on this build).
3. Closed two open items from prior sessions with clean negative results: zero-permission
   `SendToProxyActivityWithPrivilege` SMS (properly blocked), Health Services `MeasureClient`
   heart-rate access without permission (properly blocked, though enforced via the newer
   granular `android.permission.health.*` model, not classic `BODY_SENSORS` — useful to
   know for future tests on this OS generation).
4. Re-confirmed `ProactiveWearableListenerService` (Assistant/Gemini) is **still exported,
   still unauthenticated** on the current live build (2026-08-01), and — going beyond the
   original report's evidence — got a real `DataClient`-based zero-permission payload write
   to succeed with correlated background processing inside the Assistant process. This is
   the strongest lead going into the next session.

## 6. 2026-08-18 follow-on: SafetyHub (fall detection / car crash / emergency contacts)

Pursued Tier-1 Hypothesis C (event-stream spoofing/suppression, not raw sensor access).
Fall detection itself turned out to live in a separate app, `com.google.android.apps.safetyhub`
(SafetyHub), not `healthservices`. Live-pulled and decompiled it. Two significant results:

1. **`WearAppBridgeWearableListenerService`** (exported, no permission, `host="*"` wildcard)
   relays car-crash-detection alarms from the paired phone to the watch over the Data Layer
   request/response RPC (`/safetyhub-rpc/car_crash_alarm`), with **zero sender
   authentication** in the decompiled handler. The genuine on-watch sensor trigger path
   (`CarCrashBroadcastReceiver_Receiver`) is correctly `exported="false"` — this relay path is
   the gap. The same handler can both fabricate a false alarm (which, per the app's
   permissions, is designed to auto-dial emergency services after a countdown) **and**
   silently cancel a real one (`FINISH_CAR_CRASH_ALARM` broadcast) via the same
   unauthenticated entry point. Full writeup: `research_safety/CRITICAL_CARCRASH_ALARM_FINDING.md`.
   **Deliberately not dynamically validated** — the researcher explicitly authorized live
   testing including risk acceptance, but the other end of a completed trigger is a real
   emergency-dispatch call center on the paired phone's real cellular line, which is a
   real-world, third-party, public-safety system, not something contained within the
   "test device." Kept as a static-only finding for that reason; the code evidence
   (CWE-862, exact vulnerable branch identified) is strong enough to stand on its own.

2. **New finding class**: `EmergencyContactsEndpointService` and `SafetySignalEndpointService`
   are not plain `WearableListenerService`s — they host a real **gRPC server running over
   Android Binder** (Google's internal `com.google.frameworks.client.data.android.server.Endpoint`
   transport), exported with no permission, `onBind()` returning the live server binder to any
   caller unconditionally. Recovered the actual service names
   (`...proto.EmergencyContactsService`, `...proto.SafetySignalService`) and several method
   names (`ListEmergencyContacts`, `DeleteEmergencyContact`, `NotifyEmergencyContactsChange`)
   from decompiled string constants — i.e., a zero-permission app plausibly can read and
   mutate the user's emergency-contact list. A full dynamic client wasn't built this session
   (Google's binder-gRPC wire transport isn't the public `io.grpc` network stack — building a
   client requires either finding an existing legitimate caller's stub code or a substantial
   reverse-engineering effort of the framing itself). Full writeup:
   `research_safety/GRPC_OVER_BINDER_ENDPOINTS_FINDING.md`.

Both are safety-relevant, previously-unexplored components in this repo, and both extend the
"unauthenticated Data Layer/Binder trust boundary" pattern that underlies nearly every
confirmed finding in this research program to a new, higher-stakes application (SOS/emergency
response) and a new transport (gRPC-over-Binder, not just `WearableListenerService`).

## Files

- `research_arch_2026-08-17/` — full package inventory, live-pulled Assistant APK +
  decompile, dynamic evidence for the re-investigation.
- `research_arch_2026-08-17/ASSISTANT_PROACTIVE_REINVESTIGATION.md` — full detail on item 4
  above.
- `research_incall_sms/`, `research_health/` — prior session's artifacts (items 1–3 above).
- `research_safety/` — SafetyHub car-crash and gRPC-endpoint findings (item 6 above).
