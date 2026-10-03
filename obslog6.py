#!/usr/bin/env python3
"""Record the chain-to-sink methodology rule and what it filtered out."""
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

obs.write("METHODOLOGY_chain_to_sink.md", """# RULE — a finding is a proven chain that terminates in a demonstrated sink

Adopted 2026-10-02 after review. This supersedes how earlier candidates were scored.

## NOT findings (chain material only)
- An activity/service/provider **launching** (or `startActivity()` returning).
- **Bypassing a signature/permission check** and reaching a restricted component.
- Being able to **"communicate with" / bind to** an exported-but-supposedly-internal component.
- A `query()` returning null / an `insert()` returning null.
- A crash (that is DoS — separate low-severity class, never a Critical).
- "Provider reached, no SecurityException" with no rows returned.

## A finding requires ALL of
1. **Entry** — how the attacker gets in (web link / local app / network / media file).
2. **Chain** — the extra step that converts a weak primitive into a privileged capability
   (confused deputy, intent redirection, parser confusion, permission confusion, race, …).
3. **Sink** — the sensitive operation actually completed and **observed**:
   - data returned to the attacker's process (activity result / broadcast / cursor / file),
   - or a privileged state change observed (file written in another app's sandbox, setting
     flipped, account added, permission granted, object made public),
   - or attacker-controlled code executed in a privileged context.
4. **Evidence** — runtime proof, not inference. `Gf event error: 0` followed by
   `currentHome is null` is **not** a sink. A launch log is not a sink.

## Honest consequence
Re-scoring every candidate from 2026-10-02 under this rule leaves **zero** findings:

| Candidate | Why it fails the rule |
|---|---|
| Google Home geofence injection | event accepted, then stopped at `currentHome is null` → **no sink** |
| Gboard `WebDebugBridgeContentProvider` | signature allowlist — never bypassed |
| Digital Wellbeing providers | package allowlist — never bypassed |
| GMS Nearby Connections listeners | Play Integrity attestation — never bypassed |
| Stetho DevTools in Messages | SELinux blocked the connect — never bypassed |
| GMS intent-redirection sweep (9) | all `exported=false` or not registered |
| GMS Sign-In deep link (`auth.aang`) | launches, drives an authenticated flow → **no sink** |
| Photos `/link/photo` + payment deep links | crashes only → DoS, not a finding |
| Photos `/album/.*`, `/share/.*` | **entry + chain proven** (backend RPC with attacker ID via victim session) but **no sink**: needs a real album ID from a populated library |

## The binding constraint has moved
It is **no longer component discovery**. It is **account / device state**. Proving a sink now
requires:
- a Google account with a **synced Photos/Drive library** so real object IDs exist,
- a **second Google account under my control** so an OAuth token exchange can be completed and
  stolen,
- **Google Home paired to a real structure** so presence state resolves,
- a **payment instrument** so Wallet flows complete past the account chooser.

Without those, any report is inference and will be downgraded — correctly.
""")

obs.write("targets/com.google.android.apps.photos/tests/deeplink_chain.md", """# Photos deep links — entry + chain proven, SINK NOT proven

## Surface (all exported, BROWSABLE, autoVerify, NO permission, web-reachable)
| Path | Component |
|---|---|
| `photos.google.com/album/.*`, `/u/.*/album/.*` | `PrivateAlbumDeepLinkActivity` |
| `photos.google.com/share/.*`, `/u/.*/share/.*`, `/photos/.*` | `AlbumActivity` |
| `photos.google.com/link/photo` | `PhotoOneUpDeeplinkGatewayActivity` |
| `photos.google.com/link/ask_photos` | `AskPhotosDeepLinkActivity` |

## What IS proven
Attacker-chosen IDs reach the victim's authenticated backend:
```
# photos.google.com/share/<synthetic-id>
E/AsyncOperation: OperationException[Status{statusCode=unknown status code: 29503}]
I/GmsCoreXrpcWrapper: Returning a channel provider ...
```
`/share/`, `/u/0/album/`, `/photo/` all initiate real backend RPCs **using the victim's session**
from an unauthenticated web link. Entry and chain are confirmed.

## What is NOT proven — no sink
- `/link/photo` → only a crash: `IllegalArgumentException: Required value was null.` at
  `PhotoOneUpDeeplinkGatewayActivity.onCreate` → **DoS, not a finding**.
- Synthetic IDs are rejected server-side (29503). To demonstrate an **IDOR sink** (private album
  rendered from an attacker-supplied ID) a real album ID from a populated library is required.
  The test account has no synced Photos library.

**Do not report this class until a sink is demonstrated.** See `METHODOLOGY_chain_to_sink.md`.
""")

m = obs.read("VRP_Master_Tracker.md")
add = """
### 2026-10-02 (4th pass) — chain-to-sink rule adopted; re-score result = ZERO findings
Rule: **only a chain that terminates in a demonstrated sink is a finding.** Launches, signature
bypasses, "can bind to it", and crashes are chain material / DoS, never findings.
Re-scoring every 2026-10-02 candidate under this rule leaves nothing:
- 365 packages / 3,721 exported components triaged
- exported+unguarded content providers: **ZERO** → no local data sink exists at all
- unauthenticated remote sinks: **ZERO** (Nearby = Play Integrity, Stetho = SELinux)
- intent redirection: 9 candidates, all guarded or unregistered
- GMS Sign-In deep link (`auth.aang`, exported, no permission, BROWSABLE, staging+sandbox hosts in
  production): launches and drives an authenticated flow → **no sink**
- Photos deep links: entry+chain proven (backend RPC with attacker ID via victim session),
  **sink blocked** — needs real album IDs from a populated library

**New binding constraint = account/device state, not component discovery.** To prove any sink we
need a synced Photos/Drive library, a second controllable Google account (to complete an OAuth
token exchange), a paired Google Home structure, or a payment instrument. Logged in
`METHODOLOGY_chain_to_sink.md`.
"""
if "chain-to-sink rule adopted" not in m:
    obs.write("VRP_Master_Tracker.md", m + add)
print("logged chain-to-sink methodology")