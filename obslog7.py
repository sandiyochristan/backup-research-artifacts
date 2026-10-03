#!/usr/bin/env python3
"""Log the confused-deputy result sweep (zero sinks) + closeout of all no-account-state sink classes."""
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

obs.write("targets/SWEEP_SINK_CLASSES.md", """# Data-sink classes: exhaustive status (2026-10-02)

A sink = the attacker ends up **holding** data they could not read directly, or a privileged
state change they can observe. Per `METHODOLOGY_chain_to_sink.md`, only these count.

## CLOSED — exported content providers (365 packages)
Every exported provider has `android:permission`, `readPermission`, `writePermission`, or
`grantUriPermissions`. **Zero** unguarded. => No direct-read sink exists.

## CLOSED — confused deputy via activity results (64 activities)
Harness: new `ResultActivity` in the probe launches each target with `startActivityForResult`,
receives the result, and then **tries to read whatever Uri/Bundle came back**.
Result: **0 sinks.** 63/64 returned no result within the window (they show a picker and wait for
the user — the correct defence). The single `resCode=0` (bips `ImagePrintActivity`) returned no
data. User selection is the gate; no bypass found.

Candidate classes swept (all exported, BROWSABLE/SEND/PICK/GET_CONTENT, no permission):
contact pickers (AOSP + Google Contacts), Drive pickers, DocumentUI, Photo Picker (+ module),
Photos external picker, Google Chat `DynamiteDeepLinkMultiple` (in BOTH Gmail and AGSA),
Maps, Messages share, Files `SaveToDownloadsActivity`, YouTube upload, Play Books upload,
Keep, Lens, Translate, Tasks, Classroom, Gemini/Bard, Nearby Share `MainActivity`,
GMS `IntentFulfillmentActivity` (Tap-to-Share), Bluetooth OPP, setupwizard, gearhead bugreport.

## CLOSED — unauthenticated remote listeners
Nearby Connections = Play Integrity attested. Stetho (Messages) = SELinux blocked.

## CLOSED — intent redirection (CWE-940)
9 candidates, all `exported=false` or not registered as components.

## OPEN — web deep links: entry + chain proven, sink blocked by account state
| Target | Proven | Blocked on |
|---|---|---|
| `photos.google.com/share/.*`, `/album/.*`, `/u/0/album/.*`, `/photo/*` | attacker ID reaches victim's authenticated backend (`AsyncOperation 29503`, `GmsCoreXrpcWrapper`) | needs a **real album ID** from a populated library to show an IDOR |
| `photos.google.com/link/photo` | attacker input parsed by `PhotoOneUpDeeplinkGatewayActivity` | crash only -> DoS |
| GMS `auth.aang…DeepLinkActivity` (`accounts.google.com/devicephoneverification/begin`, exported, no permission, BROWSABLE, staging+sandbox hosts) | launches, builds `SignInRequest` from attacker query params | flow is authenticated; no credential obtained |
| `payments.google.com/gp/w/verificationhandoff`, `/gp/p/purchasemanager/xpay` | launches `ChooseAccountShimActivity` | crash only -> DoS |

## Bottom line
Every data-sink class that can be tested **without account/device state is now exhaustively
closed**. The only remaining candidate chains all terminate in the same blocker: there is no
victim data or no linked service on this device, so the final hop cannot be exercised.

**Concrete unblockers (any ONE is enough to proceed):**
1. Sign in a Google account with a **synced Photos/Drive library** → test the album/photo IDOR sink.
2. Add a **second Google account I control** → complete a real OAuth token exchange and steal it.
3. **Pair Google Home to a real structure** → presence/geofence sink unblocks immediately
   (`currentHome is null` disappears).
4. A **saved payment instrument** → Wallet/tokenization flows complete past the account chooser.
""")

m = obs.read("VRP_Master_Tracker.md")
add = """
### 2026-10-02 (5th pass) — confused-deputy result sweep = 0 sinks; all no-state sink classes closed
Built a new capability into the probe: `ResultActivity` launches any exported target with
`startActivityForResult`, captures the returned Uri/Bundle, **and tries to read it**.
Swept all **64** exported+unguarded result-returning activities across every pulled package
(contact pickers, Drive/DocumentUI/PhotoPicker pickers, Photos picker, Google Chat
`DynamiteDeepLinkMultiple` in Gmail+AGSA, Maps, Messages, Files, YouTube, Books, Keep, Lens,
Translate, Tasks, Classroom, Bard, Nearby Share, GMS Tap-to-Share, BT OPP, setupwizard).
**Result: 0 sinks** — 63 wait for user selection (correct defence), 1 returned empty OK.

This closes the last sink class that needs no account state. Combined with the earlier passes:
providers (365 pkgs), network listeners, intent redirection, and activity results are all
exhaustively closed. The ONLY remaining chains are web deep links whose final hop needs victim
data or a linked service. See `targets/SWEEP_SINK_CLASSES.md` for the 4 concrete unblockers.
"""
if "confused-deputy result sweep" not in m:
    obs.write("VRP_Master_Tracker.md", m + add)
print("logged sink-class closeout")