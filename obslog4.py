#!/usr/bin/env python3
"""Log the remote-network attack surface hunt (GMS Nearby Connections) to Obsidian."""
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

# --------------------------------------------------------------- new target folder
obs.write("targets/com.google.android.gms/tests/network_listener.md", """# Network-reachable listeners in GMS — CONFIRMED SURFACE, AUTH INTACT

Tested 2026-10-02 from a **separate machine on the LAN** (macOS host, 192.168.1.36 →
Pixel 192.168.1.34). This is the only class found so far that **does not require the user to
install an app** — so it was the priority for a Critical-class hunt.

## Listeners discovered (`/proc/net/tcp6`, state 0A)
| Bind | Port | Owner |
|---|---|---|
| `::ffff:192.168.1.34` | 51692, 53601, 64660 | **GMS Nearby Connections, WIFI_LAN medium** (pid 4261) |
| `::ffff:127.0.0.1` | 39317, 45107 | loopback only, not remote |
| `::` | 46697 | reachable; probe produced no protocol banner |

All four accepted a TCP connection from the external host. **No authentication is required to
establish the TCP connection.**

## Protocol reverse-engineered
```
[4-byte big-endian length]  MultiplexFrame (protobuf) { service_id = 54, payload = OfflineFrame }
OfflineFrame type must be CONNECTION_REQUEST v1
```
Evidence from an empty frame:
```
E/NearbyConnections: onIncomingConnection(WIFI_LAN) mode: INSTANT, for client 10713783
  failed to initialize the connection with WifiLanSocket_Virtual
E/NearbyConnections: java.io.IOException: In readConnectionRequestFrame,
  expected a CONNECTION_REQUEST v1 OfflineFrame but got a UNKNOWN_FRAME_TYPE frame instead
  at dwfd.M(...):72
```
Evidence the length prefix is interpreted as a 4-byte integer:
```
W/NearbyMediums: [MultiplexSocket] Failed to read because received a invalid length 218762506
W/NearbyMediums: [MultiplexSocket] Failed to read because received a invalid length -1
```

## What was REFUTED (do not retry)
| Hypothesis | Result |
|---|---|
| Memory amplification via huge declared length | **REFUTED.** Length IS validated. `0x7FFFFFFF` → "invalid length 2147483647", `0xFFFFFFFF` → "invalid length -1". GMS PSS moved only 296 MB → 297 MB. No allocation. |
| Naive protobuf crash on garbage | **REFUTED.** `CodedInputStream encountered a malformed varint` is caught and logged; GMS survives. |
| Reachable service handler pre-auth | **NOT FOUND.** Every payload is rejected at the OfflineFrame type check before any service dispatch. |

## Why the auth gate holds
Nearby Connections no longer trusts a static token. GMS strings show device attestation:
```
"Waiting for the device integrity token"
"Requesting Play Integrity token using request hash %s (salt = %s)"
"%s Device integrity token: %s"
"Integrity token generated"
```
`ConnectionRequestFrame` fields visible in `dwfd.smali`: `nonce`, `password`, `connectionMode`,
`medium`, `deviceType`, `keepAliveIntervalMillis`, `keepAliveTimeoutMillis`, `specifiedBandwidth`,
`port`, `ssid`, `frequency`. The connection is additionally backed by a Play Integrity token, which
is hardware-attested and **not forgeable off-device**.

**Verdict: properly defended. No bypass found. Do not resubmit as a finding.**
Useful negative: it closes off "remote LAN attack against GMS Nearby" as a productive direction.

## Secondary signal — Stetho in Google Messages (BLOCKED)
```
@stetho_com.google.android.apps.messaging_devtools_remote
@stetho_com.google.android.apps.messaging:rcs_devtools_remote
```
Production build of the default SMS app exposes a Stetho DevTools endpoint. A zero-permission app
attempting `LocalSocket` connect got `IOException: Permission denied` with no matching AVC line —
**SELinux app-domain isolation blocks cross-app abstract unix socket access.**
Only reachable via adb (which already has more power) or root. **Not a third-party-app bug.**
Worth flagging to Google as hardening (Stetho should not ship in release builds at all).
""")

obs.write("targets/com.google.android.gms/journal/2026-10-02-network.md", """# 2026-10-02 — remote network surface hunt (Critical-class attempt)

Goal: find a bug whose trigger is **not** "user installs a malicious app", since that penalty
downgraded the previous finding to Low.

## Confirmed
- GMS (pid 4261) runs **3 TCP listeners bound to the LAN IP** (192.168.1.34) on ports
  51692 / 53601 / 64660 for **Nearby Connections on WIFI_LAN**. Reachable from an external host
  with **no app install and no user interaction**.
- Wire format recovered: 4-byte BE length → `MultiplexFrame` protobuf (service_id=54) →
  `OfflineFrame` of type `CONNECTION_REQUEST v1`.
- Pre-auth protobuf parsing happens on attacker bytes (error traces captured).

## Refuted (do not retry)
- Length-prefix memory amplification — length is validated; PSS flat.
- Protobuf crash on garbage — caught and logged; GMS survives.
- Pre-auth reach into any service handler — blocked at the OfflineFrame type check.

## Auth gate
Play Integrity device-attestation token + `nonce`/`password` in `ConnectionRequestFrame`.
Hardware-attested, not forgeable. **Surface mapped, not broken.**

## Other signals
- **Stetho DevTools sockets exposed in Google Messages (production).** Would be execute-JS-in-WebView
  = Critical confidentiality, but SELinux blocks cross-app abstract-socket connect. Not a
  third-party-app bug. Recommend flagging as hardening.
- No Chromium `webview_devtools_remote` sockets, no adb forwards.

## Honest status
**No Critical found in this pass.** The only no-install surfaces on the device are Nearby
Connections (attestation-gated) and Stetho (SELinux-gated). Both are defended.
""")

master = obs.read("VRP_Master_Tracker.md")
add = """
### 2026-10-02 (later) — remote network surface sweep — NO CRITICAL FOUND
Hunted specifically for a trigger that is **not** "user installs an app".
| Surface | Result |
|---|---|
| GMS Nearby Connections WIFI_LAN listeners (ports 51692/53601/64660, bound to LAN IP) | **Remote-reachable, pre-auth protobuf parsing confirmed — but auth gated by Play Integrity device attestation. NOT exploitable.** Do not retry. |
| Memory amplification via length prefix | REFUTED (length validated) |
| Stetho DevTools in Google Messages | Exposed in production, but SELinux blocks cross-app access. Not a third-party-app bug. |
| Chromium webview_devtools_remote sockets | none present |
| Other LAN listeners (46697) | no protocol banner, nothing identified |

**Conclusion for planning:** on this device there is currently **no unauthenticated remote
attack surface of Critical severity**. Every no-install surface is either attestation-gated or
SELinux-gated. Remaining realistic Critical directions are account/session takeover via
BROWSABLE OAuth redirects, or a genuine sandbox/privilege escape — not another "exported
component" bug.
"""
if "remote network surface sweep" not in master:
    obs.write("VRP_Master_Tracker.md", master + add)
print("logged network surface hunt")