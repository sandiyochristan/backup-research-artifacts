# FINDING — OOB read in Google Barhopper via unvalidated `stride` (CWE-125)

**Package:** com.google.android.gms (also shipped by com.google.android.apps.wear.companion)
**Library:** lib/arm64-v8a/libbarhopper_qr_only_jni.so (GMS) and libbarhopper.so (wear.companion)
**Class:** CWE-125 Out-of-bounds Read

## Fault site (proven inside the Google library, not the harness)
sig=11  pc-in-lib = 0x161ac  (constant across independent runs and across BOTH libraries)

```
161a4: aa0d03f1   mov  x17, x13
161a8: b400012e   cbz  x14, ...          <- guards only the loop COUNTER
161ac: 38401620   ldrb w0, [x17], #0x1  <- SIGSEGV: one byte past the caller buffer
161b0: d10005ce   sub  x14, x14, #0x1
```

## Root cause (isolated by bhpin)
`Barhopper.recognizeStridedNative(int w,int h,int stride,byte[] buf,RecognitionOptions)`
walks the caller's byte[] using the caller-declared STRIDE with no validation against the
buffer length. Width/height mismatches are handled; stride is not.

| declared stride | dw | dh | buffer | result |
|---|---|---|---|---|
| 4014 | 15 | 3753 | 15x199 | CRASH @ +0x161ac |
| 4014 | 15 | 199  | 15x199 | CRASH @ +0x161ac |
| 15   | 15 | 3753 | 15x199 | ok |
| 1    | 1  | 100000| 1x1   | ok |

Smallest crashing buffer observed: 2985 bytes (15x199).

## Reachability
Barhopper is the barcode/QR decoder behind AGSA/Lens, Wallet, Photos and Keep.
- wear.companion ships it as **libbarhopper.so** = the exact name System.loadLibrary("barhopper")
  expects, so it loads there.
- GMS ships libbarhopper_qr_only_jni.so, so GMS's own Barhopper CANNOT load it:
  "dlopen failed: library libbarhopper.so not found" / "Barhopper so is not available."
  That name mismatch is a separate defect worth reporting.

## Impact (conservative)
Proven: deterministic OOB READ in Google's barcode decoder, caller-controlled geometry, process
crash. Read primitive; in principle adjacent-heap disclosure if decoded output can be made to
reflect it. NOT proven: any write, hijack, or code execution. Report as OOB read / DoS.

## Artifacts
poc/probe/jni/bhfuzz.c, bhpin.c, bhdist.c; BarhopperFuzz.java; evidence/barhopper_crash_proof.txt

---

## Escalation attempts (documented negatives — do not repeat)

Goal was to upgrade this from "OOB read / DoS" to an info-leak or write primitive.

| Attempt | Result |
|---|---|
| ASAN in-process (`-fsanitize=address`, `verify_asan_link_order=0`) | ASAN faults on its own shadow access (`0x1680...` unmapped) at load time. Device does not allow an app process to map ASAN shadow. Environment limit. |
| Off-device ASAN via QEMU | Host has only `qemu-system-aarch64` (no user-mode `qemu-aarch64`) and no Linux kernel image available. Dead end. |
| Second parser (`CalculateBlackPoints`, +0x474d8) | **Withdrawn** — fault addr is `0x0` even on perfectly matched geometry; it is a harness signature error (byte[] passed where ByteBuffer expected), not a Google bug. |
| Convert read → leak | Read feeds a histogram whose index is masked (`and x0, x0, #0x7c`), so the OOB bytes cannot be steered into an observable channel by this path. |
| Convert read → write | No caller-derived-index store found in the hot loop; static scan for `str [base, idx]` with attacker index found none reachable. |
| Measure controllable over-read distance (`bhctl`) | `GetByteArrayElements` returns NULL on this build (array not pinned), so buffer start/end could not be captured. Inconclusive, not refuted. |

## Hardened targets fuzzed with no finding (negative coverage, keep)
| Library | Path | Inputs | Result |
|---|---|---|---|
| `libjpeg2k_converter.so` (Google Pay JPEG2000 decoder, `decodeJpeg2k(byte[],boolean)`) | LIVE — GMS loads `jpeg2k_converter`, name matches | 80,000 | **no crash** |
| `libvcdiffjni.so` (GMS sync delta decoder, `nativeDecoder(byte[],byte[])`) | LIVE — loads `vcdiffjni` | 6,000 | no crash; all inputs rejected at header (returns null) — parser body not reached |
| `libbrotli_native.so` | not attempted — stateful `[J` handle API, same signature problem as barhopper | — | — |

## Verdict
One confirmed, deterministic, root-caused **out-of-bounds read (CWE-125)** in Google's barcode
decoder, reachable via caller-controlled geometry, plus a separate reportable defect
(GMS ships its barcode decoder under a name it cannot load).
**No write primitive and no code execution were demonstrated.** Escalation was attempted across
five distinct avenues and every one is documented above.
