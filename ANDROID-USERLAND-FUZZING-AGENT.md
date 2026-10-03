# Android Userland Fuzzing & Exploitation — Claude Code Agent Guide

Single-file operating manual for an agent conducting native-code vulnerability
research on Android, for coordinated disclosure through Google's VRP.

**Synthesized from:**
- *Android Userland Fuzzing and Exploitation* — mentor training deck, 115 slides, July 2021 (Lessons 1–4)
- Day 1 & Day 2 live class transcripts (the gotchas that aren't on the slides)
- *Android Security Research Playbook* v2025.1 — Dark Wolf Solutions (PLAY 00–47)
- Current-practice research, verified 25 July 2026

**Install as:** `CLAUDE.md` at the project root, or `.claude/skills/android-fuzzing/SKILL.md`.

---

## 0. SCOPE GATE — evaluate before any target work

Fuzzing is indiscriminate: it will happily crash software you have no
authorization to test. Confirm all four before pulling a single APK.

1. **Target is first-party or AOSP.** Published by Google LLC, Developed with Google, Research at Google, Red Hot Labs, Google Samples, Fitbit LLC, Nest Labs, Waymo, Waze — or it is AOSP / Google device firmware.
2. **Device is operator-owned.** Physically in hand. Rooted research device or emulator, not a shared or corporate unit.
3. **No third-party backend is contacted.** Fuzzing runs device-local. If a harness makes network calls, stub them.
4. **No other user's data is involved.** Research account only.

**Hard stops:**
- Third-party apps (banking, fintech, messaging you don't own the rights to test). Not in any Google VRP. Belongs to a separate engagement with written authorization.
- Any target where a crash would affect a live service or another person's device.

The training material uses Signal, Telegram, and WhatsApp as *teaching* targets.
Those are excellent for learning harness construction on your own device. They
are **not** Google VRP scope — a bug found there goes to that vendor's program,
not to Google. Know which you're doing before you start.

**Note on the mentor's device model:** the course assumes a **rooted** device or
Corellium instance. That is correct and necessary for fuzzing (shared memory,
`/proc` access, CPU governor control). It is a *research* environment, not the
attacker model. When you later report a bug, the attacker model must be
reachable without root — see §8.

---

## 1. What changed since the training material

The deck is from July 2021. Four things materially shifted. This section is the
highest-value part of this document; everything else follows the course.

### 1.1 AFL++ Frida mode is now the primary Android path — not QEMU

The course teaches emulated fuzzing via AFL++ QEMU mode (`-Q`), including a
QEMU source patch. AFL++'s own documentation now states that **FRIDA mode is the
primary choice for Android fuzzing**. It uses `-O` instead of `-Q`, runs
**directly on the device**, instruments via Frida Stalker (native AARCH64), and
is configurable in JavaScript rather than only environment variables.

| | QEMU mode (`-Q`) | Frida mode (`-O`) |
|---|---|---|
| Runs | Off-device, emulated | On-device, native |
| Instrumentation | Translation-time | Frida Stalker, runtime |
| Config | Env vars | Env vars **+ JavaScript** |
| Android status | Works, more setup | **Primary recommended** |
| Best for | Massive parallel scale | Realistic execution, JNI |

**Use Frida mode by default.** Fall back to QEMU mode when you need to scale to
hundreds of instances on a fuzzing server — which remains the course's strongest
argument for emulation and is still valid.

### 1.2 The QEMU signal patch may no longer be needed

The course's marquee insight — *"you can search the whole internet for this but
you will not find it"* — is that AFL cannot see crashes inside QEMU because
QEMU's own signal handler catches them first. The fix: patch
`qemu_mode/qemu-afl/linux-user/main.c`, comment out `signal_init()` with `//`,
then comment out **all six** git commands in `build_qemu_support.sh` with `#`
(the mentor notes one is "a sneaky one") so the build doesn't pull fresh source
and destroy your patch. Then `CPU_TARGET=aarch64 ./build_qemu_support.sh`.

That was true for AFL++ circa 2021. AFL++ has since had substantial QEMU work,
including a **QEMU Bridge** backend on QEMU 10.2 (`AFL_QEMU_MODE=bridge`).
**Verify empirically before patching:** build clean, run against a known-crashing
target, and check whether crashes register. Only patch if they don't. Keep the
technique in your pocket — the underlying reasoning (emulator swallows the
signal the fuzzer needs to see) generalizes to other emulation setups.

### 1.3 libFuzzer is in maintenance mode

Since late 2022. The original authors moved to **Centipede**. It still works, is
still shipped with Clang, is still the easiest on-device in-process fuzzer, and
Trail of Bits still recommends it for first experiments — so the course's Lesson
4 material remains usable as written. But expect no new features, and prefer
AFL++ for anything long-running.

### 1.4 Toolchain versions

The course predates current NDK. Known-good combination for Frida mode:

- AFL++ **4.06c or later**
- Frida GumJS devkit **16.x** (`frida-gum-devkit-<ver>-android-arm64.tar.xz`)
- Android NDK **r25c or later** (course used `aarch64-linux-android23-clang`; bump the API level to match your device)
- Target: aarch64, Android 12+ (research verified on API 31; Android 17 / API 37 shipped 16 June 2026)

---

## 2. Target model — what actually pays

The course teaches *how* to fuzz. This section is *what* to point it at.

**Parsers are the target class.** The deck says it plainly: *"Parsers are
everywhere"* — file parsers, data parsers, XML parsers — and they are complex
state machines that reach a lot of code. That instinct is correct and current
evidence has sharpened it considerably.

**Media and codec parsing is the zero-click entry surface.** Project Zero's
Pixel 9 and Pixel 10 chains both entered through a Dolby decoder integer
overflow that sat in the zero-click attack surface of most Android devices. An
in-the-wild DNG exploit hit Samsung's Quram image library. These are third-party
parsing libraries shipped inside the platform, reachable by sending a message —
and they are found by fuzzing, not by exploitation skill.

**Priority order for target selection:**

1. **Media/codec/image parsers** reachable from a message, notification, or synced file. Highest reward tier, and fuzzable.
2. **Native libraries in first-party apps** — `lib/arm64-v8a/*.so` inside Google-published APKs.
3. **Framework native components** — reachable over Binder or from an untrusted app.
4. **Third-party libraries bundled in first-party apps.** The deck flags "3rd party libraries" explicitly. These are often stale relative to upstream; a known CVE in a bundled copy is a real finding.

**The AOSP fuzzer corpus is a gold mine.** The mentor's words. Google publishes
its own harnesses at `cs.android.com` — NFC, camera metadata, and many more:

```
https://cs.android.com/android/platform/superproject/+/master:system/media/camera/fuzz/
```

Read these before writing your own. They show exactly how Google structures
`LLVMFuzzerTestOneInput`, prepares objects, drives mutators, and feeds multiple
functions. Search `cs.android.com` for `LLVMFuzzerTestOneInput` to enumerate them.
A component with an existing Google harness is a component Google considers
fuzz-worthy — and an existing harness you can adapt is hours saved.

---

## 3. Lab setup

### 3.1 Host

Ubuntu 22.04+ (or VM). The Dark Wolf playbook recommends 8+ cores, 32GB RAM,
1TB SSD. For fuzzing, cores matter most — each core is a fuzzer instance.

```bash
sudo apt update && sudo apt install -y \
  cmake curl unzip xxd build-essential git \
  gdb-multiarch openjdk-17-jdk python3 python3-pip \
  adb sqlitebrowser

# GEF — exploitation toolkit for GDB (course uses this)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Ropper — ROP gadget discovery
pip3 install ropper capstone

# Frida tooling
pip3 install frida-tools objection
```

### 3.2 Android NDK

```bash
cd /opt
curl -O https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
unzip android-ndk-r25c-linux.zip
export ANDROID_NDK=/opt/android-ndk-r25c
export PATH=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
```

Verify the cross-compiler: `aarch64-linux-android31-clang --version`

### 3.3 AFL++ with Frida mode for Android

```bash
cd /opt
curl -L https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.06c.tar.gz | tar xz
cd AFLplusplus-4.06c

# Quarkslab's Android CMakeLists builds the minimal on-device binary set
curl -O https://raw.githubusercontent.com/quarkslab/android-fuzzing/main/AFLplusplus/CMakeLists.txt

mkdir build && cd build
cmake -DANDROID_PLATFORM=31 \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a ..
make

adb push afl-fuzz afl-frida-trace.so /data/local/tmp/
```

Building AFL++ for Android is genuinely fiddly. If the CMake route fights you,
`fpicker-aflpp-android` is an alternative that builds against AOSP.

### 3.4 Device preparation

Root is required — shared memory management and CPU governor control both need it.

```bash
adb root && adb shell
# On device, as root:
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
echo core > /proc/sys/kernel/core_pattern      # course gotcha; AFL will demand this
```

Record device state for every session — you will need it in the report:

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.build.version.sdk
```

**Patch-level gate:** if the security patch level is behind the current monthly
bulletin, update before starting. Findings on stale builds are VRP-ineligible
regardless of PoC quality.

---

## 4. Target acquisition and native surface mapping

### 4.1 Pull the APK

```bash
adb shell pm list packages -f | grep -i <target>
adb pull /data/app/.../base.apk ./target.apk
```

Note the partition (`/system/`, `/product/priv-app/`, `/data/app/`) — it tells
you the privilege level of what you're about to fuzz.

### 4.2 Extract native libraries

```bash
unzip -o target.apk -d target_extracted/
ls target_extracted/lib/arm64-v8a/
# or extract one directly:
unzip -j target.apk 'lib/arm64-v8a/*.so' -d ./native/
```

### 4.3 Enumerate the JNI surface

Two directions, and you want both.

**From the Java side** — jadx, search for `native`:

```bash
jadx -d decompiled/ target.apk
grep -rn "native " decompiled/sources/ | grep -v "^Binary"
```

**From the native side** — exported symbol table:

```bash
# JNI entry points follow the Java_<pkg>_<Class>_<method> convention
aarch64-linux-android-objdump -T lib/arm64-v8a/libtarget.so | grep "Java_"

# Everything exported, including internal C++ functions worth targeting directly
aarch64-linux-android-objdump -T lib/arm64-v8a/libtarget.so | grep " g    DF .text"
```

The mangled C++ symbols matter — `_Z6fuzzMePKai` style names are directly
linkable from a harness, which is often easier than going through JNI.

**From the running process** — Frida trace, per the course:

```bash
adb push frida-server /data/local/tmp && adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
adb forward tcp:27042 tcp:27042

frida-ps -H 127.0.0.1:27042
frida-trace -H 127.0.0.1:27042 -p <PID> -i "Java_*"
```

Then exercise the app. Every JNI function that fires is a reachable entry point
with a live call signature — which is exactly what you need to build a harness.
Use `onEnter` / `onLeave` handlers to dump actual argument values.

---

## 5. Reverse engineering for harnessable functions

Load the `.so` into Ghidra. Auto-analyze. Then work three angles.

### 5.1 Unsafe function references

Symbol Tree → find references to the classic offenders:

```
memcpy   strcpy   strcat   sprintf   gets   alloca
memmove  strncpy  snprintf  read     recv
```

For each hit, the question is: **is the size attacker-controlled, and is it
validated against the destination?** The course's framing — trace back from the
sink to see whether the length comes from parsed input — is the whole game.

### 5.2 Parsing functions

Look for the shape: a loop over a buffer, a switch on a tag/type byte, offset
arithmetic, and length fields read from the input. Anything that walks a
structured format. These reach the most code per input and hold the most bugs.

### 5.3 Pick the harness point

You are looking for a function that:

- Takes a **buffer + length** (or something you can shape into one)
- Is **exported** (or you can compute its offset and call it directly)
- Sits **early enough** to reach interesting parsing, **late enough** to avoid heavy setup
- Has **no unresolvable global state** dependency

Use Ghidra's Function Call Trees to see what a candidate reaches. A function
that fans out into hundreds of blocks is a good harness point. One that returns
immediately is not.

---

## 6. Harness construction — the three cases

This is the core skill. The Quarkslab taxonomy maps directly onto what you will
encounter, and it resolves the problem the course leaves as an exercise.

### 6.1 Case A — Standard native function

No Android/Java coupling. Link the mangled symbol directly.

```c
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define BUFFER_SIZE 256

/* Target function — mangled name from objdump -T */
extern void _Z6fuzzMePKai(const uint8_t *, uint64_t);

/* Persistent loop entry — Frida mode hooks this symbol by name */
void fuzz_one_input(const uint8_t *buf, int len) {
  _Z6fuzzMePKai(buf, len);
}

int main(void) {
  uint8_t buffer[BUFFER_SIZE];
  ssize_t rlength = fread(buffer, 1, BUFFER_SIZE, stdin);
  if (rlength == -1) return errno;
  fuzz_one_input(buffer, rlength);
  return 0;
}
```

Build:

```bash
aarch64-linux-android31-clang fuzz.c -o fuzz -ltarget -L./native/
adb push fuzz afl.js native/libtarget.so /data/local/tmp/
```

### 6.2 Case B — Weakly linked JNI function

Takes `JNIEnv*` but doesn't touch app-specific Java classes. You must construct
a real JNI environment. Do it by loading `libandroid_runtime.so` and calling the
Invocation API:

```c
#include <dlfcn.h>
#include <jni.h>

#define ANDROID_RUNTIME_DSO "libandroid_runtime.so"

typedef struct JavaContext {
  JavaVM *vm;
  JNIEnv *env;
  struct JniInvocationImpl *invoc;
} JavaCTX;

typedef jint (*JNI_CreateJavaVM_t)(JavaVM **, JNIEnv **, void *);

int init_java_env(JavaCTX *ctx, char **jvm_options, uint8_t jvm_nb_options) {
  void *runtime_dso = dlopen(ANDROID_RUNTIME_DSO, RTLD_NOW);
  if (!runtime_dso) return JNI_ERR;

  struct JniInvocationImpl* (*JniInvocationCreate)() =
      dlsym(runtime_dso, "JniInvocationCreate");
  bool (*JniInvocationInit)(struct JniInvocationImpl*, const char*) =
      dlsym(runtime_dso, "JniInvocationInit");
  JNI_CreateJavaVM_t JNI_CreateJVM =
      (JNI_CreateJavaVM_t) dlsym(runtime_dso, "JNI_CreateJavaVM");
  jint (*registerFrameworkNatives)(JNIEnv*) =
      dlsym(runtime_dso, "registerFrameworkNatives");

  if (!JniInvocationCreate || !JniInvocationInit ||
      !JNI_CreateJVM || !registerFrameworkNatives) return JNI_ERR;

  ctx->invoc = JniInvocationCreate();
  JniInvocationInit(ctx->invoc, ANDROID_RUNTIME_DSO);

  JavaVMOption options[jvm_nb_options];
  for (int i = 0; i < jvm_nb_options; ++i)
    options[i].optionString = jvm_options[i];

  JavaVMInitArgs args = {
    .version = JNI_VERSION_1_6,
    .nOptions = jvm_nb_options,
    .options = options,
    .ignoreUnrecognized = JNI_TRUE
  };

  if (JNI_CreateJVM(&ctx->vm, &ctx->env, &args) == JNI_ERR) return JNI_ERR;

  /* Links framework natives — skip this and you get UnsatisfiedLinkError
     the moment the target touches anything in the framework */
  if (registerFrameworkNatives(ctx->env) == JNI_ERR) return JNI_ERR;

  return JNI_OK;
}
```

Then marshal the fuzzer buffer into a `jbyteArray`:

```c
static JavaCTX ctx;

void fuzz_one_input(const uint8_t *buffer, size_t length) {
  jbyteArray jBuffer = (*ctx.env)->NewByteArray(ctx.env, length);
  (*ctx.env)->SetByteArrayRegion(ctx.env, jBuffer, 0, length,
                                 (const jbyte *)buffer);

  Java_qb_blogfuzz_NativeHelper_fuzzMeArray(ctx.env, NULL, jBuffer);

  (*ctx.env)->DeleteLocalRef(ctx.env, jBuffer);   /* or you leak refs and die */
}
```

`init_java_env(&ctx, NULL, 0)` in `main()` — no classpath needed for this case.

**Why fuzz JNI rather than the native function underneath?** Two real reasons:
you skip reverse-engineering the internal call path, and crashes you find are
reproducible from Java — which makes the eventual report far stronger.

### 6.3 Case C — Strongly linked JNI function

Manipulates app-specific Java classes. Add the APK to the classpath and
construct the required objects:

```c
char *options = "-Djava.class.path=/data/local/tmp/target.apk";
init_java_env(&ctx, &options, 1);
```

```c
void fuzz_one_input(const uint8_t *buffer, size_t length) {
  jbyteArray jBuffer = (*ctx.env)->NewByteArray(ctx.env, length);
  (*ctx.env)->SetByteArrayRegion(ctx.env, jBuffer, 0, length,
                                 (const jbyte *)buffer);

  jclass wrapperClass = (*ctx.env)->FindClass(ctx.env, "qb/blogfuzz/Wrapper");
  jmethodID ctor = (*ctx.env)->GetMethodID(ctx.env, wrapperClass, "<init>", "([B)V");
  jobject obj = (*ctx.env)->NewObject(ctx.env, wrapperClass, ctor, jBuffer);

  Java_qb_blogfuzz_NativeHelper_fuzzMeWrapper(ctx.env, NULL, obj);

  (*ctx.env)->DeleteLocalRef(ctx.env, obj);
  (*ctx.env)->DeleteLocalRef(ctx.env, jBuffer);
}
```

**When the Java class is hostile to fuzzing** — sleeps, network calls, heavy
init — you have two outs:

*Mock it.* Decompile the class, write a stripped version, compile to dex, use
that as the classpath instead of the APK:

```bash
javac Wrapper.java
d8 Wrapper.class
mv classes.dex mock.dex
adb push mock.dex /data/local/tmp/
# then: -Djava.class.path=/data/local/tmp/mock.dex
```

*Or hook it* from `afl.js` — less performant, far quicker to set up:

```javascript
const pInitJenv = Module.getExportByName("libjenv.so", "init_java_env");
const interceptor = Interceptor.attach(pInitJenv, {
  onLeave: function (retval) {
    Java.perform(function () {
      Java.use("java.lang.Thread").sleep.overload("long")
        .implementation = function () { /* bypass */ };
      interceptor.detach();
    });
  }
});
```

### 6.4 Expected throughput

| Harness type | Execs/sec |
|---|---|
| Standard native function | ~10k |
| Weakly linked JNI | ~9k |
| Strongly linked JNI | ~5k |
| Strongly linked + Java hook | ~3.5k |

If you are two orders of magnitude below these, something is wrong — usually
missing module exclusion (§7.2) or a harness that re-initializes per iteration.

---

## 7. Running the fuzzer

### 7.1 Frida mode — default path

```bash
adb shell
cd /data/local/tmp
mkdir -p in out
dd if=/dev/urandom of=in/seed.bin bs=1 count=16

./afl-fuzz -O -G 256 -i in -o out ./fuzz
```

- `-O` — Frida mode
- `-G 256` — max input length; match your harness buffer
- `-t 3000` — raise the timeout if the harness has slow startup

### 7.2 `afl.js` — the configuration that matters

```javascript
/* Only instrument what you care about. Skipping this is the #1 cause of
   catastrophically slow Frida-mode fuzzing. */
const MODULE_WHITELIST = ["fuzz", "libtarget.so"];

Module.load("libandroid_runtime.so");
new ModuleMap().values().forEach(m => {
  if (!MODULE_WHITELIST.includes(m.name)) {
    Afl.addExcludedRange(m.base, m.size);
  }
});

const pStartAddr = DebugSymbol.fromName("fuzz_one_input").address;
Afl.setPersistentAddress(pStartAddr);
Afl.setEntryPoint(pStartAddr);
Afl.setPersistentCount(10000);

/* Restore arguments each iteration — aarch64 AAPCS: x0 = buf, x1 = len */
const cm = new CModule(`
  #include <string.h>
  #include <gum/gumdefs.h>
  #define BUF_LEN 256
  void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
                           uint32_t input_buf_len) {
    uint32_t length = (input_buf_len > BUF_LEN) ? BUF_LEN : input_buf_len;
    memcpy((void *)regs->x[0], input_buf, length);
    regs->x[1] = length;
  }`,
  { memcpy: Module.getExportByName(null, "memcpy") }
);
Afl.setPersistentHook(cm.afl_persistent_hook);

Afl.done();
```

Override the script path with `AFL_FRIDA_JS_SCRIPT=<file>`.

### 7.3 QEMU mode — for off-device scale

Retained from the course. Use when running many instances on a server.

```bash
export QEMU_LD_PREFIX="/path/to/rootfs/arm64_android/"     # Qiling ships usable rootfs
export QEMU_SET_ENV=LD_LIBRARY_PATH=/path/to/libs/

AFL_INST_LIBS=1 afl-fuzz -Q -i afl_in/ -o afl_out/ -- ./main @@
```

`AFL_INST_LIBS=1` is what makes it instrument the closed-source `.so` rather
than only your harness. If you get coverage but zero crashes, see §9.1.

Qiling is worth knowing for its rootfs collection and Python-scriptable
emulation, but the course's warning holds: unimplemented Android ARM syscalls
must be written yourself, and many are missing.

### 7.4 libFuzzer — when you have source

```bash
aarch64-linux-android31-clang -g -O1 -fsanitize=fuzzer,address -fPIC -c libtarget.c
aarch64-linux-android31-clang -g -O1 -fsanitize=fuzzer,address harness.c -o harness libtarget.o -lm

adb push harness libc++_shared.so /data/local/tmp/
adb shell
cd /data/local/tmp
LD_LIBRARY_PATH=. ./harness -max_len=6000000 CORPUS/
LD_LIBRARY_PATH=. ./harness -ignore_crashes=1 -fork=1    # keep going past first crash
```

Sanitizer variants: `-fsanitize=fuzzer,address` (ASAN),
`-fsanitize=fuzzer,memory` (MSAN), `-fsanitize=fuzzer,signed-integer-overflow`
(part of UBSAN).

### 7.5 Corpus strategy

The single highest-leverage thing after harness quality. Do not fuzz from
`/dev/urandom` if you can avoid it.

- Seed with **real files of the target format** — pull them from the device, from the app's assets, from public test suites.
- Minimize before starting: `afl-cmin -i raw_corpus -o min_corpus -- ./fuzz`
- Trim individual cases: `afl-tmin -i case -o case.min -- ./fuzz`
- A dictionary of format magic bytes and keywords (`-x dict.txt`) pays for itself on structured formats.

---

## 8. Crash triage

Expect volume. The mentor is blunt: *"crash analysis will take a significant
amount of time... you will face a lot of crashes."* Most are duplicates of the
same root cause.

### 8.1 Reproduce

```bash
LD_LIBRARY_PATH=. ./harness out/default/crashes/id:000000*
# QEMU mode:
./main out/crashes/id:000000*
```

### 8.2 Symbolize

ASAN's symbolizer frequently fails on Android — the course hits this directly.
The workaround is `llvm-symbolizer` with the raw offset from the ASAN backtrace:

```bash
llvm-symbolizer --obj=./harness 0x<offset>
# → parse_txt at libtesthello.c:15:7
```

That gives you file and line. Then read the source or the Ghidra decompilation
at that point.

### 8.3 Debug under GDB

Course workflow, on-device:

```bash
# Device, root:
am start -n com.example/.MainActivity
ps -A | grep com.example                    # get PID
gdbserver :5045 --attach <PID>

# Host:
adb forward tcp:5045 tcp:5045
gdb-multiarch ./harness
```

```
set architecture aarch64
set sysroot /path/to/sysroot
gef-remote 127.0.0.1:5045
c
```

Working set of commands: `break`, `continue`/`c`, `backtrace`/`bt`,
`info registers`/`ir`, `x/<fmt>` to examine memory, `info functions`, `vmmap`.
GEF gives you the annotated register/stack view.

For QEMU-mode crashes, start with the GDB stub: `-g 8080`, then
`gef-remote 127.0.0.1:8080`.

`rr` (rr-project.org) for reverse execution is worth the setup cost on
hard-to-follow heap corruption.

### 8.4 Classify

Answer these, in order. This is what determines whether you have a report.

1. **What is the primitive?** Read overflow, write overflow, UAF, double free, integer overflow leading to undersized allocation, type confusion, format string.
2. **How much attacker control?** Over the *offset*, over the *length*, over the *contents*. Write-what-where is a different severity from a read of one byte past a buffer.
3. **Is it deterministic?** Non-deterministic crashes are usually heap-layout dependent — often still real, harder to argue.
4. **Is it reachable without root?** Your harness ran as root on a rooted device. That is not the attacker model. Trace the path from an unprivileged entry point — an intent, a received message, a downloaded file, a parsed image. **If you cannot draw that path, you do not have a VRP finding**, however clean the crash.
5. **Is it already known?** Check the Android Security Bulletins for the component, AOSP Gerrit for recent silent fixes, and the acknowledgements page — before investing further.

### 8.5 Exploitability assessment — and where to stop

For Google VRP you need to establish **severity**, not build a weapon. Google's
reward rubric pays for root cause analysis, a minimal reproducible PoC, variant
analysis, and a proposed patch. A weaponized exploit scores no higher and reads
worse to a triage panel.

So: determine the primitive and the degree of control, note which mitigations
stand between it and code execution (ASLR/PIE, stack canaries, XN/NX, CFI,
MTE on Pixel 8+), and state honestly what you demonstrated versus what you
infer. Write "heap buffer overflow with attacker-controlled length and contents;
not demonstrated to be exploitable" rather than either overclaiming or building
the full chain.

The course's Day 2 material — ROP gadget discovery with `ropper -f <binary>`,
GEF's gadget dumping, leaking a libc address to defeat ASLR — is the right
mental model for *understanding* why a primitive is or isn't severe. Use it to
reason. You do not need to land the exploit to file the report.

---

## 9. Gotchas

### 9.1 Coverage but no crashes (QEMU mode)

The course's signature problem. QEMU's signal handler catches the crash before
AFL sees it. Fix: patch out `signal_init()` in
`qemu_mode/qemu-afl/linux-user/main.c` (comment with `//`), comment out all six
git commands in `build_qemu_support.sh` (with `#`) so the build doesn't
overwrite your patch, rebuild with `CPU_TARGET=aarch64 ./build_qemu_support.sh`.
**Verify this is still necessary on your AFL++ version before doing it.**

### 9.2 `Program 'afl-qemu-trace' not found`

You built AFL++ for the host but not `afl-qemu-trace` for aarch64. Build QEMU
support for the target architecture.

### 9.3 AFL refuses to start over core pattern

```bash
echo core > /proc/sys/kernel/core_pattern
```

### 9.4 Frida mode crawling at <100 execs/sec

You are instrumenting the entire Android runtime. Add module exclusion (§7.2).

### 9.5 `UnsatisfiedLinkError` in a JNI harness

You skipped `registerFrameworkNatives(env)`. Call it.

### 9.6 JNI harness dies after a few thousand iterations

Local reference table overflow. Every `NewByteArray` / `NewObject` needs a
matching `DeleteLocalRef` inside the persistent loop.

### 9.7 ASAN symbolizer errors

Expected on Android. Use `llvm-symbolizer --obj=<harness> <offset>` (§8.2).

### 9.8 ASAN under AFL++ slows everything

Real tradeoff, acknowledged in class. Run most instances without ASAN for
throughput, one or two with it for detection depth. ASAN catches the
non-crashing corruption that plain fuzzing walks straight past.

### 9.9 Harness compiles but instruments nothing

In QEMU mode you forgot `AFL_INST_LIBS=1`. In Frida mode your target module
isn't in the whitelist.

---

## 10. Agent workflow

Run these as slash commands or phases. Three are gates, not steps.

```
/scope       §0   authorization + program routing        ← GATE
/setup       §3   toolchain, device, patch-level check   ← GATE
/acquire     §4   pull APK, extract .so, map JNI surface
/reverse     §5   Ghidra, find the harness point
/harness     §6   build Case A / B / C harness
/fuzz        §7   Frida mode, corpus, run
/triage      §8   reproduce, symbolize, debug, classify
/novelty     §8.4 duplicate check                        ← GATE
/report      §11  draft to the VRP rubric
```

**Per-session notes template:**

```markdown
# Session — <target> — <date>
SCOPE:        target / publisher / device / program        GATE: PASS|FAIL
DEVICE:       fingerprint / security_patch / sdk           GATE: PASS|FAIL
TARGET LIB:   lib/arm64-v8a/<name>.so  (partition: ...)
HARNESS TYPE: A standard | B weakly-linked JNI | C strongly-linked JNI
ENTRY SYMBOL: <mangled or Java_ symbol>
CORPUS:       source / size / minimized?
RUN:          execs/sec, paths, stability, duration
CRASHES:      count / unique after triage
CLASSIFIED:   primitive / control / deterministic? / unprivileged path?
NOVELTY:      bulletins / gerrit / tracker / acks     → NOVEL|VARIANT|DUP|FIXED
NEXT:
```

---

## 11. Report structure

```markdown
# <Bug class> in <library> — <impact>

## TL;DR
Two sentences: who can do what, to what, with what result.

## Program routing
Mobile VRP | AGD-VRP | Google & Alphabet VRP — with justification.

## Affected target
Package/component + versionCode; library name and version if determinable;
device model; build fingerprint; security patch level.

## Attacker model
Precisely what the attacker controls and needs. State explicitly if no
permissions and no user interaction are required — it sets the reward tier.

## Root cause
File, function, line. The specific defect. Ghidra decompilation or AOSP
source where available.

## Reproduction
Numbered, deterministic, from a clean device. Attach the crashing input,
the harness source, and the build command.

## Crash evidence
ASAN output or GDB backtrace, symbolized. Device fingerprint captured
at time of crash.

## Impact
What the primitive gives an attacker. Mitigations in the way. Honest
separation of demonstrated versus inferred.

## Variant analysis
Same pattern elsewhere in this library and in sibling components.

## Proposed patch
Concrete — the bounds check, the integer-overflow guard, the length
validation. Direct reward multiplier under the 30 April 2026 policy.

## Preconditions and limitations
Including what was not demonstrated.
```

Submit at `g.co/vulnz`. Reproduce on the latest bulletin patch level first.

---

## 12. Source index

**Mentor training deck** (`Training-Material-Part1.pdf`, 115 slides, July 2021):

| Slides | Content |
|---|---|
| 8–22 | Lesson 1 — Android security model, sandbox, permissions, Binder IPC, SELinux, verified boot |
| 23–40 | Lesson 2 — ARM assembly: registers, ARMv7/ARM64 instruction sets, stack, calling conventions, syscalls, branching |
| 41–55 | Lesson 3a — Ghidra: decompiler, disassembler, call trees, symbol tree, xrefs, scripting, export for harnessing |
| 56–78 | Lesson 3b — NDK, ADB, APK unpacking, finding native components, **JNI enumeration with Frida** |
| 79–84 | Lesson 3c — Finding vulns: unsafe functions, parsing functionality |
| 85–101 | Lesson 4a — Fuzzing theory, harness building, **AFL++ QEMU emulated fuzzing** |
| 102–107 | Lesson 4b — On-device libFuzzer |
| 108–113 | Lesson 4c — Crash triage, GDB, time-travel debugging |

**Transcripts:** Day 1 = harness construction, AFL++/QEMU setup, the signal
patch, Signal/Telegram as practice targets. Day 2 = crash triage, ASAN,
llvm-symbolizer, GDB/GEF remote debugging, ROP and ASLR-bypass theory.

**Dark Wolf ASRP v2025.1:** PLAY 00–04 recon, 05–11 static analysis, 12–22
dynamic analysis, 23–32 vulnerability classes, 33–34 fuzzing, 35–43 mitigation
bypass, 44–47 exploitation effects. Use as a checklist over the top of this
guide; it is broader and shallower.

**Current external references:**
- AFL++ binary-only fuzzing — `https://aflplus.plus/docs/fuzzing_binary-only_targets/`
- AFL++ Frida mode scripting API — `https://github.com/AFLplusplus/AFLplusplus/blob/stable/frida_mode/Scripting.md`
- Quarkslab, *Android greybox fuzzing with AFL++ Frida mode* — the JNI harnessing methodology in §6; code at `https://github.com/quarkslab/android-fuzzing`
- Aleph Security, *AFL++ on Android with QEMU support*
- `fpicker-aflpp-android` — fuzzing in app context
- AOSP fuzzers — search `cs.android.com` for `LLVMFuzzerTestOneInput`
- Google Android Offensive Security — `https://androidoffsec.withgoogle.com/`
- AGD-VRP / Mobile VRP rules — `https://bughunters.google.com/about/rules/android-friends/`

---

## 13. Maintenance

Verified 25 July 2026. Re-check before relying on:

- AFL++ release and whether the QEMU signal patch is still required (§1.2)
- NDK / Frida devkit version compatibility (§1.4)
- VRP reward structure — restructured 30 April 2026; top tier $1.5M zero-click Titan M2 with persistence, $750K without, secure element exfil $375K, proposed patches explicitly incentivized
- Current monthly security bulletin for your device class
