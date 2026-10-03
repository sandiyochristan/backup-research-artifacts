#!/usr/bin/env python3
"""Log the binder-transaction fuzzing hunt + the resolved GoogleAccountDataService negative."""
import sys
sys.path.insert(0, "/Users/sandiyochristan/Downloads/ExtractedApks")
import obs

obs.write("targets/com.google.android.gms/tests/binder_transaction_fuzz.md", """# Binder transaction fuzzing — GoogleAccountDataService (SECURED)

## The capability that was missing
Until this pass, "can bindService" was treated as a result. Per `METHODOLOGY_chain_to_sink.md`
that is chain material only. New harness: `BinderFuzz` binds a target service, reads its AIDL
interface descriptor, invokes transaction codes, and **decodes the reply looking for returned
data**. That is the only thing that counts — a token, email, or ID coming back to our process.

## Target
`com.google.android.gms/com.google.android.gms.auth.account.be.legacy.GoogleAccountDataService`
- `exported="true"`, **no `android:permission`**, action `com.google.android.gms.auth.DATA_PROXY`
- `onBind()` returns the binder for
  `com.google.android.gms.auth.firstparty.dataservice.IGoogleAccountDataService`
  — GMS's **internal first-party account data service**
- Implementations (`arig`): `a(String)->Bundle`,
  `f(TokenRequest)->TokenResponse`, `e(ConfirmCredentialsRequest)->TokenResponse`,
  `d(String)->GetAndAdvanceOtpCounterResponse`,
  `b(AccountRemovalRequest)->AccountRemovalResponse`

If ungated this would be Critical (account token / OTP counter / account removal from a
zero-permission app). Worth chasing hard.

## Dynamic results
A zero-permission app (UID 10362) bound successfully and dispatched transactions:
```
I/VRPPROBE: BINDER_CONNECTED ... descriptor=com.google.android.gms.auth.firstparty.dataservice.IGoogleAccountDataService
```
Transaction 1 (`:pswitch_22`) decompiles to:
```java
String name = data.readString();                  // account name
enforceNoDataAvail(data);
Account acct = new Account(name, "com.google");
try {
    Laksx.checkCallingUid(Binder.getCallingUid()); // <-- the gate
    GoogleAccountData r = Lakzz.get(acct);
    reply.writeNoException();
    writeParcelable(reply, r);                     // <-- the data sink
} catch (Exception e) { ... }
```
`Laksx.c(int uid, ctx)`:
```java
if (ctx.d(uid)) return;
throw new SecurityException(String.format("UID %s is not associated with a first party app!", uid));
```

### Why early tests were misleading
Calling tx1 with a malformed parcel produced `exCode=-3 (EX_ILLEGAL_ARGUMENT)` and the message
`"the name must not be empty: null"`. That is **not** a security denial — it is
`new Account(name, "com.google")` throwing *before* `checkCallingUid()` is ever reached.
Only by supplying a **valid account name as the first parcel value** does execution reach the
security gate. Always push past an argument-validation error before concluding anything.

### Verdict — SECURED
With a valid name supplied:
```
W/Auth(30293): java.lang.SecurityException: UID 10362 is not associated with a first party app!
E/JavaBinder(30293): Caused by: android.os.RemoteException: UID 10362 is not associated with a first party app!
```
The first-party UID check is enforced in code and rejects third-party UIDs. The missing manifest
permission is compensated by `Laksx`/`Laqhj.d(uid)`.

**Not reportable. Do not retest without a first-party-signed caller.**

## Note on earlier "exCode=0" replies
Transactions 2/3/4/6/7 returned `exCode=0` with replies that decoded to zero-filled buffers and
short ASCII fragments (`deues`, `PoieprdErr`). These are fixed-size structs written with default
values because the argument parse was misaligned — **not** account data. No data leak.

## Reusable lesson
An exported service with no permission is common and almost always has an in-code caller check
(`Binder.getCallingUid()` + package/signature test). The only way to tell is to actually invoke a
transaction with a **well-formed** argument and read the reply. Do not stop at "it bound".
""")

m = obs.read("VRP_Master_Tracker.md")
add = """
### 2026-10-02 (6th pass) — binder transaction fuzzing; GMS account data service SECURED
Built `BinderFuzz` (bind -> read AIDL descriptor -> invoke transaction codes -> decode reply).
This closes the last "binding proves nothing" gap in the methodology.
Chased ~200 exported unguarded services; the standout,
`com.google.android.gms...GoogleAccountDataService` (exported, **no permission**, binds to GMS's
internal `IGoogleAccountDataService` with `getAccountData` / `TokenResponse` / OTP-counter /
account-removal methods).
**SECURED** — proven live:
`W/Auth: java.lang.SecurityException: UID 10362 is not associated with a first party app!`
(in-code first-party UID check `Laksx.c(uid, ctx)`; the missing manifest permission is
compensated). Argument-validation errors happen *before* the check, so always supply a valid
argument before concluding — see `targets/com.google.android.gms/tests/binder_transaction_fuzz.md`.
"""
if "binder transaction fuzzing" not in m:
    obs.write("VRP_Master_Tracker.md", m + add)
print("logged binder fuzz negative")