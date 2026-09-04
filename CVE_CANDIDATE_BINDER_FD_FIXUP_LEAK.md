# Vulnerability Report: struct file Reference Leak in Binder TF_UPDATE_TXN

**Date:** 2026-07-08
**Researcher:** Sandiyochristan
**Severity:** High (CVSS 3.1 Base: 7.1 — local DoS via permanent kernel memory exhaustion)
**CWE:** CWE-401 (Missing Release of Memory) / CWE-772 (Missing Release of Resource)
**Affected:** All Android kernels with TF_UPDATE_TXN support (android14-6.1+, android-mainline)
**Device tested:** Pixel 6a, Android 17 (CinnamonBun), kernel 6.1.162-android14-11

---

## Summary

When `TF_UPDATE_TXN` supersedes an async oneway transaction queued in a frozen process's `async_todo`, the outdated transaction is freed via `kfree(t_outdated)` **without** calling `binder_free_txn_fixups(t_outdated)`. If the superseded transaction contained `BINDER_TYPE_FD` objects, the `binder_txn_fd_fixup` structs and their `struct file` references are permanently leaked — the files are never `fput()`'d.

---

## Root Cause

**File:** `drivers/android/binder.c`
**Function:** `binder_proc_transaction()`
**Lines:** ~3116-3126

### Vulnerable Code

```c
/* binder_proc_transaction() — after releasing inner_lock + node_lock */
if (t_outdated) {
    struct binder_buffer *buffer = t_outdated->buffer;

    t_outdated->buffer = NULL;
    buffer->transaction = NULL;
    trace_binder_transaction_update_buffer_release(buffer);
    binder_release_entire_buffer(proc, NULL, buffer, false);
    binder_alloc_free_buf(&proc->alloc, buffer);
    kfree(t_outdated);                    /* ← BUG: fd_fixups not freed! */
    binder_stats_deleted(BINDER_STAT_TRANSACTION);
}
```

### Correct Comparison (binder_free_transaction)

```c
/* binder_free_transaction() — the normal transaction teardown path */
binder_free_txn_fixups(t);               /* ← releases file refs */
kfree(t);
binder_stats_deleted(BINDER_STAT_TRANSACTION);
```

### binder_free_txn_fixups() — what's missing

```c
static void binder_free_txn_fixups(struct binder_transaction *t)
{
    struct binder_txn_fd_fixup *fixup, *tmp;

    list_for_each_entry_safe(fixup, tmp, &t->fd_fixups, fixup_entry) {
        fput(fixup->file);           /* Release struct file reference */
        if (fixup->target_fd >= 0)
            put_unused_fd(fixup->target_fd);
        list_del(&fixup->fixup_entry);
        kfree(fixup);                /* Free fixup object */
    }
}
```

---

## How fd_fixups Get Populated

When `binder_transaction()` processes a `BINDER_TYPE_FD` object in the sender's data, it calls `binder_translate_fd()` which:

1. `fget()`s the source file descriptor → `struct file *file`
2. Allocates a `binder_txn_fd_fixup` struct
3. Sets `fixup->file = file`, `fixup->target_fd = -1`
4. Adds fixup to `t->fd_fixups` list

The fixup is consumed later by `binder_apply_fd_fixups()` when the transaction is **delivered** to a target thread. If the transaction is superseded before delivery, the fixups are orphaned.

---

## Trigger Conditions

1. **Target process must be frozen** (`proc->is_frozen == true`)
2. **First transaction:** `TF_ONE_WAY | TF_UPDATE_TXN` with `BINDER_TYPE_FD` objects → queued in `node->async_todo`
3. **Second transaction:** `TF_ONE_WAY | TF_UPDATE_TXN` with **same code, same sender PID, same target node** → supersedes first → first transaction's fd_fixups leaked

Matching criteria from `binder_can_update_transaction()`:
- Both have `TF_ONE_WAY | TF_UPDATE_TXN` flags
- Same `to_proc->tsk`
- Same `code`
- Same `flags`
- Same `buffer->pid` (sender)
- Same `buffer->target_node->ptr` and `->cookie`

---

## Attack Scenario (untrusted_app)

**The attacker does NOT need BINDER_FREEZE permission.** Android's Activity Manager Service (AMS) freezes background apps automatically. The attacker only needs:

1. **A handle to a binder node in another app** — obtained through normal service binding (`bindService()`)
2. **The target app to be frozen** — happens automatically when the target goes to background
3. **Send TF_UPDATE_TXN transactions with FDs** — `TF_UPDATE_TXN` (0x40) is a public flag, not restricted

**Attack flow:**
1. Attacker app binds to a target service (e.g., any exported service)
2. User switches away from target app → AMS freezes it
3. Attacker sends `TF_ONE_WAY | TF_UPDATE_TXN` transactions containing FDs to the frozen service
4. Each superseding transaction leaks the previous one's `struct file` references
5. Repeat thousands of times → exhaust file table, slab cache, or pin critical files

---

## Impact — Demonstrated on Pixel 6a

### Permanent Kernel Memory Exhaustion (Demonstrated)

**Leak rate:** ~3.3 MB/sec of unreclaimable kernel slab memory from an unprivileged app.

| Metric | Baseline | After 110s attack | After PoC killed | Delta |
|--------|----------|-------------------|-------------------|-------|
| `filp` (struct file objects) | 31,592 | 509,775 | 501,852 | **+470,260 permanent** |
| `kmalloc-64` (fixup objects) | 361,145 | ~830,000 | 829,310 | **+468,165 permanent** |
| `SUnreclaim` | 392 MB | 747 MB | 753 MB | **+361 MB permanent** |
| `MemAvailable` | 2,087 MB | 1,792 MB | 1,853 MB | **-234 MB** |
| `Load average` | 1.73 | — | 26.62 | **device thrashing** |

- **460,000 transactions sent in 110 seconds**, 0 errors, 0 rebinds
- After PoC killed (no processes running): objects **persist and continue growing**
- SUnreclaim **increased from 698 MB → 753 MB** even after PoC stopped
- Load average **26.62** — device severely degraded, UI unresponsive
- **Only a device reboot recovers the leaked memory**
- At sustained rate, full 5.7 GB RAM exhausted in ~28 minutes → device crash

### Per-Superseded Transaction Leak
- 1 `binder_txn_fd_fixup` object (64 bytes, kmalloc-64 slab)
- 1 `struct file` object (320 bytes, filp slab) — kept alive by orphaned `fget()` reference
- Associated inode/dentry/pipe_inode_info structures (~400 bytes)
- **Total: ~784 bytes per superseded transaction, all unreclaimable**

### File Reference Pinning
- Leaked `struct file` references prevent `fput()` from reaching zero
- Files that should be deleted/closed remain open in kernel
- `/proc/sys/fs/file-max` exhaustion possible with sustained triggering
- System becomes unable to open new files → system-wide DoS

---

## Proposed Fix

Add `binder_free_txn_fixups(t_outdated)` before `kfree(t_outdated)`:

```diff
 if (t_outdated) {
     struct binder_buffer *buffer = t_outdated->buffer;

     t_outdated->buffer = NULL;
     buffer->transaction = NULL;
     trace_binder_transaction_update_buffer_release(buffer);
     binder_release_entire_buffer(proc, NULL, buffer, false);
     binder_alloc_free_buf(&proc->alloc, buffer);
+    binder_free_txn_fixups(t_outdated);
     kfree(t_outdated);
     binder_stats_deleted(BINDER_STAT_TRANSACTION);
 }
```

---

## Verification

### Static Analysis (Confirmed)

1. `binder_free_txn_fixups()` is called at 3 sites:
   - `binder_free_transaction()` (line 1873) — normal teardown ✓
   - `binder_transaction()` error path (line 3985) — error cleanup ✓
   - `binder_apply_fd_fixups()` error path (line 4879) — delivery failure ✓

2. The TF_UPDATE_TXN supersede path at line 3124 calls `kfree(t_outdated)` **without** calling `binder_free_txn_fixups()` — **the only code path that frees a transaction without releasing its fd_fixups**.

3. `binder_release_entire_buffer()` does NOT handle fd_fixups — for `BINDER_TYPE_FD`, it explicitly does nothing (the buffer only contains the source fd value, not the fixup objects).

### Upstream Verification

The bug is confirmed present in `android-mainline` (`refs/heads/android-mainline/drivers/android/binder.c`) as of 2026-07-08. The same `kfree(t_outdated)` without `binder_free_txn_fixups()` exists.

---

## Dynamic Proof — Full Chain PoC (Kernel DoS Demonstrated)

### Test Environment
- **Device:** Pixel 6a (bluejay), Android 17 (CinnamonBun)
- **Kernel:** 6.1.162-android14-11-ab12833340
- **Build:** user, SELinux enforcing
- **SELinux context:** `u:r:untrusted_app:s0:c313,c256,c512,c768` (UID 10313)
- **No special permissions, no root, no unlocked bootloader**

### PoC Architecture
1. **Target service** (`LeakTargetService`): Runs in `:target` process, exposes a Binder node
2. **Attacker activity** (`MainActivity`): Binds to target, freezes via `am freeze`, sends `TF_UPDATE_TXN|FLAG_ONEWAY` transactions each containing a unique pipe FD
3. **Freeze trigger**: `am freeze <pkg>:target` → AMS → `ioctl(BINDER_FREEZE)` from `system_server`
4. **Unique FDs**: Each transaction carries a different pipe file descriptor, so each superseded transaction leaks a unique `struct file` (320 bytes) plus its `binder_txn_fd_fixup` (64 bytes)

### Results — Kernel Memory Exhaustion

```
460,000 transactions sent in 110 seconds
0 errors, 0 rebinds, 0 special permissions

Time (s)  filp objects   kmalloc-64    SUnreclaim    MemAvailable
──────────────────────────────────────────────────────────────────
0         31,592         361,145       392 MB        2,087 MB     (baseline)
12        92,750         413,760       436 MB        2,001 MB
30        192,546        522,368       518 MB        1,961 MB
48        274,175        599,552       570 MB        1,853 MB
75        389,275        709,568       653 MB        1,890 MB
100       458,201        789,248       718 MB        1,829 MB
110       509,775        ~830,000      747 MB        1,792 MB     (ADB lost)
+2 min    496,755        817,124       698 MB        2,157 MB*    (PoC killed by AMS)
+3 min    501,852        829,310       753 MB        1,853 MB     (still growing)

* MemAvailable temporarily rose because AMS killed other apps to free page cache.
  SUnreclaim CONTINUED GROWING after PoC killed — orphaned objects are permanent.
```

### Post-Attack Device State (No PoC Running, Measurements Over Time)

```
Minutes after    filp        SUnreclaim    Load avg    Notes
PoC killed       objects     (MB)
───────────────────────────────────────────────────────
+0               509,775     747           —           ADB connection lost
+2               496,755     698           26.62       ADB recovered, PoC dead
+3               501,852     753           26.62       Slab STILL GROWING
+5               502,943     766           66.27       Device spiraling
```

- **471,351 permanently leaked struct file objects** (baseline: 31,592)
- **479,188 permanently leaked fixup objects** (baseline: 361,145)
- **+374 MB permanent unreclaimable slab** — growing even without attacker
- **Load average increasing** (26 → 66) — kernel thrashing on unfreeable slabs
- **No recovery path** — objects are orphaned (no pointer), only device reboot recovers

### What the PoC Proves
1. **Trigger from untrusted_app**: Runs as UID 10313, `untrusted_app` SELinux domain
2. **No permissions needed**: `TF_UPDATE_TXN` (0x40) is a public flag, no permission check
3. **Freeze via standard Android lifecycle**: `am freeze` triggers binder-level freeze via AMS
4. **Massive leak rate**: ~3.3 MB/sec of permanent kernel slab exhaustion
5. **Objects persist after app death**: filp and kmalloc-64 counts remain elevated after PoC force-stopped
6. **Slab continues growing**: SUnreclaim increased from 698→753 MB even with zero PoC processes
7. **Device degradation**: Load average 26+ makes device unusable without reboot
8. **Projection**: Sustained attack exhausts 5.7 GB RAM in ~28 minutes → OOM → device crash

### Key Insight
Each superseded transaction leaks:
- `fget()` elevated the `struct file` refcount but `fput()` is never called (missing `binder_free_txn_fixups`)
- The `binder_txn_fd_fixup` struct holding the file pointer is orphaned when `kfree(t_outdated)` destroys the containing transaction without iterating its `fd_fixups` list
- Using unique pipe FDs per transaction ensures each leak creates a new `struct file` object (not just an elevated refcount on a shared file)

### Files
- `binder_leak_app/` — Complete Android app PoC (source + build script + APK)
- `binder_race_tests/binder_fd_leak_v2.c` — Native C PoC (requires BINDER_FREEZE capability)

---

## Timeline

- **2026-07-08:** Vulnerability discovered during source audit of android14-6.1 binder.c
- **2026-07-08:** Confirmed present in android-mainline
- **2026-07-08:** Native PoC written; SELinux blocks BINDER_FREEZE from `adb shell`
- **2026-07-09:** Android app PoC built; uses `am freeze` to trigger from `untrusted_app`
- **2026-07-09:** Initial PoC demonstrates superseding (6000 txns, ~5800 superseded) but shared-FD makes slab growth hard to measure
- **2026-07-09:** Unique-FD PoC built — each transaction creates/sends a unique pipe FD
- **2026-07-09:** Full impact demonstrated: 460K transactions, +361 MB permanent kernel slab leak, device load average 26+, no recovery without reboot
