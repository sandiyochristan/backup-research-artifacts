# C Binder Source Code Audit — Kernel 6.1.162 (android14-6.1)

> **Date:** 2026-07-08
> **Kernel:** 6.1.162-android14-11 (C Binder, NOT Rust)
> **Source:** android-kernel-6.1 branch (cloned)
> **File:** `drivers/android/binder.c` — 7367 lines

---

## Executive Summary

The Pixel 6a runs the **C Binder** (`CONFIG_ANDROID_BINDER_IPC=y`) with no Rust support compiled in. This is the same codebase as BadSpin but evolved from 5.10 to 6.1. Several new subsystems have been added:

1. **Freeze mechanism** (`BINDER_FREEZE` ioctl, freeze notifications) — ~400 lines of new code
2. **dbitmap** descriptor allocator (`dbitmap.h`) — lock-release-reacquire pattern
3. **TF_UPDATE_TXN** — superseding outdated frozen transactions
4. **binderfs** — virtual filesystem for binder devices
5. **vendor hooks** — trace/hook points for OEM customization

The **freeze mechanism is the highest-priority target** for novel vulnerability research — it's new, complex, involves multiple lock interactions, and is under-tested.

---

## Finding 1: Missing BINDER_WORK_FROZEN_BINDER in binder_release_work()

**Severity:** Low (memory leak, potential DoS)
**CWE:** CWE-401 (Missing Release of Memory after Effective Lifetime)
**Location:** `binder.c:5342-5406`

The `binder_release_work()` function handles cleanup of undelivered work items during process death. It handles `BINDER_WORK_CLEAR_FREEZE_NOTIFICATION` (line 5393) but does NOT handle `BINDER_WORK_FROZEN_BINDER`. If a `BINDER_WORK_FROZEN_BINDER` item reaches this function, the `default` case prints an error but does not free the `binder_ref_freeze` object.

**Current reachability:** Low — in normal operation, the ref cleanup (`binder_cleanup_ref_olocked`) dequeues freeze work items before `binder_release_work` processes the lists. However, if any bug or race causes a freeze work item to be orphaned from its ref while type is still `BINDER_WORK_FROZEN_BINDER`, the object will leak.

**Same pattern exists for `BINDER_WORK_DEAD_BINDER`** — also not handled in `binder_release_work`, relying on ref cleanup to dequeue first.

---

## Finding 2: dbitmap Lock-Release-Reacquire Window (New Code)

**Severity:** Medium (potential TOCTOU, needs dynamic validation)
**CWE:** CWE-362 (Race Condition)
**Location:** `binder.c:1253-1285`, `dbitmap.h:103-128`

The `get_ref_desc_olocked()` function (line 1253) releases `proc->outer_lock` to allocate memory for dbitmap growth, then reacquires it:

```c
nbits = dbitmap_grow_nbits(dmap);
binder_proc_unlock(proc);           // RELEASES outer_lock
new = bitmap_zalloc(nbits, GFP_KERNEL);
binder_proc_lock(proc);             // REACQUIRES outer_lock
dbitmap_grow(dmap, new, nbits);
return -EAGAIN;                     // Caller retries
```

**During the lock-release window:**
- Other threads can modify `proc->refs_by_node` / `refs_by_desc` trees
- Refs can be added or removed
- The dbitmap state can change

The caller (`binder_get_ref_for_node_olocked`) handles this by retrying from the top. However:
- If `bitmap_zalloc` returns NULL (OOM), `dbitmap_grow` disables the dbitmap entirely (`dbitmap_free`), permanently degrading to `slow_desc_lookup_olocked`
- An attacker can force OOM conditions to disable the dbitmap optimization
- Combined with the lock release window, this could be used to create specific timing conditions

**Assessment:** The retry logic appears correct, but the lock-release window is a race amplifier. Worth investigating for timing attacks.

---

## Finding 3: Freeze Notification State Machine Complexity

**Severity:** Medium-High (potential races in state transitions)
**CWE:** CWE-362 / CWE-667 (Improper Locking)
**Location:** `binder.c:4069-4212`, `binder.c:5815-5863`

The freeze notification mechanism has a 4-state state machine per freeze object:
- `work.type` = `BINDER_WORK_FROZEN_BINDER` or `BINDER_WORK_CLEAR_FREEZE_NOTIFICATION`
- `sent` flag = notification delivered to userspace
- `resend` flag = need to re-enqueue after ack
- `is_frozen` = current freeze state

Three independent code paths modify this state:
1. `binder_add_freeze_work()` — called when target process frozen/unfrozen (holds `node->lock` + `ref->proc->inner_lock`)
2. `binder_clear_freeze_notification()` — called by userspace (holds `proc->outer_lock` + `node->lock` + `proc->inner_lock`)
3. `binder_freeze_notification_done()` — called when userspace acks (holds only `proc->inner_lock`)

**Key concern:** `binder_add_freeze_work()` at line 5843 unconditionally sets `freeze->work.type = BINDER_WORK_FROZEN_BINDER` without checking if a CLEAR is in progress. While the `ref->freeze == NULL` check at line 5839 provides some synchronization, there may be windows where:
- `binder_clear_freeze_notification` sets `ref->freeze = NULL` and changes type to CLEAR
- Before `binder_add_freeze_work` reads `ref->freeze`, the type is already changed
- But `ref->freeze` is already NULL, so it's skipped

This needs dynamic testing with concurrent freeze/unfreeze/clear operations.

---

## Finding 4: TF_UPDATE_TXN — Transaction Superseding in Frozen Processes

**Severity:** Medium (potential UAF via race in buffer cleanup)
**CWE:** CWE-416 (Use After Free)
**Location:** `binder.c:3086-3126`

When a process is frozen and receives an async oneway transaction with `TF_UPDATE_TXN`, the old transaction is superseded:

```c
if ((t->flags & TF_UPDATE_TXN) && proc->is_frozen) {
    t_outdated = binder_find_outdated_transaction_ilocked(t, &node->async_todo);
    if (t_outdated) {
        list_del_init(&t_outdated->work.entry);
        proc->outstanding_txns--;
    }
}
```

The outdated transaction's buffer is then freed AFTER releasing all locks (line 3116-3126):
```c
t_outdated->buffer = NULL;
buffer->transaction = NULL;
binder_release_entire_buffer(proc, NULL, buffer, false);
binder_alloc_free_buf(&proc->alloc, buffer);
kfree(t_outdated);
```

**Race scenario to investigate:** What if the frozen process unfreezes between the lock release and the buffer free? The buffer release uses `proc` as the allocation owner, but if the process dies while the buffer is being released, `proc->alloc` could be in an inconsistent state.

**Assessment:** The `t_outdated` was properly dequeued under the lock, so no other thread should reference it. But the buffer release involves complex operations (fd closing, ref decrementing) that access other processes' state. Need to verify all paths.

---

## Finding 5: binder_alloc Lock Contention During Transaction

**Severity:** Low-Medium (timing side-channel, race window amplifier)
**Location:** `binder_alloc.c:582-633`

`binder_alloc_new_buf()` preallocates a split buffer before taking the allocation lock, then installs page mappings AFTER releasing it:

```c
next = kzalloc(sizeof(*next), GFP_KERNEL);    // Prealloc outside lock
binder_alloc_lock(alloc);
buffer = binder_alloc_new_buf_locked(alloc, next, size, is_async);
binder_alloc_unlock(alloc);
ret = binder_install_buffer_pages(alloc, buffer, size);  // Page install outside lock
if (ret) {
    binder_alloc_free_buf(alloc, buffer);  // Free on failure
}
```

Between `binder_alloc_unlock` and `binder_install_buffer_pages`, the buffer is allocated but pages may not be mapped. If another thread concurrently accesses this buffer region (via a different allocation that shares a page boundary), there could be a race.

---

## Priority Attack Surfaces for Dynamic Testing

### 1. Freeze Mechanism Races (Highest Priority)
- Concurrent `BINDER_FREEZE` + transaction delivery
- Concurrent `BC_REQUEST_FREEZE_NOTIFICATION` + process death
- Concurrent `binder_add_freeze_work` + `binder_clear_freeze_notification`
- Rapid freeze/unfreeze cycling with outstanding transactions

### 2. dbitmap Growth Under Lock Pressure
- Force dbitmap to grow (exhaust initial 64-bit bitmap)
- Trigger OOM during growth to disable dbitmap
- Race ref creation with dbitmap growth

### 3. TF_UPDATE_TXN Race Window
- Send `TF_UPDATE_TXN` transactions to a frozen process
- Race the unfreeze with transaction superseding
- Verify buffer cleanup ordering

### 4. Death Notification + Freeze Notification Interaction
- Register both death and freeze notifications for same ref
- Kill the target process while freeze notification is in-flight
- Verify cleanup ordering

---

---

## Finding 6: CONFIRMED — Missing binder_free_txn_fixups() in TF_UPDATE_TXN Path

**Severity:** Medium (CVSS 3.1: ~5.5 — local DoS via resource exhaustion)
**CWE:** CWE-401 (Missing Release of Memory) / CWE-772 (Missing Release of Resource)
**Location:** `binder.c:3124` — `kfree(t_outdated)` without `binder_free_txn_fixups()`
**Status:** [CONFIRMED] — static analysis conclusive, upstream android-mainline affected

When `TF_UPDATE_TXN` supersedes an async transaction in a frozen process's `async_todo`, `kfree(t_outdated)` is called without first calling `binder_free_txn_fixups(t_outdated)`. If the superseded transaction contained `BINDER_TYPE_FD` objects, the `binder_txn_fd_fixup` structs and their `struct file` references leak permanently.

**Evidence:**
- Line 3124: `kfree(t_outdated)` — **no** `binder_free_txn_fixups()` call
- Line 1873-1874: `binder_free_transaction()` — **has** `binder_free_txn_fixups(t); kfree(t);`
- Line 3985: error path — **has** `binder_free_txn_fixups(t)` before `kfree(t)` at 4004
- All other transaction kfree paths properly call `binder_free_txn_fixups()`
- TF_UPDATE_TXN path is the **ONLY** one missing the cleanup

**Fix:** One line: `binder_free_txn_fixups(t_outdated);` before `kfree(t_outdated);`

**Full report:** `CVE_CANDIDATE_BINDER_FD_FIXUP_LEAK.md`

---

## Summary of All Findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | Missing FROZEN_BINDER in binder_release_work | Low | [INFO] under-tested code |
| 2 | dbitmap lock-release-reacquire window | Medium | [POSSIBLE] needs dynamic validation |
| 3 | Freeze notification state machine complexity | Medium-High | [POSSIBLE] needs dynamic validation |
| 4 | TF_UPDATE_TXN buffer cleanup race | Medium | Reclassified → Finding 6 is the real bug |
| 5 | binder_alloc lock contention | Low-Medium | [INFO] timing amplifier |
| **6** | **Missing binder_free_txn_fixups() in TF_UPDATE_TXN** | **Medium** | **[CONFIRMED]** |

---

## Next Steps

1. ~~Build a C test harness for the Pixel 6a~~ DONE — `binder_freeze_racer.c`, `binder_fd_leak_v2.c`
2. Submit Finding 6 to Google VRP / Android Security
3. Continue auditing for novel races in freeze notification state machine (dynamic testing needs app context for BINDER_FREEZE)
4. Audit Mali GPU driver (`/dev/mali0` — world-writable, historically bug-rich)
5. Check io_uring and BPF accessibility from untrusted_app context
