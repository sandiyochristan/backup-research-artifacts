# Kernel audit notes — Pixel 6a / android14-6.1

These are research notes produced during the kernel audit. The full notes were also synced to the
Obsidian vault (`Android-Security-Research/kernel/`); this is the local mirror so the repo is
self-contained.

## Device fingerprint
- Kernel: **6.1.172-android14-11-g8d0115b07367-ab16385437** (built Sep 18 2026)
- Build: `google/bluejay_beta/bluejay:17/CP41.260831.007.A3/16450490:user/release-keys` (beta)
- SELinux Enforcing, `CONFIG_SECURITY_SELINUX_DEVELOP=y`, `CONFIG_USER_NS` not set
- Sanitizers compiled in: `CONFIG_KASAN=y` (+HW tags, VMALLOC), `UBSAN_SANITIZE_ALL=y`,
  `ANDROID_DEBUG_SYMBOLS=y`, BTF present

## FINDING (re-confirmed, STILL UNPATCHED) — binder TF_UPDATE_TXN fd_fixup leak
Audited `drivers/android/binder.c` at android14-6.1 HEAD `6612ef9d` (2026-09-29, newer than the
device build):

```
3139  binder_release_entire_buffer(proc, NULL, buffer, false);
3140  binder_alloc_free_buf(&proc->alloc, buffer);
3141  kfree(t_outdated);          <-- no binder_free_txn_fixups()
```

`binder_free_txn_fixups()` is called at only 3 sites (1890, 4002, 4896). The `TF_UPDATE_TXN`
supersede path at 3141 remains the ONLY path that frees a transaction without releasing its
`binder_txn_fd_fixup` list, so every superseded FD-bearing transaction permanently leaks a
`struct file` + fixup. Reachable from `untrusted_app` (`TF_UPDATE_TXN` = 0x40 is not privileged;
AMS freezes background targets automatically). **Still open ~2 months after the July 2026 report.**

## Freeze-notification state machine — hypotheses NOT substantiated
- `binder_add_freeze_work()` (5832) sets `work.type = BINDER_WORK_FROZEN_BINDER`, reuses existing
  `ref->freeze`, handles sent/resend/is_frozen under `inner_lock`.
- `BC_CLEAR_FREEZE_NOTIFICATION` verifies the cookie before taking the object and re-types the
  existing work (no double-alloc).
- `binder_cleanup_ref_olocked` (1414) and `binder_free_ref` (1546) DO dequeue
  `ref->freeze->work` before `kfree`, and `binder_enqueue_work_ilocked` is
  `BUG_ON(work->entry.next && !list_empty(&work->entry))`-guarded.
=> The earlier "freeze UAF" hypotheses do not hold in this tree. Do not report them.

## Reachability triage (the decisive negative)
Android's own `system/sepolicy/private/app_neverallows.te`:
```
neverallow all_untrusted_apps domain:anon_inode *;
```
io_uring and userfaultfd are both anon_inode-backed, so this single rule removes both from
app reachability. `io_uring_use()` is granted only to native daemons (snapuserd/fastbootd/statsd);
`userfaultfd_use()` only to zygote/webview_zygote/system_server/dex2oat/odrefresh/dexoptanalyzer.
`CONFIG_NF_TABLES` is **not set** (legacy xtables/conntrack only).

Raw binder framing is also closed: a minimal, well-formed `BINDER_WRITE_READ` from an untrusted app
returns **EACCES** with `avc: denied { ioctl } … ioctlcmd=0x6204`. Binder *transactions* remain
app-reachable through zygote's inherited fd (which is why the July CVE PoC works) — but the raw
transaction parser cannot be fuzzed from an app.

## Still compiled in and app-adjacent (candidates, not yet exploited)
`FUSE_FS` + `FUSE_BPF`, `XDP_SOCKETS`, `NET_CLS_BPF`, `INET_ESP`, `NET_NS`, `USB_CONFIGFS`,
`BPF_SYSCALL`, `/dev/mali*` (Tensor GPU), NFC vendor HAL.
