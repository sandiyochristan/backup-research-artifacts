# Pixel 6a Device Reconnaissance — Android 17 Kernel Research

> **Date:** 2026-07-08
> **Serial:** 26131JEGR04733
> **Build:** google/bluejay_beta/bluejay:CinnamonBun/CP31.260608.007/15653239:user/release-keys

---

## Device Profile

| Field | Value |
|-------|-------|
| **Model** | Pixel 6a |
| **Codename** | bluejay |
| **SoC** | Google Tensor G1 (ARM Mali GPU) |
| **Android Version** | 17 (CinnamonBun) |
| **Build ID** | CP31.260608.007 |
| **Build Type** | user (NOT userdebug) |
| **Debuggable** | No (ro.debuggable=0) |
| **Security Patch** | 2026-06-05 |
| **Kernel Version** | 6.1.162-android14-11-g5e8b0cffebd1-ab15202165 |
| **Kernel Branch** | android14-6.1 |
| **Compiler** | Clang 17.0.2 (+pgo, +bolt, +lto) |
| **Preemption** | CONFIG_PREEMPT=y (full preemption) |
| **SELinux** | Enforcing |

---

## Critical Finding: C Binder, NOT Rust Binder

**The Rust Binder is NOT compiled into this kernel.** The config shows only an empty `# Rust hacking` section with no `CONFIG_RUST=y`. The `CONFIG_ANDROID_BINDER_IPC=y` flag points to the C implementation (`drivers/android/binder.c`).

This means:
- The attack surface is the **C Binder driver** on kernel 6.1.162
- BadSpin-class vulnerabilities (race conditions, refcounting bugs) are still the right target class
- The specific CVE-2022-20421 fix is applied, but we're looking for **novel variants**
- The C Binder has had ~4 years of changes since the BadSpin-era code (5.4/5.10 → 6.1)

---

## Kernel Security Hardening

### Active Mitigations
| Mitigation | Status | Impact on Exploitation |
|-----------|--------|----------------------|
| **KASAN (HW Tags)** | `CONFIG_KASAN_HW_TAGS=y` | MTE-based heap tagging — UAF detected probabilistically |
| **CFI (Clang)** | `CONFIG_CFI_CLANG=y` | Blocks function pointer hijacking |
| **Shadow Call Stack** | `CONFIG_SHADOW_CALL_STACK=y` | Protects return addresses |
| **ARM64 BTI** | `CONFIG_ARM64_BTI=y` (userspace only) | Branch target validation |
| **ARM64 MTE** | `CONFIG_ARM64_MTE=y` | Memory tagging in hardware |
| **SLAB Hardened** | `CONFIG_SLAB_FREELIST_HARDENED=y` | Freelist pointer mangling |
| **SLAB Randomized** | `CONFIG_SLAB_FREELIST_RANDOM=y` | Random freelist ordering |
| **init_on_alloc** | `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` | Zero-init heap allocations |
| **FORTIFY_SOURCE** | `CONFIG_FORTIFY_SOURCE=y` | Buffer overflow checks |
| **UBSAN** | `CONFIG_UBSAN=y` + `CONFIG_UBSAN_TRAP=y` | Undefined behavior = panic |
| **HARDENED_USERCOPY** | `CONFIG_HARDENED_USERCOPY=y` | Bounds-check user copies |
| **KSTACK Randomize** | `CONFIG_RANDOMIZE_KSTACK_OFFSET=y` | Stack offset randomization |
| **KASLR** | `CONFIG_RANDOMIZE_BASE=y` | Kernel address randomization |
| **SLUB_DEBUG** | `CONFIG_SLUB_DEBUG=y` | Slab debugging support |
| **DEBUG_LIST** | `CONFIG_DEBUG_LIST=y` | Linked list corruption detection |
| **PANIC_ON_OOPS** | `CONFIG_PANIC_ON_OOPS=y` | Oops = device reboot |

### Key Implications
1. **KASAN HW Tags (MTE)**: Unlike software KASAN, MTE uses hardware memory tagging. Each 16-byte granule gets a 4-bit tag. UAF exploitation requires guessing the correct tag (1/15 chance) or finding a way to leak/control tags.
2. **CFI**: Cannot overwrite function pointers with arbitrary values. Need CFI-compatible targets or must find non-CFI-protected code paths.
3. **init_on_alloc**: All kmalloc objects are zero-initialized. The BadSpin technique of spraying TTY write buffers with 0x00000041 still works (writing to PTY fills the buffer with controlled data after allocation).
4. **PANIC_ON_OOPS**: Failed exploitation attempts will reboot the device. Must be precise.
5. **UBSAN_TRAP**: Integer overflows and undefined behavior cause immediate kernel panic.

---

## Accessible Attack Surfaces

### From shell (UID 2000)
| Interface | Path | Permissions | Notes |
|-----------|------|------------|-------|
| **Binder** | /dev/binder → binderfs | rw (via symlink) | C driver, kernel 6.1 |
| **HW Binder** | /dev/hwbinder → binderfs | rw | Vendor HAL binder |
| **VND Binder** | /dev/vndbinder → binderfs | rw | Vendor binder |
| **ashmem** | /dev/ashmem | crw-rw-rw- | Legacy shared memory |
| **Mali GPU** | /dev/mali0 | crw-rw-rw- | ARM Mali driver — historically bug-rich |
| **DRI** | /dev/dri/card0, renderD128 | crw-rw-rw- | DRM/KMS interface |
| **DMA heaps** | /dev/dma_heap/* | Various | Heap allocation (some system-only) |

### From app context (untrusted_app)
- **Seccomp**: Apps have `Seccomp: 2` (filter mode) with 1 filter
- **Shell has no seccomp** — direct testing from shell has wider syscall access
- **userfaultfd**: Root-only (`crw-------`)
- **io_uring**: Compiled in (`CONFIG_IO_URING=y`) — need to check if seccomp blocks it
- **BPF**: Compiled in, but `CONFIG_BPF_UNPRIV_DEFAULT_OFF` is not set (needs checking)

---

## Research Priority Update

Given that the **C Binder** is active (not Rust), our audit targets shift:

### Priority 1: C Binder on kernel 6.1 (android14-6.1 branch)
- Variant analysis of CVE-2022-20421 race conditions
- New code added since kernel 5.10
- Changes to locking, refcounting, transaction handling
- Error path cleanup in object translation

### Priority 2: Mali GPU driver (ARM)
- `/dev/mali0` is world-readable/writable
- Mali has had numerous CVEs (CVE-2023-4211, CVE-2023-33200, CVE-2024-4610, etc.)
- Complex ioctl interface with shared memory management
- Pixel 6a's Tensor G1 uses Mali-G78 MP20

### Priority 3: io_uring (if accessible from app context)
- `CONFIG_IO_URING=y` — compiled in
- Extremely bug-dense subsystem historically
- Need to verify if seccomp blocks `io_uring_setup()` / `io_uring_enter()`

### Priority 4: DMA heap / ashmem
- Cross-process shared memory with complex lifetime management
