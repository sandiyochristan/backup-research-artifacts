# Android 17 Kernel Vulnerability Research Plan

> **Researcher:** Sandiyochristan
> **Date:** 2026-07-08
> **Device:** Google Pixel 6a (Google-provided for research)
> **Target:** Android 17, latest security patch, stock production kernel
> **Prior Work:** CVE-2022-20421 (BadSpin) — Binder spinlock UAF, kernels 5.4.x/5.10.x
> **Goal:** Discover novel, undiscovered kernel vulnerabilities reachable from untrusted_app

---

## 1. What Changed Since BadSpin (Kernel 5.10 → 6.x)

### 1.1 Binder Driver Evolution
- **Rust Binder rewrite**: New parallel implementation in `drivers/android/binder/` with 14+ Rust source files (process.rs, transaction.rs, node.rs, thread.rs, allocation.rs, context.rs, etc.)
- **C Binder still exists**: `drivers/android/binder.c` remains — both implementations may coexist or be compile-time selectable
- **New locking architecture**: Three-tier locks (outer_lock, node->lock, inner_lock) — different from the single inner_lock/outer_lock model in 5.10
- **CVE-2022-20421 fix**: The race in `binder_inc_ref_for_node()` / `binder_inc_node_nilocked()` where a stale `binder_ref` to a dying process's `binder_proc` was created has been patched
- **New subsystems**: `binderfs.c`, `binder_netlink.c`, `vendor_hooks.c`, `dbitmap.h`, `debug_kinfo.c`

### 1.2 Kernel Hardening Since 5.10
- `CONFIG_REFCOUNT_FULL` removed (kernel ≥ 5.7) — all refcount_t checks are always on
- Enhanced KASAN / MTE (Memory Tagging Extension) on supported hardware
- CFI (Control Flow Integrity) enforcement — clang CFI or kCFI
- PAC (Pointer Authentication Codes) on ARMv8.3+
- BTI (Branch Target Identification) 
- `init_on_alloc` / `init_on_free` by default
- Stricter SELinux policies
- `usercopy` hardening expanded
- `CONFIG_SLAB_FREELIST_HARDENED` / `CONFIG_SLAB_FREELIST_RANDOM`
- `addr_limit` removal (no more UAO-based arbitrary R/W technique)

### 1.3 Implications for Exploitation
- The BadSpin technique of overwriting `addr_limit` via UAO **no longer works** on kernel 6.x (addr_limit removed)
- `filp_cache` / `kmalloc-1k` cross-cache attacks are harder with `init_on_alloc`
- CFI blocks simple function pointer overwrites
- MTE (if enabled) tags heap memory — makes UAF exploitation probabilistic
- New exploitation primitives needed even if a bug is found

---

## 2. Research Strategy — Attack Surface Prioritization

### Priority 1: Rust Binder Implementation (NEW CODE = NEW BUGS)

**Rationale:** The Rust Binder is new code that handles the same complex IPC logic. While Rust prevents memory safety bugs in safe code, the Rust Binder:
- Uses extensive `unsafe` blocks for kernel FFI
- Interacts with C kernel infrastructure (kmalloc, spinlocks, waitqueues)
- Must correctly implement complex reference counting across process boundaries
- Has `unsafe` pointer manipulation at the Rust/C boundary

**Audit targets:**
| File | Attack Surface |
|------|---------------|
| `process.rs` | binder_proc lifecycle, fd management, mmap |
| `transaction.rs` | Object translation, scatter-gather, the core race window area |
| `node.rs` + `node/wrapper.rs` | Node refcounting, death notifications — where BadSpin lived |
| `thread.rs` | Thread lifecycle, work queue management |
| `allocation.rs` | Buffer allocation in binder mmap'd region |
| `context.rs` | Context manager operations |
| `deferred_close.rs` | Deferred fd closing — new mechanism |
| `range_alloc/` | Custom range allocator — memory management bugs? |
| `defs.rs` | Struct definitions, unsafe transmutes, type punning |

**What to look for:**
- Logic errors in refcounting (Rust can have logic bugs even without memory unsafety)
- `unsafe` blocks that make incorrect assumptions about invariants
- TOCTOU races between Rust safe code and underlying C kernel state
- Error path handling — does the Rust code correctly unwind all state on failure?
- Integer overflow/underflow in allocation size calculations
- Missing validation at the Rust/C FFI boundary

### Priority 2: C Binder — Variant Analysis of BadSpin

**Rationale:** The CVE-2022-20421 fix patched one specific race, but the fundamental pattern (stale references to dying processes) may have variants in related code paths.

**Variant hunt targets:**
1. **HANDLE vs WEAK_HANDLE translation**: BadSpin used WEAK_HANDLE. Are there similar races with HANDLE translation? (Appendix B of the paper hinted at this)
2. **binder_node_release() death notification enumeration**: Iterates refs while nodes are being modified — any new races introduced?
3. **binder_deferred_release() cleanup ordering**: Are there other objects that can be accessed after the process dies but before cleanup completes?
4. **binder_transaction() error paths**: Object translation failures during error cleanup — any objects leaked or double-freed?
5. **File descriptor translation (FDA objects)**: Complex state machine with process-crossing fd operations
6. **Scatter-gather (SG) copy operations**: Buffer management during SG copies — off-by-one, overflow?

### Priority 3: Non-Binder Kernel Attack Surfaces from untrusted_app

**Rationale:** Diversify beyond Binder. These are reachable from the app sandbox.

| Interface | Path | Why Interesting |
|-----------|------|-----------------|
| **ion / dma-buf** | `/dev/dma_heap/*` | Shared memory — complex refcounting, cross-process lifetimes |
| **ashmem** (if still present) | `/dev/ashmem` | Legacy shared memory, mmap-related bugs |
| **GPU driver (Mali/Adreno)** | `/dev/mali0`, `/dev/kgsl-3d0` | Complex, vendor-specific, historically bug-rich |
| **V4L2 / camera** | `/dev/video*` | Media framework kernel interfaces |
| **netlink sockets** | `socket(AF_NETLINK)` | Kernel networking from app context |
| **io_uring** (if enabled) | `io_uring_setup()` | Complex async I/O — extremely bug-dense historically |
| **perf_event** | `perf_event_open()` | Performance monitoring — seccomp-filtered but worth checking |
| **userfaultfd** | `userfaultfd()` | Page fault handling — useful as exploit primitive |
| **eBPF** (if accessible) | `bpf()` syscall | Program verification bugs — usually restricted but check |
| **Pixel-specific drivers** | Various | Titan M2, UFS, display, modem interfaces |

### Priority 4: Syscall Interface Fuzzing

**Rationale:** Systematic coverage of what the `untrusted_app` domain can actually reach.

**Approach:**
1. Extract the seccomp-bpf filter applied to the zygote/app process
2. Map all allowed syscalls
3. For each allowed syscall, identify kernel code paths reachable with valid/edge-case arguments
4. Focus on syscalls that interact with kernel objects (fds, mmaps, ioctls)

---

## 3. Research Phases

### Phase 1: Reconnaissance (Current)
- [ ] Connect Pixel 6a, extract exact kernel version, build config
- [ ] Dump seccomp filter to know which syscalls are accessible
- [ ] Extract `/proc/config.gz` for kernel configuration
- [ ] Identify which Binder implementation is active (C vs Rust)
- [ ] Map SELinux policy for `untrusted_app` domain
- [ ] List accessible device nodes from app sandbox

### Phase 2: Source Code Audit
- [ ] Audit Rust Binder `unsafe` blocks systematically
- [ ] Variant analysis: search for BadSpin-pattern races in new code
- [ ] Audit `transaction.rs` object translation error paths
- [ ] Audit `node.rs` reference counting logic
- [ ] Audit `deferred_close.rs` for lifetime/ordering issues
- [ ] Review recent Binder commits for incomplete fixes
- [ ] Cross-reference C and Rust implementations for behavioral differences

### Phase 3: Dynamic Analysis (Device)
- [ ] Build and deploy kernel tracing (ftrace) for Binder operations
- [ ] Write targeted fuzzers for specific Binder ioctl sequences
- [ ] Race condition testing with multi-threaded Binder operations
- [ ] Stress test process death + transaction interleaving
- [ ] Monitor KASAN output (if enabled) during fuzzing
- [ ] Test non-Binder attack surfaces (GPU, dma-buf, etc.)

### Phase 4: Vulnerability Development
- [ ] For any confirmed bugs: determine exploitability
- [ ] Develop PoC that demonstrates the primitive
- [ ] Assess impact (info leak, privilege escalation, DoS)
- [ ] Write VRP report with complete evidence

---

## 4. First Steps (When Device Connected)

```bash
# 1. Basic device info
adb shell getprop ro.build.fingerprint
adb shell uname -r
adb shell cat /proc/version

# 2. Kernel config
adb shell cat /proc/config.gz | gunzip > kernel_config.txt

# 3. Seccomp filter (from zygote)
adb shell cat /proc/$(adb shell pidof zygote64)/status | grep Seccomp

# 4. SELinux context
adb shell id
adb shell getenforce
adb shell cat /sys/fs/selinux/policy > sepolicy.bin

# 5. Accessible device nodes
adb shell ls -la /dev/binder /dev/hwbinder /dev/vndbinder
adb shell ls -la /dev/dma_heap/
adb shell ls -la /dev/mali* /dev/kgsl* 2>/dev/null

# 6. Binder implementation check
adb shell dmesg | grep -i binder
adb shell cat /proc/filesystems | grep binder

# 7. Check if io_uring is available
adb shell cat /proc/config.gz | gunzip | grep IO_URING

# 8. Kernel modules
adb shell lsmod
```

---

## 5. Key Questions to Answer

1. **Is the Rust Binder active on this device?** Or is it still the C implementation?
2. **What kernel version exactly?** (6.1? 6.6? 6.12?)
3. **Is MTE enabled?** (Pixel 6a has ARMv8.5 with MTE support)
4. **Is kCFI/CFI active?** (Blocks function pointer hijacking)
5. **What's the seccomp filter?** (Defines reachable syscall surface)
6. **Is io_uring enabled?** (Rich attack surface if so)
7. **Which GPU driver?** (Pixel 6a = Mali GPU = ARM driver)
8. **What slab allocator?** (SLUB vs SLAB, hardening options)

---

## 6. Novel Research Angles

### 6.1 Rust/C Binder Semantic Gaps
If both implementations exist, look for behavioral differences where the C code does X but the Rust code does Y for the same operation. Semantic gaps between parallel implementations are a rich source of bugs.

### 6.2 Rust unsafe Audit
Systematic review of every `unsafe` block in the Rust Binder for:
- Raw pointer dereferences without null checks
- Incorrect lifetime assumptions
- Missing Send/Sync bounds on types shared across threads
- Aliased mutable references (undefined behavior in Rust)

### 6.3 Cross-Process Binder Object Lifetime Confusion
The fundamental complexity of Binder hasn't changed: objects that span process lifetimes with asynchronous death notifications. The Rust rewrite may have introduced new ordering assumptions.

### 6.4 dma-buf / DMA Heap Exploitation
Modern Android relies heavily on dma-buf for GPU, camera, and display buffers. The refcounting and cross-device sharing creates complex lifetime management — similar patterns to Binder.

### 6.5 Kernel Task Work / Deferred Operations
The `deferred_close.rs` and task_work mechanism in the kernel are relatively new and handle asynchronous cleanup — race-prone by nature.
