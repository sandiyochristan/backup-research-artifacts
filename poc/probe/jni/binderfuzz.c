/*
 * binderfuzz.c — raw BINDER_WRITE_READ fuzzer for the app-reachable Android binder driver.
 *
 * Rationale: /dev/binder is reachable from untrusted_app. A malformed binder transaction that
 * drives the kernel binder parser into an OOB/UAF is a local privilege escalation (RCE-equivalent).
 * This kernel has CONFIG_KASAN=y, so any such bug is caught with a precise report = proof.
 *
 * We craft binder_object payloads (strings / fds / strong-binder objects) at hostile offsets,
 * including TF_UPDATE_TXN-flagged oneway transactions, which is where the known fd_fixup leak and
 * the under-tested freeze/supersede paths live.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/binder.h>
#include <sys/ioctl.h>
#include <android/log.h>

static int g_fd = -1;

/* the exact ioctl number this binary issues, for SELinux AVC correlation */

/* deterministic xorshift so runs are reproducible from a seed we control */
static uint64_t rng_state;
static uint32_t xr(void) {
    uint64_t x = rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    rng_state = x;
    return (uint32_t)(x >> 32);
}

int bff_ioctlnum(void) { return (int)BINDER_WRITE_READ; }

int bff_open(const char *dev) {
    g_fd = open(dev, O_RDWR | O_CLOEXEC);
    if (g_fd < 0) return -errno;
    return g_fd;
}

int bff_run(int seed, int iters) {
    rng_state = (uint64_t)seed * 6364136223846793005ULL + 1442695040888963407ULL;
    if (g_fd < 0) return -1;
    if (mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
        return -errno;

    size_t bufsz = 256 * 1024;
    uint8_t *buf = malloc(bufsz);
    if (!buf) return -ENOMEM;

    for (int i = 0; i < iters; i++) {
        uint32_t flags = TF_ACCEPT_FDS | TF_ONE_WAY | TF_UPDATE_TXN | (xr() & 0xF);
        uint32_t objsize = 1 + (xr() % 8);
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_buffer = (uintptr_t)buf;
        /* prepend a binder_transaction_header so the kernel enters the transaction path */
        uint32_t hdr_words = 3 + objsize;  /* header(3 words) + objects */
        bwr.write_size = hdr_words * sizeof(__u32);
        bwr.write_consumed = 0;
        struct { __u32 size; __u32 ptr; __u32 flags; } th;
        th.size = bwr.write_size;
        th.ptr  = 0;
        th.flags = flags;
        memcpy(buf, &th, sizeof(th));

        /* fill with hostile binder_object records */
        struct binder_object *o = (struct binder_object *)(buf + 3 * sizeof(__u32));
        for (uint32_t k = 0; k < objsize; k++) {
            uint32_t kind = xr() % 6;
            memset(&o[k], xr() & 0xFF, sizeof(o[k]));
            o[k].hdr.type = (kind == 0) ? BINDER_TYPE_BINDER :
                            (kind == 1) ? BINDER_TYPE_HANDLE :
                            (kind == 2) ? BINDER_TYPE_FD :
                            (kind == 3) ? BINDER_TYPE_STRING_UTF8 :
                            (kind == 4) ? BINDER_TYPE_BUFFER : BINDER_TYPE_BINDER;
            o[k].flags = 1 | (xr() & 0xFE);
            o[k].binder_type = BINDER_TYPE_WEAK_BINDER;
            o[k].weak_ref = xr();            /* bogus node descriptor -> node lookup path */
            o[k].strong_ref = xr();
            o[k].padding[0] = xr();
            if (o[k].hdr.type == BINDER_TYPE_FD)
                o[k].weak_ref = (uint32_t)(xr() % 4) + 1000; /* fd slot */
        }

        if (ioctl(g_fd, BINDER_WRITE_READ, &bwr) < 0) {
            /* expected: most malformed payloads are rejected; keep going */
            if (errno != EINVAL && errno != EBADF && errno != EFAULT &&
                errno != ENOSYS && errno != EPERM && errno != EINTR)
                { free(buf); return -errno; }
        }
    }
    free(buf);
    return iters;
}

/* Control: a MINIMAL, well-formed BINDER_WRITE_READ (empty transaction, no fuzzing).
 * Distinguishes "ioctl is blanket-denied for untrusted_app" from "my payload is rejected". */
int bff_clean(void) {
    if (g_fd < 0) return -1;
    size_t sz = 64;
    unsigned char *buf = calloc(1, sz);
    struct binder_transaction_header *th = (struct binder_transaction_header *)buf;
    th->size = sz;
    th->ptr = 0;
    th->flags = 0;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = (uintptr_t)buf;
    bwr.write_size = sz;
    int rc = ioctl(g_fd, BINDER_WRITE_READ, &bwr);
    int e = errno;
    free(buf);
    return rc < 0 ? -e : rc;
}
