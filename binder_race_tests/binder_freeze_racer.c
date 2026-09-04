/*
 * binder_freeze_racer.c — Race condition tester for Android Binder freeze mechanism
 *
 * Targets: Kernel 6.1.162-android14-11 (Pixel 6a)
 * Goal: Trigger races in freeze notification state machine, dbitmap growth,
 *       TF_UPDATE_TXN transaction superseding, and process death cleanup.
 *
 * PANIC_ON_OOPS=y means any kernel fault reboots the device.
 * KASAN HW_TAGS (MTE) will catch UAF probabilistically.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <linux/android/binder.h>

#define BINDER_DEV "/dev/binder"
#define MMAP_SIZE (1024 * 1024)

static volatile int g_running = 1;
static volatile pid_t g_target_pid = 0;

static int open_binder(void)
{
    int fd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;

    void *mapped = mmap(NULL, MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        close(fd);
        return -1;
    }

    return fd;
}

static int binder_write_read(int fd, void *wdata, size_t wlen,
                             void *rdata, size_t rlen)
{
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = wlen;
    bwr.write_buffer = (uintptr_t)wdata;
    bwr.read_size = rlen;
    bwr.read_buffer = (uintptr_t)rdata;

    return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int binder_write(int fd, void *data, size_t len)
{
    return binder_write_read(fd, data, len, NULL, 0);
}

/* ------------------------------------------------------------------- */
/* Test 1: Freeze/unfreeze cycling racing with process death           */
/* ------------------------------------------------------------------- */

static void test_freeze_death_race(int iterations)
{
    printf("[*] Test 1: Freeze/unfreeze + process death race (%d iters)\n", iterations);

    int i;
    for (i = 0; i < iterations && g_running; i++) {
        pid_t target = fork();
        if (target == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);
            ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
            pause();
            _exit(0);
        }

        usleep(20000);

        pid_t freezer = fork();
        if (freezer == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);

            struct binder_freeze_info info;
            info.pid = target;
            info.timeout_ms = 0;

            int j;
            for (j = 0; j < 500; j++) {
                info.enable = 1;
                ioctl(fd, BINDER_FREEZE, &info);
                info.enable = 0;
                ioctl(fd, BINDER_FREEZE, &info);
            }
            close(fd);
            _exit(0);
        }

        /* Race: kill target while freeze/unfreeze is happening */
        usleep(5000 + (rand() % 10000));
        kill(target, SIGKILL);

        waitpid(target, NULL, 0);
        waitpid(freezer, NULL, 0);

        if (i % 20 == 0)
            printf("    %d/%d\n", i, iterations);
    }
    printf("[+] Test 1 complete (%d iterations survived)\n\n", i);
}

/* ------------------------------------------------------------------- */
/* Test 2: TF_UPDATE_TXN with concurrent freeze/unfreeze               */
/* ------------------------------------------------------------------- */

struct txn_sender_args {
    pid_t target_pid;
    int iterations;
};

static void *txn_sender_thread(void *arg)
{
    struct txn_sender_args *a = (struct txn_sender_args *)arg;
    int fd = open_binder();
    if (fd < 0) return NULL;

    struct {
        uint32_t cmd;
        struct binder_transaction_data tr;
    } __attribute__((packed)) txn;

    int i;
    for (i = 0; i < a->iterations && g_running; i++) {
        memset(&txn, 0, sizeof(txn));
        txn.cmd = BC_TRANSACTION;
        txn.tr.target.handle = 0;
        txn.tr.code = 1;
        txn.tr.flags = TF_ONE_WAY | TF_UPDATE_TXN;
        txn.tr.data_size = 0;
        txn.tr.offsets_size = 0;

        binder_write(fd, &txn, sizeof(txn));

        /* Read any replies to drain buffers */
        char rbuf[256];
        binder_write_read(fd, NULL, 0, rbuf, sizeof(rbuf));
    }

    close(fd);
    return NULL;
}

static void *freeze_toggle_thread(void *arg)
{
    pid_t target = *(pid_t *)arg;
    int fd = open_binder();
    if (fd < 0) return NULL;

    struct binder_freeze_info info;
    info.pid = target;
    info.timeout_ms = 0;

    int i;
    for (i = 0; i < 50000 && g_running; i++) {
        info.enable = 1;
        ioctl(fd, BINDER_FREEZE, &info);
        info.enable = 0;
        ioctl(fd, BINDER_FREEZE, &info);
    }

    close(fd);
    return NULL;
}

static void test_update_txn_race(int iterations)
{
    printf("[*] Test 2: TF_UPDATE_TXN + freeze race (%d iters)\n", iterations);

    int i;
    for (i = 0; i < iterations && g_running; i++) {
        pid_t target = fork();
        if (target == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);
            ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
            /* Don't process transactions — let them queue up */
            sleep(30);
            _exit(0);
        }

        usleep(50000);

        struct txn_sender_args args = { .target_pid = target, .iterations = 5000 };

        pthread_t senders[4], freezer;
        int j;
        for (j = 0; j < 4; j++)
            pthread_create(&senders[j], NULL, txn_sender_thread, &args);
        pthread_create(&freezer, NULL, freeze_toggle_thread, &target);

        for (j = 0; j < 4; j++)
            pthread_join(senders[j], NULL);
        g_running = 0;
        pthread_join(freezer, NULL);
        g_running = 1;

        kill(target, SIGKILL);
        waitpid(target, NULL, 0);

        if (i % 5 == 0)
            printf("    %d/%d\n", i, iterations);
    }
    printf("[+] Test 2 complete (%d iterations survived)\n\n", i);
}

/* ------------------------------------------------------------------- */
/* Test 3: Freeze notification request/clear race                      */
/* ------------------------------------------------------------------- */

static void test_freeze_notification_race(int iterations)
{
    printf("[*] Test 3: BC_REQUEST/CLEAR_FREEZE_NOTIFICATION race (%d iters)\n",
           iterations);

    int i;
    for (i = 0; i < iterations && g_running; i++) {
        pid_t target = fork();
        if (target == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);
            ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
            pause();
            _exit(0);
        }

        usleep(30000);

        /* Watcher process: requests and clears freeze notifications rapidly */
        pid_t watcher = fork();
        if (watcher == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);

            /* First, send a transaction to get a handle (ref) to the target */
            struct {
                uint32_t cmd;
                struct binder_transaction_data tr;
            } __attribute__((packed)) txn;

            memset(&txn, 0, sizeof(txn));
            txn.cmd = BC_TRANSACTION;
            txn.tr.target.handle = 0; /* context manager */
            txn.tr.code = 1;
            txn.tr.flags = TF_ONE_WAY;
            txn.tr.data_size = 0;
            txn.tr.offsets_size = 0;
            binder_write(fd, &txn, sizeof(txn));

            usleep(10000);

            /* Request/clear freeze notifications on handle 0 */
            struct {
                uint32_t cmd;
                struct binder_handle_cookie hc;
            } __attribute__((packed)) req;

            int j;
            for (j = 0; j < 1000; j++) {
                /* Request freeze notification */
                req.cmd = BC_REQUEST_FREEZE_NOTIFICATION;
                req.hc.handle = 0;
                req.hc.cookie = (binder_uintptr_t)0xdeadbeef;
                binder_write(fd, &req, sizeof(req));

                /* Drain read buffer */
                char rbuf[256];
                binder_write_read(fd, NULL, 0, rbuf, sizeof(rbuf));

                /* Clear freeze notification */
                req.cmd = BC_CLEAR_FREEZE_NOTIFICATION;
                req.hc.handle = 0;
                req.hc.cookie = (binder_uintptr_t)0xdeadbeef;
                binder_write(fd, &req, sizeof(req));

                /* Drain */
                binder_write_read(fd, NULL, 0, rbuf, sizeof(rbuf));
            }

            close(fd);
            _exit(0);
        }

        /* Freezer process: cycles freeze/unfreeze on the target */
        pid_t freezer = fork();
        if (freezer == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);

            struct binder_freeze_info info;
            info.pid = target;
            info.timeout_ms = 0;

            int j;
            for (j = 0; j < 2000; j++) {
                info.enable = 1;
                ioctl(fd, BINDER_FREEZE, &info);
                info.enable = 0;
                ioctl(fd, BINDER_FREEZE, &info);
            }

            close(fd);
            _exit(0);
        }

        /* Let them race for a while, then kill the target */
        usleep(50000 + (rand() % 50000));
        kill(target, SIGKILL);

        waitpid(target, NULL, 0);
        waitpid(watcher, NULL, 0);
        waitpid(freezer, NULL, 0);

        if (i % 10 == 0)
            printf("    %d/%d\n", i, iterations);
    }
    printf("[+] Test 3 complete (%d iterations survived)\n\n", i);
}

/* ------------------------------------------------------------------- */
/* Test 4: Massive ref creation to stress dbitmap growth               */
/* ------------------------------------------------------------------- */

static void test_dbitmap_stress(int iterations)
{
    printf("[*] Test 4: dbitmap growth stress test (%d iters)\n", iterations);

    int i;
    for (i = 0; i < iterations && g_running; i++) {
        pid_t target = fork();
        if (target == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);
            ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
            pause();
            _exit(0);
        }

        usleep(30000);

        /* Two processes creating refs concurrently to race dbitmap growth */
        pid_t workers[3];
        int w;
        for (w = 0; w < 3; w++) {
            workers[w] = fork();
            if (workers[w] == 0) {
                int fd = open_binder();
                if (fd < 0) _exit(1);

                struct {
                    uint32_t cmd;
                    struct binder_transaction_data tr;
                } __attribute__((packed)) txn;

                int j;
                for (j = 0; j < 200; j++) {
                    memset(&txn, 0, sizeof(txn));
                    txn.cmd = BC_TRANSACTION;
                    txn.tr.target.handle = 0;
                    txn.tr.code = j + 1;
                    txn.tr.flags = TF_ONE_WAY;
                    txn.tr.data_size = 0;
                    txn.tr.offsets_size = 0;
                    binder_write(fd, &txn, sizeof(txn));
                }

                close(fd);
                _exit(0);
            }
        }

        /* Kill target while workers are creating refs */
        usleep(10000 + (rand() % 20000));
        kill(target, SIGKILL);

        waitpid(target, NULL, 0);
        for (w = 0; w < 3; w++)
            waitpid(workers[w], NULL, 0);

        if (i % 10 == 0)
            printf("    %d/%d\n", i, iterations);
    }
    printf("[+] Test 4 complete (%d iterations survived)\n\n", i);
}

/* ------------------------------------------------------------------- */
/* Test 5: Death + freeze notification combined                        */
/* ------------------------------------------------------------------- */

static void test_death_freeze_combined(int iterations)
{
    printf("[*] Test 5: Death + freeze notification combined (%d iters)\n",
           iterations);

    int i;
    for (i = 0; i < iterations && g_running; i++) {
        pid_t target = fork();
        if (target == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);
            ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
            pause();
            _exit(0);
        }

        usleep(30000);

        pid_t watcher = fork();
        if (watcher == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);

            /* Request both death and freeze notifications on handle 0 */
            struct {
                uint32_t cmd;
                struct binder_handle_cookie hc;
            } __attribute__((packed)) req;

            /* Death notification */
            req.cmd = BC_REQUEST_DEATH_NOTIFICATION;
            req.hc.handle = 0;
            req.hc.cookie = (binder_uintptr_t)0x1111;
            binder_write(fd, &req, sizeof(req));

            /* Freeze notification */
            req.cmd = BC_REQUEST_FREEZE_NOTIFICATION;
            req.hc.handle = 0;
            req.hc.cookie = (binder_uintptr_t)0x2222;
            binder_write(fd, &req, sizeof(req));

            /* Wait and drain */
            int j;
            for (j = 0; j < 1000; j++) {
                char rbuf[512];
                binder_write_read(fd, NULL, 0, rbuf, sizeof(rbuf));
                usleep(100);
            }

            close(fd);
            _exit(0);
        }

        /* Freezer */
        pid_t freezer = fork();
        if (freezer == 0) {
            int fd = open_binder();
            if (fd < 0) _exit(1);

            struct binder_freeze_info info;
            info.pid = target;
            info.timeout_ms = 0;

            int j;
            for (j = 0; j < 500; j++) {
                info.enable = 1;
                ioctl(fd, BINDER_FREEZE, &info);
                info.enable = 0;
                ioctl(fd, BINDER_FREEZE, &info);
            }
            close(fd);
            _exit(0);
        }

        /* Race: kill target while both death and freeze notifications are active */
        usleep(10000 + (rand() % 30000));
        kill(target, SIGKILL);

        waitpid(target, NULL, 0);
        waitpid(watcher, NULL, 0);
        waitpid(freezer, NULL, 0);

        if (i % 10 == 0)
            printf("    %d/%d\n", i, iterations);
    }
    printf("[+] Test 5 complete (%d iterations survived)\n\n", i);
}

/* ------------------------------------------------------------------- */

static void sigint_handler(int sig)
{
    (void)sig;
    g_running = 0;
    printf("\n[!] Stopping...\n");
}

int main(int argc, char **argv)
{
    signal(SIGINT, sigint_handler);
    signal(SIGCHLD, SIG_DFL);
    srand(getpid());

    printf("=== Binder Freeze Race Condition Tester ===\n");
    printf("PANIC_ON_OOPS=y — device will reboot on kernel fault\n");
    printf("KASAN HW_TAGS=y — UAF detected probabilistically via MTE\n\n");

    int fd = open_binder();
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", BINDER_DEV, strerror(errno));
        return 1;
    }
    close(fd);
    printf("[+] Binder accessible\n\n");

    int test = 0;
    int iters = 100;

    if (argc > 1)
        test = atoi(argv[1]);
    if (argc > 2)
        iters = atoi(argv[2]);

    if (test == 0 || test == 1)
        test_freeze_death_race(iters);

    if (test == 0 || test == 2)
        test_update_txn_race(iters > 20 ? 20 : iters);

    if (test == 0 || test == 3)
        test_freeze_notification_race(iters);

    if (test == 0 || test == 4)
        test_dbitmap_stress(iters);

    if (test == 0 || test == 5)
        test_death_freeze_combined(iters);

    printf("=== All tests complete ===\n");
    printf("Device survived. Check kernel logs for warnings.\n");

    return 0;
}
