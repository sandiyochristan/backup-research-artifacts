/*
 * binder_selinux_check.c — Check which binder ioctls are permitted
 * from the current SELinux context.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/android/binder.h>

static const char *binder_devs[] = {
    "/dev/binder",
    "/dev/hwbinder",
    "/dev/vndbinder",
    NULL
};

static void check_device(const char *dev)
{
    printf("\n--- %s ---\n", dev);

    int fd = open(dev, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("  open: %s\n", strerror(errno));
        return;
    }
    printf("  open: OK (fd=%d)\n", fd);

    void *m = mmap(NULL, 1024*1024, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED) {
        printf("  mmap: %s\n", strerror(errno));
    } else {
        printf("  mmap: OK\n");
    }

    /* Check BINDER_VERSION */
    struct binder_version ver;
    int ret = ioctl(fd, BINDER_VERSION, &ver);
    if (ret < 0)
        printf("  BINDER_VERSION: %s\n", strerror(errno));
    else
        printf("  BINDER_VERSION: OK (protocol=%d)\n",
               ver.protocol_version);

    /* Check BINDER_SET_CONTEXT_MGR */
    ret = ioctl(fd, BINDER_SET_CONTEXT_MGR, 0);
    if (ret < 0)
        printf("  BINDER_SET_CONTEXT_MGR: %s\n", strerror(errno));
    else
        printf("  BINDER_SET_CONTEXT_MGR: OK\n");

    /* Check BINDER_FREEZE (on self) */
    struct binder_freeze_info info;
    info.pid = getpid();
    info.enable = 0;
    info.timeout_ms = 0;
    ret = ioctl(fd, BINDER_FREEZE, &info);
    if (ret < 0)
        printf("  BINDER_FREEZE: %s\n", strerror(errno));
    else
        printf("  BINDER_FREEZE: OK\n");

    /* Check basic BINDER_WRITE_READ */
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0)
        printf("  BINDER_WRITE_READ: %s\n", strerror(errno));
    else
        printf("  BINDER_WRITE_READ: OK\n");

    close(fd);
}

int main(void)
{
    /* Show SELinux context */
    FILE *f = fopen("/proc/self/attr/current", "r");
    if (f) {
        char ctx[256];
        if (fgets(ctx, sizeof(ctx), f))
            printf("SELinux context: %s\n", ctx);
        fclose(f);
    }

    printf("PID: %d, UID: %d\n", getpid(), getuid());

    int i;
    for (i = 0; binder_devs[i]; i++)
        check_device(binder_devs[i]);

    return 0;
}
