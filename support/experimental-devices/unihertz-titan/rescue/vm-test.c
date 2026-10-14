/* SPDX-License-Identifier: MIT
 * VM-only callback: never link this file into the production rescue init.
 */
#define _GNU_SOURCE
#ifndef TITAN_RESCUE_VM_TEST
#error VM test callback requires TITAN_RESCUE_VM_TEST
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *reason) {
    printf("TITAN_RESCUE_VM_FAIL %s\n", reason);
    return 1;
}

int titan_rescue_vm_test(void) {
    static const char sentinel[] = "TITAN_RESCUE_VM_SENTINEL_v1\n";
    char data[sizeof(sentinel) - 1], line[8192], point[4096], type[32];
    struct stat st;
    unsigned mount_count = 0;
    int read_only = 0, fd;
    FILE *mounts = fopen("/proc/self/mountinfo", "r");
    if (!mounts)
        return fail("mountinfo-unavailable");
    while (fgets(line, sizeof(line), mounts)) {
        char *separator = strstr(line, " - ");
        if (!separator || !strchr(line, '\n')
                || sscanf(line, "%*u %*u %*u:%*u %*s %4095s", point) != 1
                || sscanf(separator + 3, "%31s", type) != 1) {
            fclose(mounts);
            return fail("mountinfo-malformed");
        }
        if (!(strcmp(point, "/") == 0
                    && (strcmp(type, "rootfs") == 0 || strcmp(type, "ramfs") == 0
                        || strcmp(type, "tmpfs") == 0))
                && !(strcmp(point, "/dev") == 0 && strcmp(type, "devtmpfs") == 0)
                && !(strcmp(point, "/proc") == 0 && strcmp(type, "proc") == 0)
                && !(strcmp(point, "/sys") == 0 && strcmp(type, "sysfs") == 0)
                && !((strcmp(point, "/run") == 0 || strcmp(point, "/tmp") == 0)
                    && strcmp(type, "tmpfs") == 0)) {
            fclose(mounts);
            return fail("unexpected-mount");
        }
        ++mount_count;
    }
    if (ferror(mounts) || mount_count != 6) {
        fclose(mounts);
        return fail("mount-set-incomplete");
    }
    fclose(mounts);
    fd = open("/dev/vda", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return fail("sentinel-device-unavailable");
    if (fstat(fd, &st) < 0 || !S_ISBLK(st.st_mode)
            || ioctl(fd, BLKROGET, &read_only) < 0 || read_only != 1) {
        close(fd);
        return fail("sentinel-device-not-read-only");
    }
    if (read(fd, data, sizeof(data)) != (ssize_t)sizeof(data)
            || memcmp(data, sentinel, sizeof(data)) != 0) {
        close(fd);
        return fail("sentinel-bytes-mismatch");
    }
    close(fd);
    errno = 0;
    fd = open("/dev/vda", O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd >= 0) {
        /* Only the VM's generated sentinel disk is ever targeted. Some kernels
         * allow the open and reject the write rather than rejecting the open. */
        const char different_byte = 'X';
        ssize_t written = pwrite(fd, &different_byte, 1, 0);
        int error = errno;
        close(fd);
        if (written != -1)
            return fail("read-only-block-write-succeeded");
        errno = error;
    }
    if (errno != EROFS && errno != EACCES && errno != EPERM)
        return fail("write-refused-for-unexpected-reason");
    puts("TITAN_RESCUE_VM_PASS");
    /* The VM harness also requires QEMU to exit cleanly after this marker.
     * No sync() is needed: this test has made no block-device writes. */
    if (reboot(RB_POWER_OFF) < 0)
        return fail("vm-poweroff-failed");
    return fail("vm-poweroff-returned");
}
