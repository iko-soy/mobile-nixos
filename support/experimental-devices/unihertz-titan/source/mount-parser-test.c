/* SPDX-License-Identifier: MIT
 * Host-only parser fixtures for the default six-mount source guard. Linux 4.14
 * numbers the initramfs rootfs mount 0, which disposable 6.18 VMs never
 * produce, so these synthetic inventories cover it. No storage is opened.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int titan_source_test_mount_inventory(const char *path, const char **reason);

#define DEV "rw,nosuid,noexec - devtmpfs devtmpfs rw,size=1024k,mode=755\n"
#define PROC "ro,nosuid,nodev,noexec - proc proc ro\n"
#define SYS "ro,nosuid,nodev,noexec - sysfs sysfs ro\n"
#define RAM "rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k,mode=700\n"
#define CHILDREN(parent) \
    "21 " parent " 0:6 / /dev " DEV "22 " parent " 0:4 / /proc " PROC \
    "23 " parent " 0:17 / /sys " SYS "24 " parent " 0:18 / /run " RAM \
    "25 " parent " 0:19 / /tmp " RAM

static const struct {
    const char *name, *inventory;
    int expected;
} cases[] = {
    { "rootfs-id-0-as-on-4.14", "0 0 0:1 / / rw - rootfs rootfs rw\n" CHILDREN("0"), 0 },
    { "numbered-from-1", "1 1 0:1 / / rw - rootfs rootfs rw\n" CHILDREN("1"), 0 },
    { "root-with-hidden-parent", "2 1 0:1 / / rw - rootfs rootfs rw\n" CHILDREN("2"), 0 },
    { "propagation-tag-accepted", "0 0 0:1 / / rw shared:1 - rootfs rootfs rw\n" CHILDREN("0"), 0 },
    { "duplicate-id", "21 21 0:1 / / rw - rootfs rootfs rw\n" CHILDREN("21"), 1 },
    { "child-not-on-root", "0 0 0:1 / / rw - rootfs rootfs rw\n" CHILDREN("24"), 1 },
    { "missing-mount", "0 0 0:1 / / rw - rootfs rootfs rw\n"
      "21 0 0:6 / /dev " DEV "22 0 0:4 / /proc " PROC, 1 },
    { "storage-device", "0 0 179:36 / / rw - ext4 /dev/mmcblk0p36 rw\n" CHILDREN("0"), 1 },
};

int main(void)
{
    const char *base = getenv("TMPDIR");
    char directory[4096], path[4200];
    int failures = 0;
    if (snprintf(directory, sizeof(directory), "%s/titan-source-parser-XXXXXX", base ? base : "/tmp")
            >= (int)sizeof(directory) || mkdtemp(directory) == NULL) {
        fputs("cannot create fixture directory\n", stderr);
        return 2;
    }
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        snprintf(path, sizeof(path), "%s/case-%zu", directory, index);
        FILE *stream = fopen(path, "w");
        if (stream == NULL || fputs(cases[index].inventory, stream) == EOF || fclose(stream) != 0) {
            fputs("cannot write fixture\n", stderr);
            return 2;
        }
        const char *reason = NULL;
        int result = titan_source_test_mount_inventory(path, &reason) != 0;
        int passed = result == cases[index].expected;
        printf("%s %s result=%d reason=%s\n", passed ? "PASS" : "FAIL", cases[index].name,
               result, reason ? reason : "none");
        failures += !passed;
        unlink(path);
    }
    rmdir(directory);
    return failures != 0;
}
