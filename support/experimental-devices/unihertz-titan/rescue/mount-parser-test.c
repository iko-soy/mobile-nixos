/* SPDX-License-Identifier: MIT
 * Host-only parser fixtures for the USB mount policy. Linux 4.14 numbers the
 * initramfs rootfs mount 0, which disposable 6.18 VMs never produce, so these
 * synthetic inventories cover that numbering. No mount is performed here.
 */
#define _POSIX_C_SOURCE 200809L
#include "mount-policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEV "rw,nosuid,noexec - devtmpfs devtmpfs rw,size=1024k,mode=755\n"
#define PROC "ro,nosuid,nodev,noexec - proc proc ro\n"
#define SYS "ro,nosuid,nodev,noexec - sysfs sysfs ro\n"
#define RAM "rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k,mode=700\n"
#define CONFIGFS "ro,nosuid,nodev,noexec - configfs configfs ro\n"

/* Rootfs is mount 0 and its own parent; every child's parent is 0. */
#define BASE_414 \
    "0 0 0:1 / / rw - rootfs rootfs rw\n" \
    "21 0 0:6 / /dev " DEV \
    "22 0 0:4 / /proc " PROC \
    "23 0 0:17 / /sys " SYS \
    "24 0 0:18 / /run " RAM \
    "25 0 0:19 / /tmp " RAM
#define SEALED_414 BASE_414 "26 24 0:20 / /run/usb-config " CONFIGFS

static const struct {
    const char *name;
    enum titan_mount_phase phase;
    const char *inventory;
    int expected;
} cases[] = {
    { "baseline-4.14-rootfs-id-0", TITAN_MOUNTS_BASELINE_6, BASE_414, 0 },
    { "sealed-4.14-rootfs-id-0", TITAN_MOUNTS_USB_SEALED_7, SEALED_414, 0 },
    { "baseline-numbered-from-1", TITAN_MOUNTS_BASELINE_6,
      "1 1 0:1 / / rw - rootfs rootfs rw\n"
      "2 1 0:6 / /dev " DEV "3 1 0:4 / /proc " PROC "4 1 0:17 / /sys " SYS
      "5 1 0:18 / /run " RAM "6 1 0:19 / /tmp " RAM, 0 },
    { "baseline-root-with-hidden-parent", TITAN_MOUNTS_BASELINE_6,
      "2 1 0:1 / / rw - rootfs rootfs rw\n"
      "3 2 0:6 / /dev " DEV "4 2 0:4 / /proc " PROC "5 2 0:17 / /sys " SYS
      "6 2 0:18 / /run " RAM "7 2 0:19 / /tmp " RAM, 0 },
    { "duplicate-id-0", TITAN_MOUNTS_BASELINE_6,
      "0 0 0:1 / / rw - rootfs rootfs rw\n"
      "0 0 0:6 / /dev " DEV "22 0 0:4 / /proc " PROC "23 0 0:17 / /sys " SYS
      "24 0 0:18 / /run " RAM "25 0 0:19 / /tmp " RAM, 1 },
    { "child-not-on-root", TITAN_MOUNTS_BASELINE_6,
      "0 0 0:1 / / rw - rootfs rootfs rw\n"
      "21 0 0:6 / /dev " DEV "22 0 0:4 / /proc " PROC "23 0 0:17 / /sys " SYS
      "24 0 0:18 / /run " RAM "25 24 0:19 / /tmp " RAM, 1 },
    { "configfs-not-on-run", TITAN_MOUNTS_USB_SEALED_7, BASE_414 "26 0 0:20 / /run/usb-config " CONFIGFS, 1 },
    { "missing-tmp", TITAN_MOUNTS_BASELINE_6,
      "0 0 0:1 / / rw - rootfs rootfs rw\n"
      "21 0 0:6 / /dev " DEV "22 0 0:4 / /proc " PROC "23 0 0:17 / /sys " SYS
      "24 0 0:18 / /run " RAM, 1 },
    /* Six records with an expected path and type, but a storage device. */
    { "storage-backed-tmp", TITAN_MOUNTS_BASELINE_6,
      "0 0 0:1 / / rw - rootfs rootfs rw\n"
      "21 0 0:6 / /dev " DEV "22 0 0:4 / /proc " PROC "23 0 0:17 / /sys " SYS
      "24 0 0:18 / /run " RAM "25 0 179:36 / /tmp " RAM, 1 },
    { "seventh-mount-in-baseline", TITAN_MOUNTS_BASELINE_6, SEALED_414, 1 },
};

int main(void)
{
    const char *base = getenv("TMPDIR");
    char directory[4096], path[4200];
    int failures = 0;
    if (snprintf(directory, sizeof(directory), "%s/titan-mount-parser-XXXXXX", base ? base : "/tmp")
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
        titan_mount_policy_test_path(path);
        int result = titan_mount_inventory(cases[index].phase, &reason);
        int passed = result == cases[index].expected;
        printf("%s %s result=%d reason=%s\n", passed ? "PASS" : "FAIL", cases[index].name,
               result, reason ? reason : "none");
        failures += !passed;
        unlink(path);
    }
    rmdir(directory);
    return failures != 0;
}
