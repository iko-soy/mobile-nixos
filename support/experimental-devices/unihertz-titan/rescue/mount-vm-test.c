/* SPDX-License-Identifier: MIT
 * Disposable VM mount-policy callback. No gadget, acquisition or block writes.
 */
#define _GNU_SOURCE
#if !defined(TITAN_RESCUE_VM_TEST) || !defined(TITAN_SOURCE_VM_TEST) || \
    !defined(TITAN_USB_MOUNT_PROFILE) || !defined(TITAN_MOUNT_VM_TEST)
#error Mount callback requires all explicit VM and USB mount-profile macros
#endif
#include "guard.h"
#include "mount-policy.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#define WRONG_PATH "/run/usb-wrong"
#define ALIAS_PATH "/run/usb-alias"
#define FIXTURE_CONFIGFS_MAGIC 0x62656570

struct test_case { const char *name, *expected; };
static const struct test_case cases[] = {
    { "sealed", NULL },
    { "missing-configfs", "mount-inventory-incomplete" },
    { "writable-configfs", "unexpected-mount" },
    { "wrong-path", "unexpected-mount" },
    { "extra-alias", "unexpected-mount" },
    { "mount-only-readonly", "unexpected-mount" },
    { "recheck-writable", "unexpected-mount" }
};

static const struct test_case *selected_case(void)
{
    char text[4096];
    FILE *stream = fopen("/proc/cmdline", "r");
    if (stream == NULL)
        return NULL;
    size_t count = fread(text, 1, sizeof(text), stream);
    int invalid = ferror(stream) || count == sizeof(text);
    if (fclose(stream) != 0)
        invalid = 1;
    if (invalid || memchr(text, '\0', count) != NULL)
        return NULL;
    text[count] = '\0';
    const struct test_case *selected = NULL;
    char *state = NULL;
    for (char *word = strtok_r(text, " \t\r\n", &state); word != NULL;
         word = strtok_r(NULL, " \t\r\n", &state)) {
        static const char prefix[] = "titan_mount_test=";
        if (strncmp(word, prefix, sizeof(prefix) - 1) != 0)
            continue;
        if (selected != NULL)
            return NULL;
        for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index)
            if (strcmp(word + sizeof(prefix) - 1, cases[index].name) == 0)
                selected = &cases[index];
        if (selected == NULL)
            return NULL;
    }
    return selected;
}

static int elapsed_ok(const struct timespec *start)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return now.tv_sec - start->tv_sec < 30;
}

static int fixture_open(const char *path, int exclusive)
{
    return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                     (exclusive ? O_EXCL : 0));
}

static int claim_probe(int held)
{
    static const char *const paths[] = { "/dev/vda", "/dev/vda1" };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        errno = 0;
        int descriptor = fixture_open(paths[index], 1), error = errno;
        if (held) {
            if (descriptor >= 0) {
                close(descriptor);
                return -1;
            }
            if (error != EBUSY)
                return -1;
        } else if (descriptor < 0 || close(descriptor) != 0) {
            return -1;
        }
        descriptor = fixture_open(paths[index], 0);
        struct stat metadata;
        int readonly = 0;
        if (descriptor < 0)
            return -1;
        int invalid = fstat(descriptor, &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
                      ioctl(descriptor, BLKROGET, &readonly) != 0 || readonly != 1;
        if (close(descriptor) != 0)
            invalid = 1;
        if (invalid)
            return -1;
    }
    return 0;
}

static int has_option(const char *text, const char *option)
{
    size_t length = strlen(option);
    for (const char *start = text; start != NULL; ) {
        const char *end = strchr(start, ',');
        size_t amount = end == NULL ? strlen(start) : (size_t)(end - start);
        if (amount == length && memcmp(start, option, length) == 0)
            return 1;
        start = end == NULL ? NULL : end + 1;
    }
    return 0;
}

/* Check the actual mount/superblock split so the bind-remount negative cannot
 * pass merely because its fixture failed to establish the intended state. */
static int configfs_flags(const char *path, int mount_ro, int super_ro)
{
    FILE *stream = fopen("/proc/self/mountinfo", "r");
    if (stream == NULL)
        return -1;
    char line[8192];
    int matches = 0, invalid = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *end = strchr(line, '\n');
        if (end == NULL) { invalid = 1; break; }
        *end = '\0';
        char *tokens[10], *state = NULL;
        size_t count = 0;
        for (char *token = strtok_r(line, " ", &state); token != NULL;
             token = strtok_r(NULL, " ", &state)) {
            if (count == 10) { invalid = 1; break; }
            tokens[count++] = token;
        }
        if (invalid || count != 10 || strcmp(tokens[6], "-") != 0) { invalid = 1; break; }
        if (strcmp(tokens[4], path) != 0)
            continue;
        if (++matches != 1 || strcmp(tokens[7], "configfs") != 0 ||
            !has_option(tokens[5], mount_ro ? "ro" : "rw") ||
            has_option(tokens[5], mount_ro ? "rw" : "ro") ||
            !has_option(tokens[9], super_ro ? "ro" : "rw") ||
            has_option(tokens[9], super_ro ? "rw" : "ro")) { invalid = 1; break; }
    }
    if (ferror(stream))
        invalid = 1;
    if (fclose(stream) != 0)
        invalid = 1;
    return !invalid && matches == 1 ? 0 : -1;
}

static int cleanup(struct titan_source *source, const char *path, int mounted,
                   int directory, int alias_mounted, int alias_directory)
{
    titan_source_close(source);
    if (alias_mounted && umount(ALIAS_PATH) != 0)
        return -1;
    if (alias_directory && rmdir(ALIAS_PATH) != 0)
        return -1;
    if (mounted && umount(path) != 0)
        return -1;
    if (directory && rmdir(path) != 0)
        return -1;
    return titan_mount_inventory(TITAN_MOUNTS_BASELINE_6, NULL) == 0 && claim_probe(0) == 0 ? 0 : -1;
}

int titan_rescue_vm_test(void)
{
    const struct test_case *test = selected_case();
    struct titan_source source = TITAN_SOURCE_INITIALIZER;
    const unsigned long restricted = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    int directory = 0, mounted = 0, alias_directory = 0, alias_mounted = 0;
    const char *path = TITAN_USB_CONFIGFS_PATH, *failure = "initial-baseline", *reason = NULL;
    struct timespec start;
    struct utsname kernel;
    if (test == NULL || getpid() != 1) {
        puts("TITAN_MOUNT_VM_FAIL missing-case-or-not-pid-one");
        return 1;
    }
    printf("TITAN_MOUNT_VM_START %s\n", test->name);
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0 || uname(&kernel) != 0)
        goto failed;
    printf("TITAN_MOUNT_VM_KERNEL %s\n", kernel.release);
    if (titan_mount_inventory(TITAN_MOUNTS_BASELINE_6, &reason) != 0 || claim_probe(0) != 0)
        goto failed;
    if (strcmp(test->name, "wrong-path") == 0)
        path = WRONG_PATH;
    if (strcmp(test->name, "missing-configfs") != 0) {
        failure = "fixture-configfs-mount";
        if (mkdir(path, 0700) != 0)
            goto failed;
        directory = 1;
        if (mount("configfs", path, "configfs", restricted, NULL) != 0)
            goto failed;
        mounted = 1;
        struct statfs filesystem;
        if (statfs(path, &filesystem) != 0 || filesystem.f_type != FIXTURE_CONFIGFS_MAGIC ||
            configfs_flags(path, 0, 0) != 0)
            goto failed;
        if (strcmp(test->name, "mount-only-readonly") == 0) {
            failure = "fixture-mount-only-readonly";
            if (mount(NULL, path, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY | restricted, NULL) != 0 ||
                configfs_flags(path, 1, 0) != 0)
                goto failed;
        } else if (strcmp(test->name, "writable-configfs") != 0) {
            failure = "fixture-superblock-seal";
            if (mount("configfs", path, "configfs", MS_REMOUNT | MS_RDONLY | restricted, NULL) != 0 ||
                configfs_flags(path, 1, 1) != 0)
                goto failed;
        }
        if (strcmp(test->name, "extra-alias") == 0) {
            failure = "fixture-extra-alias";
            if (mkdir(ALIAS_PATH, 0700) != 0)
                goto failed;
            alias_directory = 1;
            if (mount(path, ALIAS_PATH, NULL, MS_BIND, NULL) != 0)
                goto failed;
            alias_mounted = 1;
            if (configfs_flags(ALIAS_PATH, 1, 1) != 0)
                goto failed;
        }
    }

    failure = "source-open-outcome";
    reason = NULL;
    int result = titan_source_open(&source, &reason);
    int initially_valid = strcmp(test->name, "sealed") == 0 || strcmp(test->name, "recheck-writable") == 0;
    if (initially_valid) {
        if (result != 0 || titan_source_recheck(&source, &reason) != 0 || claim_probe(1) != 0)
            goto failed;
        if (strcmp(test->name, "recheck-writable") == 0) {
            failure = "fixture-unseal-held-source";
            if (mount("configfs", path, "configfs", MS_REMOUNT | restricted, NULL) != 0 ||
                configfs_flags(path, 0, 0) != 0)
                goto failed;
            reason = NULL;
            result = titan_source_recheck(&source, &reason);
            failure = "failed-recheck-dropped-claim";
            if (claim_probe(1) != 0)
                goto failed;
        }
    } else {
        /* Rejection before source opening must not retain even a partial claim. */
        failure = "rejected-open-retained-claim";
        if (source.ready || source.disk_fd >= 0 || source.partition_fd >= 0 || claim_probe(0) != 0)
            goto failed;
    }
    failure = "unexpected-policy-outcome";
    if (test->expected != NULL) {
        if (result == 0 || reason == NULL || strcmp(reason, test->expected) != 0)
            goto failed;
        printf("TITAN_MOUNT_VM_EXPECTED %s %s\n", test->name, reason);
    } else if (result != 0) {
        goto failed;
    }
    failure = "cleanup-or-deadline";
    if (cleanup(&source, path, mounted, directory, alias_mounted, alias_directory) != 0 ||
        !elapsed_ok(&start)) {
        printf("TITAN_MOUNT_VM_FAIL %s\n", failure);
        return 1;
    }
    printf("TITAN_MOUNT_VM_PASS %s\n", test->name);
    if (fflush(stdout) != 0 || reboot(RB_POWER_OFF) < 0) {
        puts("TITAN_MOUNT_VM_FAIL vm-poweroff");
        return 1;
    }
    puts("TITAN_MOUNT_VM_FAIL vm-poweroff-returned");
    return 1;

failed:
    printf("TITAN_MOUNT_VM_FAIL %s\n", failure);
    if (reason != NULL)
        printf("TITAN_MOUNT_VM_OBSERVED %s\n", reason);
    if (cleanup(&source, path, mounted, directory, alias_mounted, alias_directory) != 0)
        puts("TITAN_MOUNT_VM_FAIL cleanup");
    return 1;
}
