/* SPDX-License-Identifier: MIT
 * Synthetic VM callback only. Never link this into the production rescue init.
 */
#define _GNU_SOURCE
#if !defined(TITAN_SOURCE_VM_TEST) || !defined(TITAN_RESCUE_VM_TEST)
#error Source VM callback requires both explicit VM test macros
#endif
#include "guard.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

struct test_case {
    const char *name;
    const char *expected;
};

static const struct test_case cases[] = {
    { "valid", NULL },
    { "wrong-label", "partition-identity-mismatch" },
    { "wrong-start", "partition-geometry-mismatch" },
    { "wrong-size", "partition-geometry-mismatch" },
    { "unprotected", "block-not-read-only" },
    { "extra-mount", "unexpected-mount" },
    { "symlink-node", "block-node-mismatch" },
    { "claim-conflict", "partition-claim-conflict" },
    { "recheck-ro-clear", "block-not-read-only" },
    { "recheck-node-change", "block-node-mismatch" },
};

static int fail(const char *name, const char *reason)
{
    printf("TITAN_SOURCE_VM_FAIL %s %s\n", name, reason);
    return 1;
}

static const struct test_case *selected_case(void)
{
    char command[4096];
    FILE *stream = fopen("/proc/cmdline", "r");
    if (stream == NULL)
        return NULL;
    size_t length = fread(command, 1, sizeof(command), stream);
    int invalid = ferror(stream) || length == sizeof(command);
    fclose(stream);
    if (invalid || memchr(command, '\0', length) != NULL)
        return NULL;
    command[length] = '\0';
    const struct test_case *selected = NULL;
    char *save = NULL;
    for (char *word = strtok_r(command, " \t\r\n", &save); word != NULL;
         word = strtok_r(NULL, " \t\r\n", &save)) {
        static const char prefix[] = "titan.source_case=";
        if (strncmp(word, prefix, sizeof(prefix) - 1) != 0)
            continue;
        if (selected != NULL)
            return NULL;
        for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
            if (strcmp(word + sizeof(prefix) - 1, cases[index].name) == 0) {
                selected = &cases[index];
                break;
            }
        }
        if (selected == NULL)
            return NULL;
    }
    return selected;
}

static int fixture_open(const char *path, int exclusive)
{
    return open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                     (exclusive ? O_EXCL : 0));
}

static int set_fixture_writable(void)
{
    static const char *const paths[] = { "/dev/vda", "/dev/vda1" };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        struct stat metadata;
        int descriptor = fixture_open(paths[index], 0), value = 0;
        if (descriptor < 0)
            return -1;
        int invalid = fstat(descriptor, &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
                      ioctl(descriptor, BLKROSET, &value) != 0 ||
                      ioctl(descriptor, BLKROGET, &value) != 0 || value != 0;
        close(descriptor);
        if (invalid)
            return -1;
    }
    return 0;
}

static int replace_fixture_node(void)
{
    struct stat metadata;
    if (lstat("/dev/vda1", &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
        unlink("/dev/vda1") != 0 || symlink("/dev/vda", "/dev/vda1") != 0)
        return -1;
    return 0;
}

static int probe_exclusive_busy(const char *path)
{
    errno = 0;
    int descriptor = fixture_open(path, 1), error = errno;
    if (descriptor >= 0) {
        close(descriptor);
        return -1;
    }
    return error == EBUSY ? 0 : -1;
}

static int probe_claims_held(void)
{
    static const char *const paths[] = { "/dev/vda1", "/dev/vda" };
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        if (probe_exclusive_busy(paths[index]) != 0)
            return -1;
        int descriptor = fixture_open(paths[index], 0);
        if (descriptor < 0)
            return -1;
        close(descriptor);
    }
    return 0;
}

static int probe_released(const char *path)
{
    int descriptor = fixture_open(path, 1);
    if (descriptor < 0)
        return -1;
    close(descriptor);
    return 0;
}

int titan_rescue_vm_test(void)
{
    const struct test_case *test = selected_case();
    if (test == NULL)
        return fail("unknown", "missing-or-invalid-case");
    struct titan_source source = TITAN_SOURCE_INITIALIZER;
    const char *reason = NULL;
    int conflict = -1, result;
    if (strcmp(test->name, "unprotected") == 0 && set_fixture_writable() != 0)
        return fail(test->name, "fixture-clear-read-only-failed");
    if (strcmp(test->name, "extra-mount") == 0) {
        if (mkdir("/run/extra", 0700) != 0 ||
            mount("tmpfs", "/run/extra", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  "size=1m,mode=0700") != 0)
            return fail(test->name, "fixture-extra-mount-failed");
    }
    if (strcmp(test->name, "symlink-node") == 0) {
        if (replace_fixture_node() != 0)
            return fail(test->name, "fixture-node-replacement-failed");
    }
    if (strcmp(test->name, "claim-conflict") == 0) {
        conflict = fixture_open("/dev/vda1", 1);
        if (conflict < 0)
            return fail(test->name, "fixture-exclusive-claim-failed");
    }

    result = titan_source_open(&source, &reason);
    if (strcmp(test->name, "valid") == 0 || strcmp(test->name, "recheck-ro-clear") == 0 ||
        strcmp(test->name, "recheck-node-change") == 0) {
        if (result != 0) {
            printf("TITAN_SOURCE_VM_OBSERVED %s\n", reason == NULL ? "missing-reason" : reason);
            titan_source_close(&source);
            return fail(test->name, "initial-source-open-failed");
        }
        if (titan_source_recheck(&source, &reason) != 0) {
            printf("TITAN_SOURCE_VM_OBSERVED %s\n", reason == NULL ? "missing-reason" : reason);
            titan_source_close(&source);
            return fail(test->name, "initial-source-recheck-failed");
        }
        if (probe_claims_held() != 0) {
            titan_source_close(&source);
            return fail(test->name, "exclusive-claim-probe-failed");
        }
        if (strcmp(test->name, "recheck-ro-clear") == 0) {
            if (set_fixture_writable() != 0) {
                titan_source_close(&source);
                return fail(test->name, "fixture-clear-read-only-failed");
            }
            reason = NULL;
            result = titan_source_recheck(&source, &reason);
        } else if (strcmp(test->name, "recheck-node-change") == 0) {
            if (replace_fixture_node() != 0) {
                titan_source_close(&source);
                return fail(test->name, "fixture-node-replacement-failed");
            }
            reason = NULL;
            result = titan_source_recheck(&source, &reason);
        }
        if (result != 0 && probe_exclusive_busy("/dev/vda") != 0) {
            titan_source_close(&source);
            return fail(test->name, "failed-recheck-dropped-held-claim");
        }
    }
    titan_source_close(&source);
    titan_source_close(&source); /* Closing an already-closed guard is harmless. */
    if (conflict >= 0)
        close(conflict);
    if (test->expected != NULL) {
        if (result == 0)
            return fail(test->name, "unexpected-source-acceptance");
        if (reason == NULL || strcmp(reason, test->expected) != 0) {
            printf("TITAN_SOURCE_VM_OBSERVED %s\n", reason == NULL ? "missing-reason" : reason);
            return fail(test->name, "unexpected-rejection-reason");
        }
        printf("TITAN_SOURCE_VM_EXPECTED %s %s\n", test->name, reason);
    }
    if (probe_released("/dev/vda") != 0 ||
        (strcmp(test->name, "valid") == 0 && probe_released("/dev/vda1") != 0))
        return fail(test->name, "exclusive-claim-not-released");
    printf("TITAN_SOURCE_VM_PASS %s\n", test->name);
    if (fflush(stdout) != 0 || reboot(RB_POWER_OFF) < 0)
        return fail(test->name, "vm-poweroff-failed");
    return fail(test->name, "vm-poweroff-returned");
}
