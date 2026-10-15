/* SPDX-License-Identifier: MIT
 * Fixed RAM/virtual mount policy for the explicit USB build profile.
 * No mount, remount, namespace change or storage operation is performed here.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifndef TITAN_USB_MOUNT_PROFILE
#error Shared USB mount policy requires its explicit build profile
#endif
#include "mount-policy.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int fail(const char **reason, const char *message)
{
    if (reason != NULL)
        *reason = message;
    return 1;
}

static int decimal(const char *text, uint64_t maximum, uint64_t *value)
{
    uint64_t result = 0;
    if (*text == '\0')
        return 0;
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9')
            return 0;
        unsigned digit = (unsigned)(*text - '0');
        if (result > maximum / 10 ||
            (result == maximum / 10 && digit > maximum % 10))
            return 0;
        result = result * 10 + digit;
    }
    *value = result;
    return 1;
}

static int virtual_device(char *text)
{
    char *colon = strchr(text, ':');
    uint64_t device_major, device_minor;
    if (colon == NULL || strchr(colon + 1, ':') != NULL)
        return 0;
    *colon = '\0';
    if (!decimal(text, UINT_MAX, &device_major) || device_major != 0 ||
        !decimal(colon + 1, UINT_MAX, &device_minor))
        return 0;
    dev_t device = makedev((unsigned)device_major, (unsigned)device_minor);
    return major(device) == device_major && minor(device) == device_minor;
}

#ifdef TITAN_MOUNT_POLICY_PARSER_TEST
/* Host parser fixtures only; production builds read this process's table. */
static const char *inventory_path = "/proc/self/mountinfo";
void titan_mount_policy_test_path(const char *path)
{
    inventory_path = path;
}
#define TITAN_MOUNTINFO_PATH inventory_path
#else
#define TITAN_MOUNTINFO_PATH "/proc/self/mountinfo"
#endif

static int read_inventory(char *buffer, size_t capacity)
{
    int fd = open(TITAN_MOUNTINFO_PATH, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 1;
    struct stat metadata;
    int invalid = fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode);
    size_t used = 0;
    while (!invalid) {
        char excess;
        size_t available = capacity - 1 - used;
        ssize_t count = read(fd, available ? buffer + used : &excess, available ? available : 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 || (count > 0 && available == 0)) {
            invalid = 1;
            break;
        }
        if (count == 0)
            break;
        for (ssize_t index = 0; index < count; ++index) {
            unsigned char byte = (unsigned char)buffer[used + (size_t)index];
            if (byte != '\n' && (byte < 0x20 || byte > 0x7e))
                invalid = 1;
        }
        used += (size_t)count;
    }
    if (close(fd) != 0)
        invalid = 1;
    if (invalid || used == 0)
        return 1;
    buffer[used] = '\0';
    return 0;
}

static int expected_mount(const char *path, const char *type)
{
    if (strcmp(path, "/") == 0 && (strcmp(type, "rootfs") == 0 ||
        strcmp(type, "ramfs") == 0 || strcmp(type, "tmpfs") == 0)) return 0;
    if (strcmp(path, "/dev") == 0 && strcmp(type, "devtmpfs") == 0) return 1;
    if (strcmp(path, "/proc") == 0 && strcmp(type, "proc") == 0) return 2;
    if (strcmp(path, "/sys") == 0 && strcmp(type, "sysfs") == 0) return 3;
    if (strcmp(path, "/run") == 0 && strcmp(type, "tmpfs") == 0) return 4;
    if (strcmp(path, "/tmp") == 0 && strcmp(type, "tmpfs") == 0) return 5;
    if (strcmp(path, TITAN_USB_CONFIGFS_PATH) == 0 && strcmp(type, "configfs") == 0) return 6;
    return -1;
}

enum { READ_ONLY = 1, READ_WRITE = 2, NO_SUID = 4, NO_DEV = 8, NO_EXEC = 16 };

static int option_flags(char *options, unsigned *flags)
{
    size_t length = strlen(options);
    *flags = 0;
    if (length == 0 || options[0] == ',' || options[length - 1] == ',' || strstr(options, ",,") != NULL)
        return 1;
    unsigned count = 0;
    char *state = NULL;
    for (char *option = strtok_r(options, ",", &state); option != NULL;
         option = strtok_r(NULL, ",", &state)) {
        if (++count > 32)
            return 1;
        unsigned flag = 0;
        if (strcmp(option, "ro") == 0) flag = READ_ONLY;
        else if (strcmp(option, "rw") == 0) flag = READ_WRITE;
        else if (strcmp(option, "nosuid") == 0) flag = NO_SUID;
        else if (strcmp(option, "nodev") == 0) flag = NO_DEV;
        else if (strcmp(option, "noexec") == 0) flag = NO_EXEC;
        if (flag != 0 && (*flags & flag) != 0)
            return 1;
        *flags |= flag;
    }
    return (*flags & (READ_ONLY | READ_WRITE)) != READ_ONLY &&
           (*flags & (READ_ONLY | READ_WRITE)) != READ_WRITE;
}

static int mount_options(char *options, char *super_options, int index)
{
    unsigned flags;
    if (option_flags(options, &flags) != 0)
        return 1;
    if (index == 0)
        return 0;
    unsigned required = NO_SUID | NO_EXEC;
    if (index != 1)
        required |= NO_DEV;
    required |= index == 2 || index == 3 || index == 6 ? READ_ONLY : READ_WRITE;
    if ((flags & required) != required)
        return 1;
    /* A read-only bind remount alone does not seal the configfs superblock. */
    if (index == 6 && (option_flags(super_options, &flags) != 0 ||
                      (flags & (READ_ONLY | READ_WRITE)) != READ_ONLY))
        return 1;
    return 0;
}

int titan_mount_inventory(enum titan_mount_phase phase, const char **reason)
{
    if (phase != TITAN_MOUNTS_BASELINE_6 && phase != TITAN_MOUNTS_USB_SEALED_7)
        return fail(reason, "invalid-mount-policy");
    size_t expected = phase == TITAN_MOUNTS_BASELINE_6 ? 6U : 7U;
    char text[65536];
    uint64_t mount_ids[7] = {0}, parent_ids[7] = {0};
    unsigned seen = 0;
    size_t count = 0;
    if (read_inventory(text, sizeof(text)) != 0)
        return fail(reason, "mount-inventory-unavailable");
    for (char *line = text; *line != '\0'; ) {
        char *end = strchr(line, '\n');
        if (end == NULL || end == line || end - line > 8191 || count == expected)
            return fail(reason, "unexpected-mount");
        *end = '\0';
        char *tokens[10], *state = NULL;
        size_t token_count = 0;
        for (char *token = strtok_r(line, " ", &state); token != NULL;
             token = strtok_r(NULL, " ", &state)) {
            if (token_count == 10)
                return fail(reason, "unexpected-mount");
            tokens[token_count++] = token;
        }
        uint64_t id, parent;
        /* These independently owned initramfs mounts must be private: no
         * shared/master/propagate_from tags in this visible inventory. Mount
         * ID 0 is valid: Linux 4.14 numbers the initramfs rootfs 0. */
        if (token_count != 10 || strcmp(tokens[6], "-") != 0 ||
            !decimal(tokens[0], UINT64_MAX, &id) ||
            !decimal(tokens[1], UINT64_MAX, &parent) ||
            !virtual_device(tokens[2]) || strcmp(tokens[3], "/") != 0)
            return fail(reason, "unexpected-mount");
        int index = expected_mount(tokens[4], tokens[7]);
        if (index < 0 || (size_t)index >= expected || (seen & (1U << index)) != 0 ||
            mount_options(tokens[5], tokens[9], index) != 0)
            return fail(reason, "unexpected-mount");
        for (size_t previous = 0; previous < 7; ++previous)
            if ((seen & (1U << previous)) != 0 && mount_ids[previous] == id)
                return fail(reason, "unexpected-mount");
        mount_ids[index] = id;
        parent_ids[index] = parent;
        seen |= 1U << index;
        ++count;
        line = end + 1;
    }
    if (count != expected || seen != (1U << expected) - 1U)
        return fail(reason, "mount-inventory-incomplete");
    /* The fixed tree: the five virtual mounts sit directly on '/' and
     * configfs sits on /run. The root's own parent number is not assumed: it
     * can be itself (4.14 rootfs) or a hidden mount on other kernels. */
    for (size_t index = 1; index < 6; ++index)
        if (parent_ids[index] != mount_ids[0])
            return fail(reason, "unexpected-mount");
    if (phase == TITAN_MOUNTS_USB_SEALED_7 && parent_ids[6] != mount_ids[4])
        return fail(reason, "unexpected-mount");
    return 0;
}
