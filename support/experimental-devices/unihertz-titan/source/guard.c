/* SPDX-License-Identifier: MIT
 * Fixed-profile, read-only source preflight. No storage contents are read.
 * No ioctl here changes a block flag, partition table, filesystem or mount.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include "guard.h"
#ifdef TITAN_USB_MOUNT_PROFILE
#include "mount-policy.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifdef TITAN_SOURCE_VM_TEST
#define DISK_NAME "vda"
#define PARTITION_NAME "vda1"
#define DISK_BYTES UINT64_C(67108864)
#define PARTITION_SECTORS UINT64_C(32768)
#define PARTITION_START UINT64_C(2048)
#define PARTITION_NUMBER UINT64_C(1)
#else
#define DISK_NAME "mmcblk0"
#define PARTITION_NAME "mmcblk0p36"
#define DISK_BYTES UINT64_C(125074145280)
#define PARTITION_SECTORS UINT64_C(234137536)
#define PARTITION_START UINT64_C(10027008)
#define PARTITION_NUMBER UINT64_C(36)
#endif

#define DISK_PATH "/dev/" DISK_NAME
#define PARTITION_PATH "/dev/" PARTITION_NAME
#define DISK_SYSFS "/sys/class/block/" DISK_NAME
#define PARTITION_SYSFS "/sys/class/block/" PARTITION_NAME
#define SECTOR_BYTES UINT64_C(512)
#define PARTITION_BYTES (PARTITION_SECTORS * SECTOR_BYTES)
#define BLOCK_FLAGS (O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
#define DIRECTORY_FLAGS (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)

_Static_assert(PATH_MAX <= TITAN_SOURCE_PATH_MAX, "canonical path buffer too small");
_Static_assert(DISK_BYTES % SECTOR_BYTES == 0, "nonintegral disk geometry");
_Static_assert(PARTITION_START + PARTITION_SECTORS <= DISK_BYTES / SECTOR_BYTES,
               "partition exceeds fixed disk profile");

static int fail(const char **reason, const char *message)
{
    if (reason != NULL)
        *reason = message;
    return 1;
}

static int same_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_rdev == b->st_rdev && a->st_mode == b->st_mode &&
           a->st_uid == b->st_uid && a->st_gid == b->st_gid;
}

static int decimal(const char *text, uint64_t maximum, uint64_t *value)
{
    uint64_t result = 0;
    if (*text == '\0')
        return 0;
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9')
            return 0;
        unsigned int digit = (unsigned int) (*text - '0');
        if (result > maximum / 10 ||
            (result == maximum / 10 && digit > maximum % 10))
            return 0;
        result = result * 10 + digit;
    }
    *value = result;
    return 1;
}

/* Only fixed proc/sysfs metadata paths reach this helper. The final component
 * must be a regular metadata file, not a symlink. Reject truncation, NULs and
 * unexpected control bytes rather than parsing an ambiguous prefix. */
static int read_text_at(int directory, const char *path, char *buffer, size_t capacity)
{
    int fd = openat(directory, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 1;
    struct stat st;
    int invalid = fstat(fd, &st) != 0 || !S_ISREG(st.st_mode);
    size_t used = 0;
    while (!invalid) {
        char excess;
        size_t available = capacity - 1 - used;
        ssize_t count = read(fd, available ? buffer + used : &excess, available ? available : 1);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            invalid = 1;
            break;
        }
        if (count == 0)
            break;
        if (available == 0) {
            invalid = 1;
            break;
        }
        for (ssize_t i = 0; i < count; ++i) {
            unsigned char c = (unsigned char) buffer[used + (size_t) i];
            if (c != '\n' && c != '\t' && (c < 0x20 || c > 0x7e))
                invalid = 1;
        }
        used += (size_t) count;
    }
    if (close(fd) != 0)
        invalid = 1;
    if (invalid || used == 0)
        return 1;
    buffer[used] = '\0';
    return 0;
}

static int strip_newline(char *text)
{
    size_t length = strlen(text);
    if (length == 0 || text[length - 1] != '\n')
        return 1;
    text[length - 1] = '\0';
    return strchr(text, '\n') != NULL;
}

static int read_number(int directory, const char *name, uint64_t *number)
{
    char text[64];
    return read_text_at(directory, name, text, sizeof(text)) != 0 ||
           strip_newline(text) != 0 || !decimal(text, UINT64_MAX, number);
}

static int parse_device(char *text, dev_t *device)
{
    char *colon = strchr(text, ':');
    uint64_t device_major, device_minor;
    if (colon == NULL || strchr(colon + 1, ':') != NULL)
        return 1;
    *colon = '\0';
    if (!decimal(text, UINT_MAX, &device_major) ||
        !decimal(colon + 1, UINT_MAX, &device_minor))
        return 1;
    *device = makedev((unsigned int) device_major, (unsigned int) device_minor);
    return major(*device) != device_major || minor(*device) != device_minor;
}

static int read_device(int directory, dev_t *device)
{
    char text[64];
    return read_text_at(directory, "dev", text, sizeof(text)) != 0 ||
           strip_newline(text) != 0 || parse_device(text, device) != 0;
}

static int canonical_paths(char *disk, char *partition, const char **reason)
{
    char device[TITAN_SOURCE_PATH_MAX], expected[TITAN_SOURCE_PATH_MAX];
    if (realpath(DISK_SYSFS, disk) == NULL || realpath(PARTITION_SYSFS, partition) == NULL ||
        realpath(DISK_SYSFS "/device", device) == NULL)
        return fail(reason, "sysfs-identity-unavailable");
    int length = snprintf(expected, sizeof(expected), "%s/block/" DISK_NAME, device);
    if (length < 0 || (size_t) length >= sizeof(expected) || strcmp(expected, disk) != 0)
        return fail(reason, "sysfs-parent-mismatch");
    length = snprintf(expected, sizeof(expected), "%s/" PARTITION_NAME, disk);
    if (length < 0 || (size_t) length >= sizeof(expected) || strcmp(expected, partition) != 0)
        return fail(reason, "sysfs-parent-mismatch");
    return 0;
}

static int validate_uevent(int directory, dev_t device, int partition, const char **reason)
{
    char text[8192];
    char *keys[32];
    size_t key_count = 0;
    unsigned int seen = 0;
    const char *failure = partition ? "partition-identity-mismatch" : "disk-identity-mismatch";
    if (read_text_at(directory, "uevent", text, sizeof(text)) != 0)
        return fail(reason, failure);
    char *line = text;
    while (*line != '\0') {
        char *end = strchr(line, '\n');
        if (end == NULL || end == line || end - line > 255 || key_count == 32)
            return fail(reason, failure);
        *end = '\0';
        char *value = strchr(line, '=');
        if (value == NULL || value == line || value - line > 63)
            return fail(reason, failure);
        *value++ = '\0';
        for (char *p = line; *p != '\0'; ++p)
            if (!(*p >= 'A' && *p <= 'Z') && !(*p >= '0' && *p <= '9') && *p != '_')
                return fail(reason, failure);
        for (size_t i = 0; i < key_count; ++i)
            if (strcmp(keys[i], line) == 0)
                return fail(reason, failure);
        keys[key_count++] = line;
        uint64_t number;
        if (strcmp(line, "MAJOR") == 0) {
            if (!decimal(value, UINT_MAX, &number) || number != major(device))
                return fail(reason, failure);
            seen |= 1U;
        } else if (strcmp(line, "MINOR") == 0) {
            if (!decimal(value, UINT_MAX, &number) || number != minor(device))
                return fail(reason, failure);
            seen |= 2U;
        } else if (strcmp(line, "DEVNAME") == 0) {
            if (strcmp(value, partition ? PARTITION_NAME : DISK_NAME) != 0)
                return fail(reason, failure);
            seen |= 4U;
        } else if (strcmp(line, "DEVTYPE") == 0) {
            if (strcmp(value, partition ? "partition" : "disk") != 0)
                return fail(reason, failure);
            seen |= 8U;
        } else if (strcmp(line, "PARTN") == 0) {
            if (!partition || !decimal(value, UINT_MAX, &number) || number != PARTITION_NUMBER)
                return fail(reason, failure);
            seen |= 16U;
        } else if (strcmp(line, "PARTNAME") == 0) {
            if (!partition || strcmp(value, "userdata") != 0)
                return fail(reason, failure);
            seen |= 32U;
        }
        line = end + 1;
    }
    if (seen != (partition ? 63U : 15U))
        return fail(reason, failure);
    return 0;
}

static int empty_directory(int parent, const char *name, int optional, const char **reason)
{
    int fd = openat(parent, name, DIRECTORY_FLAGS);
    if (fd < 0) {
        if (optional && errno == ENOENT)
            return 0;
        return fail(reason, "block-dependency-unavailable");
    }
    DIR *directory = fdopendir(fd);
    if (directory == NULL) {
        (void) close(fd);
        return fail(reason, "block-dependency-unavailable");
    }
    int result = 0;
    unsigned int records = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                result = fail(reason, "block-dependency-unavailable");
            break;
        }
        if (++records > 2 || (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)) {
            result = fail(reason, "block-dependency-present");
            break;
        }
    }
    if (closedir(directory) != 0)
        return fail(reason, "block-dependency-unavailable");
    return result;
}

static int sector_geometry(int parent, int optional, const char **reason)
{
    int queue = openat(parent, "queue", DIRECTORY_FLAGS);
    if (queue < 0) {
        if (optional && errno == ENOENT)
            return 0;
        return fail(reason, "sector-geometry-unavailable");
    }
    uint64_t logical, physical;
    int invalid = read_number(queue, "logical_block_size", &logical) != 0 ||
        read_number(queue, "physical_block_size", &physical) != 0 ||
        logical != SECTOR_BYTES || physical != SECTOR_BYTES;
    if (close(queue) != 0)
        invalid = 1;
    return invalid ? fail(reason, "sector-geometry-mismatch") : 0;
}

static int sysfs_profile(const struct titan_source *source, dev_t *disk_device,
                         dev_t *partition_device, const char **reason)
{
    if (read_device(source->disk_sysfs_fd, disk_device) != 0 ||
        read_device(source->partition_sysfs_fd, partition_device) != 0 ||
        *disk_device == *partition_device)
        return fail(reason, "sysfs-device-invalid");
    if (validate_uevent(source->disk_sysfs_fd, *disk_device, 0, reason) != 0 ||
        validate_uevent(source->partition_sysfs_fd, *partition_device, 1, reason) != 0)
        return 1;
    struct stat unexpected;
    if (fstatat(source->disk_sysfs_fd, "partition", &unexpected, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        return fail(reason, "disk-identity-mismatch");
    uint64_t number, sectors, start, removable;
    if (read_number(source->partition_sysfs_fd, "partition", &number) != 0 ||
        number != PARTITION_NUMBER)
        return fail(reason, "partition-identity-mismatch");
    if (read_number(source->disk_sysfs_fd, "size", &sectors) != 0 ||
        sectors != DISK_BYTES / SECTOR_BYTES ||
        read_number(source->disk_sysfs_fd, "removable", &removable) != 0 || removable != 0)
        return fail(reason, "disk-geometry-mismatch");
    if (read_number(source->partition_sysfs_fd, "size", &sectors) != 0 ||
        sectors != PARTITION_SECTORS ||
        read_number(source->partition_sysfs_fd, "start", &start) != 0 || start != PARTITION_START)
        return fail(reason, "partition-geometry-mismatch");
#ifndef TITAN_SOURCE_VM_TEST
    char type[32];
    if (read_text_at(source->disk_sysfs_fd, "device/type", type, sizeof(type)) != 0 ||
        strcmp(type, "MMC\n") != 0)
        return fail(reason, "mmc-type-mismatch");
#endif
    if (sector_geometry(source->disk_sysfs_fd, 0, reason) != 0 ||
        sector_geometry(source->partition_sysfs_fd, 1, reason) != 0 ||
        empty_directory(source->disk_sysfs_fd, "holders", 0, reason) != 0 ||
        empty_directory(source->disk_sysfs_fd, "slaves", 0, reason) != 0 ||
        empty_directory(source->partition_sysfs_fd, "holders", 0, reason) != 0 ||
        empty_directory(source->partition_sysfs_fd, "slaves", 1, reason) != 0)
        return 1;
    return 0;
}

#ifdef TITAN_USB_MOUNT_PROFILE
static int mount_inventory(const char **reason)
{
    /* USB acquisition never falls back to the pre-setup six-mount inventory. */
    return titan_mount_inventory(TITAN_MOUNTS_USB_SEALED_7, reason);
}
#else
static int expected_mount(const char *path, const char *type)
{
    if (strcmp(path, "/") == 0 && (strcmp(type, "rootfs") == 0 ||
        strcmp(type, "ramfs") == 0 || strcmp(type, "tmpfs") == 0))
        return 0;
    if (strcmp(path, "/dev") == 0 && strcmp(type, "devtmpfs") == 0) return 1;
    if (strcmp(path, "/proc") == 0 && strcmp(type, "proc") == 0) return 2;
    if (strcmp(path, "/sys") == 0 && strcmp(type, "sysfs") == 0) return 3;
    if (strcmp(path, "/run") == 0 && strcmp(type, "tmpfs") == 0) return 4;
    if (strcmp(path, "/tmp") == 0 && strcmp(type, "tmpfs") == 0) return 5;
    return -1;
}

static int mount_options(char *options, int index)
{
    unsigned int flags = 0;
    char *state = NULL;
    size_t original = strlen(options);
    if (original == 0 || options[0] == ',' || options[original - 1] == ',' || strstr(options, ",,") != NULL)
        return 1;
    char *option = strtok_r(options, ",", &state);
    unsigned int count = 0;
    while (option != NULL) {
        if (++count > 32)
            return 1;
        unsigned int flag = 0;
        if (strcmp(option, "ro") == 0) flag = 1U;
        else if (strcmp(option, "rw") == 0) flag = 2U;
        else if (strcmp(option, "nosuid") == 0) flag = 4U;
        else if (strcmp(option, "nodev") == 0) flag = 8U;
        else if (strcmp(option, "noexec") == 0) flag = 16U;
        if (flag != 0 && (flags & flag) != 0)
            return 1;
        flags |= flag;
        option = strtok_r(NULL, ",", &state);
    }
    if ((flags & 3U) != 1U && (flags & 3U) != 2U)
        return 1;
    if (index == 0)
        return 0;
    unsigned int required = index == 1 ? 22U : (index == 2 || index == 3 ? 29U : 30U);
    return (flags & required) != required;
}

#ifdef TITAN_SOURCE_PARSER_TEST
/* Host parser fixtures only; production builds read this process's table. */
static const char *mountinfo_path = "/proc/self/mountinfo";
int titan_source_test_mount_inventory(const char *path, const char **reason);
#define TITAN_SOURCE_MOUNTINFO mountinfo_path
#else
#define TITAN_SOURCE_MOUNTINFO "/proc/self/mountinfo"
#endif

static int mount_inventory(const char **reason)
{
    char text[65536];
    uint64_t mount_ids[6], parent_ids[6];
    int indexes[6];
    unsigned int seen = 0;
    size_t count = 0;
    if (read_text_at(AT_FDCWD, TITAN_SOURCE_MOUNTINFO, text, sizeof(text)) != 0)
        return fail(reason, "mount-inventory-unavailable");
    char *line = text;
    while (*line != '\0') {
        char *end = strchr(line, '\n');
        if (end == NULL || end == line || end - line > 8191 || count == 6)
            return fail(reason, "unexpected-mount");
        *end = '\0';
        char *tokens[32], *state = NULL;
        size_t token_count = 0;
        char *token = strtok_r(line, " ", &state);
        while (token != NULL) {
            if (token_count == 32)
                return fail(reason, "unexpected-mount");
            tokens[token_count++] = token;
            token = strtok_r(NULL, " ", &state);
        }
        size_t separator = 6;
        while (separator < token_count && strcmp(tokens[separator], "-") != 0)
            ++separator;
        uint64_t id, parent;
        dev_t device;
        /* Mount ID 0 is valid: Linux 4.14 numbers the initramfs rootfs 0. */
        if (token_count < 10 || separator + 4 != token_count ||
            !decimal(tokens[0], UINT64_MAX, &id) ||
            !decimal(tokens[1], UINT64_MAX, &parent) ||
            parse_device(tokens[2], &device) != 0 || major(device) != 0 ||
            strcmp(tokens[3], "/") != 0)
            return fail(reason, "unexpected-mount");
        for (size_t i = 0; i < count; ++i)
            if (mount_ids[i] == id)
                return fail(reason, "unexpected-mount");
        int index = expected_mount(tokens[4], tokens[separator + 1]);
        if (index < 0 || (seen & (1U << index)) != 0 || mount_options(tokens[5], index) != 0)
            return fail(reason, "unexpected-mount");
        for (size_t i = 6; i < separator; ++i) {
            char *colon = strchr(tokens[i], ':');
            if (strcmp(tokens[i], "unbindable") == 0)
                continue;
            if (colon == NULL)
                return fail(reason, "unexpected-mount");
            *colon = '\0';
            uint64_t group;
            if ((strcmp(tokens[i], "shared") != 0 && strcmp(tokens[i], "master") != 0 &&
                strcmp(tokens[i], "propagate_from") != 0) ||
                !decimal(colon + 1, UINT64_MAX, &group) || group == 0)
                return fail(reason, "unexpected-mount");
        }
        mount_ids[count] = id;
        parent_ids[count] = parent;
        indexes[count++] = index;
        seen |= 1U << index;
        line = end + 1;
    }
    if (count != 6 || seen != 63U)
        return fail(reason, "mount-inventory-incomplete");
    /* The five virtual mounts must sit directly on the '/' record. Its own
     * parent number is not assumed (itself on 4.14, possibly hidden elsewhere). */
    uint64_t root = 0;
    for (size_t i = 0; i < count; ++i)
        if (indexes[i] == 0)
            root = mount_ids[i];
    for (size_t i = 0; i < count; ++i)
        if (indexes[i] != 0 && parent_ids[i] != root)
            return fail(reason, "unexpected-mount");
    return 0;
}

#ifdef TITAN_SOURCE_PARSER_TEST
int titan_source_test_mount_inventory(const char *path, const char **reason)
{
    mountinfo_path = path;
    return mount_inventory(reason);
}
#endif
#endif

static int swap_inventory(const char **reason)
{
    char text[4096];
    if (read_text_at(AT_FDCWD, "/proc/swaps", text, sizeof(text)) != 0)
        return fail(reason, "swap-inventory-unavailable");
    char *newline = strchr(text, '\n');
    if (newline == NULL)
        return fail(reason, "swap-inventory-invalid");
    *newline = '\0';
    char *state = NULL;
    static const char *const headings[] = { "Filename", "Type", "Size", "Used", "Priority" };
    char *token = strtok_r(text, " \t", &state);
    for (size_t i = 0; i < sizeof(headings) / sizeof(headings[0]); ++i) {
        if (token == NULL || strcmp(token, headings[i]) != 0)
            return fail(reason, "swap-inventory-invalid");
        token = strtok_r(NULL, " \t", &state);
    }
    if (token != NULL)
        return fail(reason, "swap-inventory-invalid");
    return newline[1] == '\0' ? 0 : fail(reason, "swap-active");
}

static int namespaces(const struct titan_source *source, const char **reason)
{
    struct stat held, self, manager, root, manager_root;
    if (fstat(source->namespace_fd, &held) != 0 ||
        stat("/proc/self/ns/mnt", &self) != 0 || stat("/proc/1/ns/mnt", &manager) != 0 ||
        !S_ISREG(held.st_mode))
        return fail(reason, "namespace-unavailable");
    if (!same_identity(&held, &source->namespace_identity) ||
        !same_identity(&held, &self) || !same_identity(&held, &manager))
        return fail(reason, "namespace-mismatch");
    if (fstat(source->root_fd, &held) != 0 || stat("/", &root) != 0 ||
        stat("/proc/1/root", &manager_root) != 0 || !S_ISDIR(held.st_mode))
        return fail(reason, "root-identity-unavailable");
    if (!same_identity(&held, &source->root_identity) ||
        !same_identity(&held, &root) || !same_identity(&held, &manager_root))
        return fail(reason, "root-identity-mismatch");
    return 0;
}

static int environment(const struct titan_source *source, const char **reason)
{
    if (namespaces(source, reason) != 0 || mount_inventory(reason) != 0 ||
        swap_inventory(reason) != 0 || namespaces(source, reason) != 0)
        return 1;
    return 0;
}

static int retained_sysfs(const struct titan_source *source, const char **reason)
{
    char disk[TITAN_SOURCE_PATH_MAX], partition[TITAN_SOURCE_PATH_MAX];
    struct stat held, path;
    if (canonical_paths(disk, partition, reason) != 0)
        return 1;
    if (strcmp(disk, source->disk_sysfs_path) != 0 ||
        strcmp(partition, source->partition_sysfs_path) != 0)
        return fail(reason, "sysfs-parent-mismatch");
    if (fstat(source->disk_sysfs_fd, &held) != 0 || lstat(disk, &path) != 0 ||
        !S_ISDIR(held.st_mode) || !same_identity(&held, &source->disk_sysfs_identity) ||
        !same_identity(&held, &path) ||
        fstat(source->partition_sysfs_fd, &held) != 0 || lstat(partition, &path) != 0 ||
        !S_ISDIR(held.st_mode) || !same_identity(&held, &source->partition_sysfs_identity) ||
        !same_identity(&held, &path))
        return fail(reason, "sysfs-identity-mismatch");
    return 0;
}

static int block_node(int fd, const char *path, dev_t expected,
                      const struct stat *original, const char **reason)
{
    struct stat held, current;
    int flags = fcntl(fd, F_GETFL), descriptor = fcntl(fd, F_GETFD);
    if (flags < 0 || descriptor < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        (flags & O_NONBLOCK) == 0 || (descriptor & FD_CLOEXEC) == 0)
        return fail(reason, "block-access-invalid");
    if (fstat(fd, &held) != 0 || lstat(path, &current) != 0 ||
        !S_ISBLK(held.st_mode) || !S_ISBLK(current.st_mode) ||
        held.st_rdev != expected || !same_identity(&held, original) ||
        !same_identity(&held, &current))
        return fail(reason, "block-node-mismatch");
    return 0;
}

static int block_geometry(int fd, uint64_t expected_size, int partition, const char **reason)
{
    uint64_t size = 0;
    int logical = 0, physical = 0, read_only = 0;
    if (ioctl(fd, BLKGETSIZE64, &size) != 0 || ioctl(fd, BLKSSZGET, &logical) != 0 ||
        ioctl(fd, BLKPBSZGET, &physical) != 0 || ioctl(fd, BLKROGET, &read_only) != 0)
        return fail(reason, "block-query-failed");
    if (size != expected_size)
        return fail(reason, partition ? "partition-geometry-mismatch" : "disk-geometry-mismatch");
    if (logical != (int) SECTOR_BYTES || physical != (int) SECTOR_BYTES)
        return fail(reason, "sector-geometry-mismatch");
    return read_only == 1 ? 0 : fail(reason, "block-not-read-only");
}

int titan_source_recheck(struct titan_source *source, const char **reason)
{
    if (source == NULL || !source->ready || source->disk_fd < 0 || source->partition_fd < 0)
        return fail(reason, "state-invalid");
    dev_t disk, partition;
    if (environment(source, reason) != 0 || retained_sysfs(source, reason) != 0 ||
        sysfs_profile(source, &disk, &partition, reason) != 0 ||
        block_node(source->disk_fd, DISK_PATH, disk, &source->disk_identity, reason) != 0 ||
        block_node(source->partition_fd, PARTITION_PATH, partition, &source->partition_identity, reason) != 0 ||
        block_geometry(source->disk_fd, DISK_BYTES, 0, reason) != 0 ||
        block_geometry(source->partition_fd, PARTITION_BYTES, 1, reason) != 0 ||
        environment(source, reason) != 0)
        return 1;
    if (reason != NULL)
        *reason = "ok";
    return 0;
}

void titan_source_close(struct titan_source *source)
{
    if (source == NULL)
        return;
    int *descriptors[] = { &source->partition_fd, &source->disk_fd,
        &source->partition_sysfs_fd, &source->disk_sysfs_fd,
        &source->namespace_fd, &source->root_fd };
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(descriptors[0]); ++i) {
        if (*descriptors[i] >= 0)
            (void) close(*descriptors[i]);
    }
    struct titan_source empty = TITAN_SOURCE_INITIALIZER;
    *source = empty;
}

int titan_source_open(struct titan_source *source, const char **reason)
{
    if (source == NULL || source->ready || source->disk_fd >= 0 || source->partition_fd >= 0 ||
        source->disk_sysfs_fd >= 0 || source->partition_sysfs_fd >= 0 ||
        source->namespace_fd >= 0 || source->root_fd >= 0)
        return fail(reason, "state-invalid");
    source->namespace_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    source->root_fd = open("/", DIRECTORY_FLAGS);
    if (source->namespace_fd < 0 || source->root_fd < 0 ||
        fstat(source->namespace_fd, &source->namespace_identity) != 0 ||
        fstat(source->root_fd, &source->root_identity) != 0) {
        (void) fail(reason, "namespace-unavailable");
        goto failed;
    }
    if (environment(source, reason) != 0 ||
        canonical_paths(source->disk_sysfs_path, source->partition_sysfs_path, reason) != 0)
        goto failed;
    source->disk_sysfs_fd = open(source->disk_sysfs_path, DIRECTORY_FLAGS);
    source->partition_sysfs_fd = open(source->partition_sysfs_path, DIRECTORY_FLAGS);
    if (source->disk_sysfs_fd < 0 || source->partition_sysfs_fd < 0 ||
        fstat(source->disk_sysfs_fd, &source->disk_sysfs_identity) != 0 ||
        fstat(source->partition_sysfs_fd, &source->partition_sysfs_identity) != 0) {
        (void) fail(reason, "sysfs-identity-unavailable");
        goto failed;
    }
    dev_t disk, partition;
    if (sysfs_profile(source, &disk, &partition, reason) != 0)
        goto failed;
    struct stat disk_path, partition_path;
    if (lstat(DISK_PATH, &disk_path) != 0 || lstat(PARTITION_PATH, &partition_path) != 0 ||
        !S_ISBLK(disk_path.st_mode) || !S_ISBLK(partition_path.st_mode) ||
        disk_path.st_rdev != disk || partition_path.st_rdev != partition) {
        (void) fail(reason, "block-node-mismatch");
        goto failed;
    }
    source->disk_fd = open(DISK_PATH, BLOCK_FLAGS);
    if (source->disk_fd < 0 || fstat(source->disk_fd, &source->disk_identity) != 0 ||
        !same_identity(&source->disk_identity, &disk_path)) {
        (void) fail(reason, "block-node-mismatch");
        goto failed;
    }
    source->partition_fd = open(PARTITION_PATH, BLOCK_FLAGS | O_EXCL);
    if (source->partition_fd < 0) {
        (void) fail(reason, errno == EBUSY ? "partition-claim-conflict" : "partition-open-failed");
        goto failed;
    }
    if (fstat(source->partition_fd, &source->partition_identity) != 0 ||
        !same_identity(&source->partition_identity, &partition_path)) {
        (void) fail(reason, "block-node-mismatch");
        goto failed;
    }
    source->ready = 1;
    if (titan_source_recheck(source, reason) == 0)
        return 0;
failed:
    titan_source_close(source);
    return 1;
}
