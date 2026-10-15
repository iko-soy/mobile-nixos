/* SPDX-License-Identifier: MIT
 * Fixed producer for the sixteen control and calibration regions, for an
 * offline acquisition started from the recovery partition. It reads exactly
 * the regions in its compiled table, holds exclusive read-only claims on them,
 * checks their identity before and after, checks the four ext4 calibration
 * filesystems for a clean state, and streams the regions raw in table order,
 * followed by a text manifest with two independent SHA-256 passes per region.
 * Every read uses O_DIRECT, so both passes and the superblock rereads come from
 * the storage, not from the page cache.
 * No argument or peer input selects a source. It never writes storage, mounts,
 * repairs or changes a block flag.
 */
#define _GNU_SOURCE
#ifndef TITAN_USB_MOUNT_PROFILE
#error The control producer requires the sealed seven-mount profile
#endif
#include "mount-policy.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct region {
    const char *label;
    unsigned number;
    uint64_t start, sectors;
    int ext4;
};

#ifdef TITAN_CONTROL_VM_TEST
/* Disposable VM disk: the same labels in table order, small and contiguous. */
#define DISK_NAME "vda"
#define PARTITION_PREFIX "vda"
#define RAW_SECTORS 16
#define FS_SECTORS 512
static const struct region regions[] = {
    { "boot_para", 1, 2048, RAW_SECTORS, 0 }, { "para", 2, 2064, RAW_SECTORS, 0 },
    { "expdb", 3, 2080, RAW_SECTORS, 0 }, { "frp", 4, 2096, RAW_SECTORS, 0 },
    { "nvcfg", 5, 2112, FS_SECTORS, 1 }, { "nvdata", 6, 2624, FS_SECTORS, 1 },
    { "metadata", 7, 3136, RAW_SECTORS, 0 }, { "protect1", 8, 3152, FS_SECTORS, 1 },
    { "protect2", 9, 3664, FS_SECTORS, 1 }, { "seccfg", 10, 4176, RAW_SECTORS, 0 },
    { "sec1", 11, 4192, RAW_SECTORS, 0 }, { "proinfo", 12, 4208, RAW_SECTORS, 0 },
    { "nvram", 13, 4224, RAW_SECTORS, 0 }, { "cache", 14, 4240, RAW_SECTORS, 0 },
    { "otp", 15, 4256, RAW_SECTORS, 0 }, { "flashinfo", 16, 4272, RAW_SECTORS, 0 },
};
#else
/* The measured original-Titan GPT entries (verify-backup-catalog.py layout). */
#define DISK_NAME "mmcblk0"
#define PARTITION_PREFIX "mmcblk0p"
static const struct region regions[] = {
    { "boot_para", 1, 64, 2048, 0 }, { "para", 3, 67648, 1024, 0 },
    { "expdb", 4, 68672, 40960, 0 }, { "frp", 5, 109632, 2048, 0 },
    { "nvcfg", 6, 111680, 65536, 1 }, { "nvdata", 7, 177216, 131072, 1 },
    { "metadata", 8, 308288, 65536, 0 }, { "protect1", 9, 373824, 16384, 1 },
    { "protect2", 10, 390208, 19392, 1 }, { "seccfg", 11, 409600, 16384, 0 },
    { "sec1", 12, 425984, 4096, 0 }, { "proinfo", 13, 430080, 6144, 0 },
    { "nvram", 25, 829440, 131072, 0 }, { "cache", 35, 9142272, 884736, 0 },
    { "otp", 37, 244164544, 88064, 0 }, { "flashinfo", 38, 244252608, 32768, 0 },
};
#endif
#define REGION_COUNT 16
_Static_assert(sizeof(regions) / sizeof(regions[0]) == REGION_COUNT, "fixed sixteen-region table");

#define SECTOR_BYTES UINT64_C(512)
#define CHUNK_BYTES (1U << 20)
#define MANIFEST_MAX 8192U

enum status {
    STATUS_OK = 0,
    STATUS_ENVIRONMENT = 2,
    STATUS_IDENTITY = 3,
    STATUS_READ = 4,
    STATUS_OUTPUT = 5,
    STATUS_CHANGED = 6,
};

struct held {
    int fd;
    dev_t rdev;
    ino_t ino;
    char state[32];
    unsigned char first[32], second[32];
};

/* O_DIRECT needs aligned buffers; offsets and lengths are whole sectors. */
static unsigned char buffer[CHUNK_BYTES] __attribute__((aligned(4096)));
static unsigned char first_block[4096] __attribute__((aligned(4096)));

static int write_all(int fd, const void *data, size_t size)
{
    const unsigned char *bytes = data;
    while (size) {
        ssize_t count = write(fd, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        bytes += count;
        size -= (size_t)count;
    }
    return 0;
}

static _Noreturn void finish(int status_fd, enum status status)
{
    unsigned char record[8] = { 'T', 'P', 'S', 'T', 0, 0, 0, (unsigned char)status };
    (void)write_all(status_fd, record, sizeof(record));
    close(status_fd);
    _exit(status == STATUS_OK ? 0 : (int)status);
}

static int read_text(const char *path, char *text, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count = read(fd, text, size - 1);
    close(fd);
    if (count <= 0 || (size_t)count >= size - 1) return -1;
    text[count] = '\0';
    return 0;
}

static int read_number(const char *directory, const char *attribute, uint64_t *value)
{
    char path[PATH_MAX], text[64], *end;
    if (snprintf(path, sizeof(path), "%s/%s", directory, attribute) >= (int)sizeof(path) ||
        read_text(path, text, sizeof(text)) != 0) return -1;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno || end == text || (*end != '\n' && *end != '\0')) return -1;
    *value = parsed;
    return 0;
}

/* The partition's own sysfs records, its kernel read-only flag and an exclusive
 * read-only claim with matching geometry. */
static int check_identity(const struct region *region, struct held *held, int claim)
{
    char name[32], directory[64], path[PATH_MAX], canonical[PATH_MAX], text[4096], wanted[96];
    uint64_t value;
    unsigned device_major, device_minor;
    struct stat metadata;
    if (snprintf(name, sizeof(name), "%s%u", PARTITION_PREFIX, region->number) >= (int)sizeof(name) ||
        snprintf(directory, sizeof(directory), "/sys/class/block/%s", name) >= (int)sizeof(directory))
        return -1;
    if (realpath(directory, canonical) == NULL) return -1;
    char *slash = strrchr(canonical, '/');
    if (slash == NULL || strcmp(slash + 1, name) != 0) return -1;
    *slash = '\0';
    slash = strrchr(canonical, '/');
    if (slash == NULL || strcmp(slash + 1, DISK_NAME) != 0) return -1;
    if (read_number(directory, "partition", &value) != 0 || value != region->number ||
        read_number(directory, "start", &value) != 0 || value != region->start ||
        read_number(directory, "size", &value) != 0 || value != region->sectors ||
        read_number(directory, "ro", &value) != 0 || value != 1) return -1;
    if (snprintf(path, sizeof(path), "%s/uevent", directory) >= (int)sizeof(path) ||
        read_text(path, text, sizeof(text)) != 0 ||
        snprintf(wanted, sizeof(wanted), "\nPARTNAME=%s\n", region->label) >= (int)sizeof(wanted)) return -1;
    char lined[sizeof(text) + 2];
    snprintf(lined, sizeof(lined), "\n%s", text);
    if (strstr(lined, wanted) == NULL) return -1;
    if (snprintf(path, sizeof(path), "%s/dev", directory) >= (int)sizeof(path) ||
        read_text(path, text, sizeof(text)) != 0 ||
        sscanf(text, "%u:%u", &device_major, &device_minor) != 2) return -1;
    if (snprintf(path, sizeof(path), "%s/holders", directory) >= (int)sizeof(path)) return -1;
    DIR *holders = opendir(path);
    if (holders == NULL) return -1;
    for (struct dirent *entry; (entry = readdir(holders)) != NULL;)
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) { closedir(holders); return -1; }
    closedir(holders);
    if (claim) {
        if (snprintf(path, sizeof(path), "/dev/%s", name) >= (int)sizeof(path)) return -1;
        /* O_EXCL on a block device is an exclusive claim: it fails while the
         * partition is mounted or claimed elsewhere. */
        held->fd = open(path, O_RDONLY | O_EXCL | O_DIRECT | O_CLOEXEC | O_NOFOLLOW);
        if (held->fd < 0) return -1;
    }
    if (fstat(held->fd, &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
        metadata.st_rdev != makedev(device_major, device_minor)) return -1;
    if (claim) { held->rdev = metadata.st_rdev; held->ino = metadata.st_ino; }
    else if (held->rdev != metadata.st_rdev || held->ino != metadata.st_ino) return -1;
    uint64_t bytes = 0;
    int sector = 0, read_only = 0;
    if (ioctl(held->fd, BLKGETSIZE64, &bytes) != 0 || bytes != region->sectors * SECTOR_BYTES ||
        ioctl(held->fd, BLKSSZGET, &sector) != 0 || sector != (int)SECTOR_BYTES ||
        ioctl(held->fd, BLKROGET, &read_only) != 0 || read_only != 1) return -1;
    return 0;
}

static uint32_t le32(const unsigned char *bytes)
{
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

/* Primary superblock only: a clean state, no pending journal recovery and no
 * orphan list. The filesystem is never mounted, replayed or repaired. */
static int ext4_state(int fd, char *state, size_t size)
{
    if (pread(fd, first_block, sizeof(first_block), 0) != (ssize_t)sizeof(first_block)) return -1;
    const unsigned char *superblock = first_block + 1024;
    unsigned magic = superblock[0x38] | superblock[0x39] << 8;
    unsigned flags = superblock[0x3A] | superblock[0x3B] << 8;
    const char *result = magic != 0xEF53 ? "not-ext4" :
        !(flags & 1) || (flags & 2) ? "unclean-state" :
        le32(superblock + 0x60) & 0x4 ? "journal-recovery-pending" :
        le32(superblock + 0xE8) != 0 ? "orphans-pending" : "clean";
    snprintf(state, size, "%s", result);
    return 0;
}

static int read_region(int fd, uint64_t bytes, int output, unsigned char digest[32])
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned length = 0;
    int result = -1;
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) goto done;
    for (uint64_t offset = 0; offset < bytes;) {
        size_t want = bytes - offset < CHUNK_BYTES ? (size_t)(bytes - offset) : CHUNK_BYTES;
        ssize_t count = pread(fd, buffer, want, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto done;
        if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) goto done;
        if (output >= 0 && write_all(output, buffer, (size_t)count) != 0) { result = -2; goto done; }
        offset += (uint64_t)count;
    }
    result = EVP_DigestFinal_ex(context, digest, &length) == 1 && length == 32 ? 0 : -1;
done:
    EVP_MD_CTX_free(context);
    return result;
}

static void hex(const unsigned char digest[32], char text[65])
{
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        text[2 * i] = digits[digest[i] >> 4];
        text[2 * i + 1] = digits[digest[i] & 15];
    }
    text[64] = '\0';
}

static int descriptor_argument(const char *text, int *fd)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || end == text || *end || value <= STDERR_FILENO || value > INT_MAX) return -1;
    *fd = (int)value;
    return 0;
}

int main(int argc, char **argv)
{
    int output = -1, status_fd = -1;
    unsigned long long max_bytes = 0, timeout = 0;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) return 1;
        char *end;
        if (strcmp(argv[i], "--output-fd") == 0) { if (descriptor_argument(argv[i + 1], &output) != 0) return 1; }
        else if (strcmp(argv[i], "--status-fd") == 0) { if (descriptor_argument(argv[i + 1], &status_fd) != 0) return 1; }
        else if (strcmp(argv[i], "--max-bytes") == 0) {
            errno = 0; max_bytes = strtoull(argv[i + 1], &end, 10);
            if (errno || *end || max_bytes == 0) return 1;
        } else if (strcmp(argv[i], "--timeout-seconds") == 0) {
            errno = 0; timeout = strtoull(argv[i + 1], &end, 10);
            if (errno || *end || timeout == 0 || timeout > 86400) return 1;
        } else return 1;
    }
    struct stat output_metadata, status_metadata;
    if (output < 0 || status_fd < 0 || output == status_fd || max_bytes == 0 || timeout == 0 ||
        fstat(output, &output_metadata) != 0 || fstat(status_fd, &status_metadata) != 0 ||
        !S_ISFIFO(output_metadata.st_mode) || !S_ISFIFO(status_metadata.st_mode) ||
        (output_metadata.st_dev == status_metadata.st_dev && output_metadata.st_ino == status_metadata.st_ino))
        return 1;
    alarm((unsigned)timeout);
    /* Only the offline environment: started by PID 1, in the sealed mount set. */
    const char *reason = NULL;
    if (getpid() == 1 || getppid() != 1 || titan_mount_inventory(TITAN_MOUNTS_USB_SEALED_7, &reason) != 0)
        finish(status_fd, STATUS_ENVIRONMENT);
    uint64_t total = 0;
    for (int i = 0; i < REGION_COUNT; ++i) total += regions[i].sectors * SECTOR_BYTES;
    if (total + MANIFEST_MAX > max_bytes) finish(status_fd, STATUS_OUTPUT);
    struct held held[REGION_COUNT];
    for (int i = 0; i < REGION_COUNT; ++i) {
        held[i].fd = -1;
        snprintf(held[i].state, sizeof(held[i].state), "-");
        if (check_identity(&regions[i], &held[i], 1) != 0) finish(status_fd, STATUS_IDENTITY);
        if (regions[i].ext4 && ext4_state(held[i].fd, held[i].state, sizeof(held[i].state)) != 0)
            finish(status_fd, STATUS_READ);
    }
    /* First pass: stream every region in table order while hashing it. */
    for (int i = 0; i < REGION_COUNT; ++i) {
        int result = read_region(held[i].fd, regions[i].sectors * SECTOR_BYTES, output, held[i].first);
        if (result == -2) finish(status_fd, STATUS_OUTPUT);
        if (result != 0) finish(status_fd, STATUS_READ);
    }
    /* Second, independent pass over the same claims; then identities again. */
    for (int i = 0; i < REGION_COUNT; ++i)
        if (read_region(held[i].fd, regions[i].sectors * SECTOR_BYTES, -1, held[i].second) != 0)
            finish(status_fd, STATUS_READ);
    for (int i = 0; i < REGION_COUNT; ++i) {
        char again[32];
        if (check_identity(&regions[i], &held[i], 0) != 0) finish(status_fd, STATUS_CHANGED);
        if (regions[i].ext4) {
            if (ext4_state(held[i].fd, again, sizeof(again)) != 0) finish(status_fd, STATUS_READ);
            if (strcmp(again, held[i].state) != 0) finish(status_fd, STATUS_CHANGED);
        }
    }
    char manifest[MANIFEST_MAX];
    size_t used = 0;
    int written = snprintf(manifest, sizeof(manifest), "TITAN-CONTROL-REGIONS v1 regions=%d bytes=%llu\n",
                           REGION_COUNT, (unsigned long long)total);
    if (written < 0 || (size_t)written >= sizeof(manifest)) finish(status_fd, STATUS_OUTPUT);
    used = (size_t)written;
    for (int i = 0; i < REGION_COUNT; ++i) {
        char first[65], second[65];
        hex(held[i].first, first);
        hex(held[i].second, second);
        written = snprintf(manifest + used, sizeof(manifest) - used,
            "region %s %u %llu %llu %llu %s %s %s %s\n", regions[i].label, regions[i].number,
            (unsigned long long)regions[i].start, (unsigned long long)regions[i].sectors,
            (unsigned long long)(regions[i].sectors * SECTOR_BYTES), first, second,
            regions[i].ext4 ? "ext4" : "raw", held[i].state);
        if (written < 0 || (size_t)written >= sizeof(manifest) - used) finish(status_fd, STATUS_OUTPUT);
        used += (size_t)written;
    }
    written = snprintf(manifest + used, sizeof(manifest) - used, "end\n");
    if (written < 0 || (size_t)written >= sizeof(manifest) - used) finish(status_fd, STATUS_OUTPUT);
    used += (size_t)written;
    if (write_all(output, manifest, used) != 0) finish(status_fd, STATUS_OUTPUT);
    if (close(output) != 0) finish(status_fd, STATUS_OUTPUT);
    for (int i = 0; i < REGION_COUNT; ++i) close(held[i].fd);
    finish(status_fd, STATUS_OK);
}
