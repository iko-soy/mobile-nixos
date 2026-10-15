/* SPDX-License-Identifier: MIT
 * Fixed diagnostic producer for the native route (diag/README.adoc). Started
 * by the probe profile's PID 1 after the storage guard and the gadget bind, it
 * waits until the kernel has settled, then streams a fixed list of kernel and
 * firmware state as named sections: the command line, the kernel log, the
 * device tree as the bootloader passed it, every device with its bound driver,
 * interrupts, processors, partitions and the physical memory map. It never
 * opens a block device, mounts, writes a file or changes kernel state, and no
 * argument or peer input selects what is read.
 *
 * Stream: "TITAN-DIAG v1\n", then for each section in order either
 * "section NAME LENGTH\n" (or "... LENGTH truncated\n") followed by exactly
 * LENGTH bytes, "section NAME missing\n", or "section NAME error ERRNO\n"
 * when it could not be read; then "end\n". The eight-byte status record
 * follows on its own descriptor: "TPST" and a big-endian code.
 */
#define _GNU_SOURCE
#ifndef TITAN_USB_MOUNT_PROFILE
#error The diagnostic producer requires the sealed seven-mount profile
#endif
#include "mount-policy.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef TITAN_DIAG_VM_TEST
#define SETTLE_SECONDS 5
#else
/* Lets deferred probes finish and report (after ten seconds), and the
 * regulator core's unused-regulator pass log its result (thirty seconds after
 * late init), before the log is read. */
#define SETTLE_SECONDS 40
#endif
#define KMSG_LIMIT (4U << 20)
#define RECORD_LIMIT 16384U

enum status {
    STATUS_OK = 0,
    STATUS_ENVIRONMENT = 2,
    STATUS_OUTPUT = 5,
};

enum source { SOURCE_FILE, SOURCE_KMSG, SOURCE_BINDINGS };

struct section {
    const char *name;
    const char *path;
    size_t limit;
    enum source source;
};

static const struct section sections[] = {
    { "cmdline", "/proc/cmdline", 4096, SOURCE_FILE },
    { "kmsg", "/dev/kmsg", KMSG_LIMIT, SOURCE_KMSG },
    { "fdt", "/sys/firmware/fdt", 2U << 20, SOURCE_FILE },
    { "bindings", "/sys/bus", 256U << 10, SOURCE_BINDINGS },
    { "interrupts", "/proc/interrupts", 256U << 10, SOURCE_FILE },
    { "cpuinfo", "/proc/cpuinfo", 64U << 10, SOURCE_FILE },
    { "partitions", "/proc/partitions", 64U << 10, SOURCE_FILE },
    { "iomem", "/proc/iomem", 256U << 10, SOURCE_FILE },
};

static unsigned char buffer[KMSG_LIMIT];

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

/* A regular procfs or sysfs file, read to its end within the limit. Returns
 * the length, -1 when absent, -2 on a read error with errno set; sets
 * *truncated. */
static long read_file(const char *path, size_t limit, int *truncated)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? -1 : -2;
    size_t used = 0;
    *truncated = 0;
    for (;;) {
        if (used == limit) {
            unsigned char probe;
            ssize_t more = read(fd, &probe, 1);
            if (more < 0 && errno == EINTR) continue;
            if (more > 0) *truncated = 1;
            break;
        }
        ssize_t count = read(fd, buffer + used, limit - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { int saved = errno; close(fd); errno = saved; return -2; }
        if (count == 0) break;
        used += (size_t)count;
    }
    close(fd);
    return (long)used;
}

/* Every kernel log record currently held, one read per record, until the
 * buffer is empty. Records overwritten while reading are skipped. */
static long read_kmsg(size_t limit, int *truncated)
{
    int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? -1 : -2;
    size_t used = 0;
    *truncated = 0;
    for (;;) {
        if (limit - used < RECORD_LIMIT) { *truncated = 1; break; }
        ssize_t count = read(fd, buffer + used, RECORD_LIMIT);
        if (count < 0 && (errno == EINTR || errno == EPIPE)) continue;
        if (count < 0 && errno == EAGAIN) break;
        if (count < 0) { int saved = errno; close(fd); errno = saved; return -2; }
        if (count == 0) break;
        used += (size_t)count;
    }
    close(fd);
    return (long)used;
}

/* "BUS DEVICE DRIVER" for every device on every bus, DRIVER "-" while
 * unbound. Only directory listings and link targets are read: no device
 * attribute, since some take the device lock and can deadlock against a probe
 * in progress (waiting_for_supplier). Returns the length or -2 with errno set;
 * sets *truncated. */
static long read_bindings(const char *root, size_t limit, int *truncated)
{
    DIR *buses = opendir(root);
    if (buses == NULL) return errno == ENOENT ? -1 : -2;
    size_t used = 0;
    *truncated = 0;
    struct dirent *bus;
    while (!*truncated && (errno = 0, bus = readdir(buses)) != NULL) {
        if (bus->d_name[0] == '.') continue;
        char directory[PATH_MAX];
        int length = snprintf(directory, sizeof(directory), "%s/%s/devices", root, bus->d_name);
        if (length <= 0 || (size_t)length >= sizeof(directory)) continue;
        DIR *devices = opendir(directory);
        if (devices == NULL) continue;
        struct dirent *device;
        while ((device = readdir(devices)) != NULL) {
            if (device->d_name[0] == '.') continue;
            char path[PATH_MAX], target[PATH_MAX];
            const char *driver = "-";
            length = snprintf(path, sizeof(path), "%s/%s/driver", directory, device->d_name);
            if (length <= 0 || (size_t)length >= sizeof(path)) continue;
            ssize_t count = readlink(path, target, sizeof(target) - 1);
            if (count > 0) {
                target[count] = '\0';
                const char *slash = strrchr(target, '/');
                driver = slash != NULL ? slash + 1 : target;
            }
            length = snprintf((char *)buffer + used, limit - used, "%s %s %s\n",
                              bus->d_name, device->d_name, driver);
            if (length <= 0 || (size_t)length >= limit - used) { *truncated = 1; break; }
            used += (size_t)length;
        }
        closedir(devices);
    }
    int saved = errno;
    closedir(buses);
    if (!*truncated && saved != 0) { errno = saved; return -2; }
    return (long)used;
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

static void settle(void)
{
    for (;;) {
        struct timespec now, pause = { .tv_sec = 1, .tv_nsec = 0 };
        if (clock_gettime(CLOCK_BOOTTIME, &now) != 0 || now.tv_sec >= SETTLE_SECONDS) return;
        (void)nanosleep(&pause, NULL);
    }
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
    size_t budget = 64;
    for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); ++i) budget += sections[i].limit + 64;
    if (budget > max_bytes) finish(status_fd, STATUS_OUTPUT);
    settle();
    static const char banner[] = "TITAN-DIAG v1\n";
    if (write_all(output, banner, sizeof(banner) - 1) != 0) finish(status_fd, STATUS_OUTPUT);
    for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); ++i) {
        const struct section *section = &sections[i];
        int truncated = 0;
        errno = 0;
        long length = section->source == SOURCE_KMSG ? read_kmsg(section->limit, &truncated)
                    : section->source == SOURCE_BINDINGS ? read_bindings(section->path, section->limit, &truncated)
                    : read_file(section->path, section->limit, &truncated);
        char header[96];
        int written = length == -1 ? snprintf(header, sizeof(header), "section %s missing\n", section->name)
                    : length == -2 ? snprintf(header, sizeof(header), "section %s error %d\n", section->name,
                                              errno > 0 && errno < 4096 ? errno : 0)
                    : snprintf(header, sizeof(header), "section %s %ld%s\n", section->name, length,
                               truncated ? " truncated" : "");
        if (written <= 0 || (size_t)written >= sizeof(header) ||
            write_all(output, header, (size_t)written) != 0 ||
            (length > 0 && write_all(output, buffer, (size_t)length) != 0))
            finish(status_fd, STATUS_OUTPUT);
    }
    static const char trailer[] = "end\n";
    if (write_all(output, trailer, sizeof(trailer) - 1) != 0 || close(output) != 0)
        finish(status_fd, STATUS_OUTPUT);
    finish(status_fd, STATUS_OK);
}
