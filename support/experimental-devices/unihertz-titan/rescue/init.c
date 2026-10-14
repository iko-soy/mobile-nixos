/* SPDX-License-Identifier: MIT
 * Build-only rescue PID 1. No storage mounts, acquisition, shell or transport.
 * BLKROSET changes the kernel's volatile block-device flag, not storage bytes.
 * This does not prevent kernel/firmware writers or establish hardware safety.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef TITAN_RESCUE_DISCOVERY_SECONDS
#define TITAN_RESCUE_DISCOVERY_SECONDS 10
#endif
#if TITAN_RESCUE_DISCOVERY_SECONDS < 1
#error Discovery timeout must be positive
#endif

#ifdef TITAN_RESCUE_VM_TEST
int titan_rescue_vm_test(void);
#endif

static void reap_children(void) {
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

static void wait_one_second(void) {
    struct timespec left = { .tv_sec = 1, .tv_nsec = 0 };
    while (nanosleep(&left, &left) < 0 && errno == EINTR)
        reap_children();
    reap_children();
}

static _Noreturn void failed(const char *reason) {
    printf("TITAN_RESCUE_FAILED %s\n", reason);
    /* Never return from PID 1, invoke reboot, or fall through to another init. */
    for (;;)
        wait_one_second();
}

static void make_directory(const char *path, mode_t mode) {
    struct stat st;
    if (mkdir(path, mode) < 0 && errno != EEXIST)
        failed("cannot-create-ram-directory");
    if (lstat(path, &st) < 0 || !S_ISDIR(st.st_mode))
        failed("ram-directory-is-not-directory");
}

static void mount_virtual(const char *type, const char *path,
                          unsigned long flags, const char *options) {
    if (mount(type, path, type, flags, options) < 0)
        failed("virtual-mount-failed");
}

static void open_console(void) {
    struct stat st;
    int fd = open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISCHR(st.st_mode)
            || major(st.st_rdev) != 5 || minor(st.st_rdev) != 1)
        failed("console-unavailable");
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        failed("console-dup-failed");
    if (fd > STDERR_FILENO)
        close(fd);
}

static int expected_mount(const char *path, const char *type) {
    if (strcmp(path, "/") == 0)
        return (strcmp(type, "rootfs") == 0 || strcmp(type, "ramfs") == 0
                || strcmp(type, "tmpfs") == 0) ? 0 : -1;
    if (strcmp(path, "/dev") == 0 && strcmp(type, "devtmpfs") == 0) return 1;
    if (strcmp(path, "/proc") == 0 && strcmp(type, "proc") == 0) return 2;
    if (strcmp(path, "/sys") == 0 && strcmp(type, "sysfs") == 0) return 3;
    if (strcmp(path, "/run") == 0 && strcmp(type, "tmpfs") == 0) return 4;
    if (strcmp(path, "/tmp") == 0 && strcmp(type, "tmpfs") == 0) return 5;
    return -1;
}

static void verify_mounts(void) {
    FILE *stream = fopen("/proc/self/mountinfo", "r");
    char line[8192], root[4096], path[4096], type[32];
    unsigned seen = 0, total = 0, device_major, device_minor;
    if (!stream)
        failed("mount-inventory-unavailable");
    while (fgets(line, sizeof(line), stream)) {
        char *separator = strstr(line, " - ");
        int index;
        if (++total > 16 || !strchr(line, '\n') || !separator
                || sscanf(line, "%*u %*u %u:%u %4095s %4095s", &device_major,
                          &device_minor, root, path) != 4
                || sscanf(separator + 3, "%31s", type) != 1
                || device_major != 0 || strcmp(root, "/") != 0)
            failed("unexpected-mount-record");
        index = expected_mount(path, type);
        if (index < 0 || (seen & (1u << index)))
            failed("unexpected-or-duplicate-mount");
        seen |= 1u << index;
    }
    if (ferror(stream) || seen != 0x3f)
        failed("mount-inventory-incomplete");
    fclose(stream);
}

static int safe_device_name(const char *name) {
    if (!*name || strlen(name) > 255 || strcmp(name, ".") == 0
            || strcmp(name, "..") == 0)
        return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p)
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.')
            return 0;
    return 1;
}

static void sysfs_device_number(int directory, const char *name,
                               unsigned *device_major, unsigned *device_minor) {
    char path[264], data[64], extra;
    ssize_t count;
    int fd;
    if (snprintf(path, sizeof(path), "%s/dev", name) >= (int)sizeof(path))
        failed("block-name-too-long");
    /* sysfs class entries are kernel-owned symlinks to the device tree. */
    fd = openat(directory, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        failed("block-identity-unavailable");
    count = read(fd, data, sizeof(data) - 1);
    close(fd);
    if (count <= 0 || count >= (ssize_t)sizeof(data) - 1)
        failed("block-identity-invalid");
    data[count] = '\0';
    if (sscanf(data, "%u:%u %c", device_major, device_minor, &extra) != 2)
        failed("block-identity-invalid");
}

static unsigned guard_block_devices(void) {
    DIR *directory = opendir("/sys/class/block");
    struct dirent *entry;
    unsigned storage = 0;
    int devices = open("/dev", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (!directory || devices < 0)
        failed("block-inventory-unavailable");
    for (;;) {
        struct stat st;
        unsigned device_major, device_minor;
        int fd, read_only = 1;
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno)
                failed("block-inventory-read-failed");
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (!safe_device_name(entry->d_name))
            failed("block-name-invalid");
        sysfs_device_number(dirfd(directory), entry->d_name, &device_major, &device_minor);
        /* Never follow a /dev symlink or open a node with mismatched identity. */
        fd = openat(devices, entry->d_name,
                    O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &st) < 0 || !S_ISBLK(st.st_mode)
                || major(st.st_rdev) != device_major || minor(st.st_rdev) != device_minor)
            failed("block-node-missing-or-mismatched");
        if (ioctl(fd, BLKROSET, &read_only) < 0)
            failed("block-read-only-set-failed");
        read_only = 0;
        if (ioctl(fd, BLKROGET, &read_only) < 0 || read_only != 1)
            failed("block-read-only-verification-failed");
        close(fd);
        /* RAM disks (major 1) and loop devices (major 7) are guarded too, but
         * their presence does not establish that physical storage appeared. */
        if (device_major != 1 && device_major != 7)
            ++storage;
    }
    close(devices);
    closedir(directory);
    return storage;
}

int main(void) {
    unsigned elapsed = 0;
    const unsigned long restricted = MS_NOSUID | MS_NODEV | MS_NOEXEC;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() != 1) {
        fputs("TITAN_RESCUE_REFUSED not-pid-one\n", stderr);
        return 1;
    }
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    umask(0077);
    if (chdir("/") < 0)
        failed("root-directory-unavailable");
    make_directory("/dev", 0755);
    make_directory("/proc", 0555);
    make_directory("/sys", 0555);
    make_directory("/run", 0700);
    make_directory("/tmp", 0700);
    mount_virtual("devtmpfs", "/dev", MS_NOSUID | MS_NOEXEC, "mode=0755");
    open_console();
    puts("TITAN_RESCUE_START v1");
    mount_virtual("proc", "/proc", restricted | MS_RDONLY, "");
    mount_virtual("sysfs", "/sys", restricted | MS_RDONLY, "");
    mount_virtual("tmpfs", "/run", restricted, "size=16m,mode=0700");
    mount_virtual("tmpfs", "/tmp", restricted, "size=16m,mode=0700");
    for (;;) {
        verify_mounts();
        if (guard_block_devices() > 0)
            break;
        if (elapsed >= TITAN_RESCUE_DISCOVERY_SECONDS)
            failed("no-storage-before-deadline");
        wait_one_second();
        ++elapsed;
    }
    puts("TITAN_RESCUE_READY v1");
#ifdef TITAN_RESCUE_VM_TEST
    (void)titan_rescue_vm_test();
    failed("vm-test-returned");
#endif
    for (;;) {
        wait_one_second();
        verify_mounts();
        if (guard_block_devices() == 0)
            failed("storage-disappeared");
    }
}
