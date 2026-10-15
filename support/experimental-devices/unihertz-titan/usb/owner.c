/* SPDX-License-Identifier: MIT
 * Fixed experimental ACM owner. No storage opens, peer commands or overrides.
 * 1209:0005 is pid.codes' private-test PID: in-house experiments only, never a
 * shipping identifier. It is neither unique device identity nor authentication.
 */
#define _GNU_SOURCE
#ifndef TITAN_USB_MOUNT_PROFILE
#error USB owner requires the explicit seven-mount profile
#endif
#include "owner.h"
#include "mount-policy.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CONFIG_ROOT TITAN_USB_CONFIGFS_PATH
#define GADGET_ROOT CONFIG_ROOT "/usb_gadget"
#define GADGET_PATH GADGET_ROOT "/titan-rescue"
#ifdef TITAN_USB_PIPELINE_VM_TEST
#define UDC_NAME "dummy_udc.0"
#define UDC_DEVICE "/sys/devices/platform/dummy_udc.0"
#define UDC_DRIVER "/sys/bus/platform/drivers/dummy_udc"
#else
#define UDC_NAME "musb-hdrc"
#define UDC_DEVICE "/sys/devices/platform/11201000.usb3"
#define UDC_DRIVER "/sys/bus/platform/drivers/mtu3_phone"
#endif
#define UDC_FUNCTION "/sys/class/udc/" UDC_NAME "/function"
/* Linux fs/configfs/mount.c; not provided by the kernel UAPI magic header. */
#define TITAN_CONFIGFS_MAGIC 0x62656570

static int fail(const char **reason, const char *value)
{
    if (reason != NULL) *reason = value;
    return -1;
}

static int deadline_set(struct timespec *deadline, time_t seconds)
{
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0) return -1;
    deadline->tv_sec += seconds;
    return 0;
}

static int remaining(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    int64_t ns = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000000000LL +
                 deadline->tv_nsec - now.tv_nsec;
    if (ns <= 0) return -1;
    int64_t ms = (ns + 999999) / 1000000;
    return ms > INT_MAX ? INT_MAX : (int)ms;
}

static int pause_probe(const struct timespec *deadline)
{
    int left = remaining(deadline);
    if (left < 0) return -1;
    int result = poll(NULL, 0, left < 10 ? left : 10);
    return (result < 0 && errno != EINTR) || remaining(deadline) < 0 ? -1 : 0;
}

static int path_join(char *output, size_t size, const char *base, const char *child)
{
    int count = snprintf(output, size, "%s/%s", base, child);
    return count < 0 || (size_t)count >= size ? -1 : 0;
}

static int read_text(const char *path, char *output, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    size_t length = 0;
    int result = 0;
    for (;;) {
        ssize_t count = read(fd, output + length, size - 1 - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { result = -1; break; }
        if (count == 0) break;
        length += (size_t)count;
        if (length == size - 1) { result = -1; break; }
    }
    if (close(fd) != 0) result = -1;
    if (result != 0 || memchr(output, '\0', length) != NULL) return -1;
    if (length > 0 && output[length - 1] == '\n') --length;
    output[length] = '\0';
    return 0;
}

static int text_equals(const char *path, const char *expected)
{
    char value[256];
    return read_text(path, value, sizeof(value)) == 0 && strcmp(value, expected) == 0;
}

static int write_attribute(const char *attribute, const char *value)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), GADGET_PATH, attribute) != 0) return ENAMETOOLONG;
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno;
    size_t length = strlen(value);
    ssize_t count;
    do { count = write(fd, value, length); } while (count < 0 && errno == EINTR);
    int error = count < 0 ? errno : ((size_t)count == length ? 0 : EIO);
    if (close(fd) != 0 && error == 0) error = errno;
    return error;
}

static int attribute_equals(const char *attribute, const char *expected)
{
    char path[PATH_MAX];
    return path_join(path, sizeof(path), GADGET_PATH, attribute) == 0 && text_equals(path, expected);
}

static int directory_empty(const char *path)
{
    DIR *directory = opendir(path);
    if (directory == NULL) return 0;
    int empty = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) { if (errno != 0) empty = 0; break; }
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            empty = 0; break;
        }
    }
    if (closedir(directory) != 0) empty = 0;
    return empty;
}

static int absent(const char *path)
{
    struct stat metadata;
    return lstat(path, &metadata) < 0 && errno == ENOENT;
}

static int udc_identity(void)
{
    char device[PATH_MAX], driver[PATH_MAX];
    return realpath("/sys/class/udc/" UDC_NAME "/device", device) != NULL &&
           realpath("/sys/class/udc/" UDC_NAME "/device/driver", driver) != NULL &&
           strcmp(device, UDC_DEVICE) == 0 && strcmp(driver, UDC_DRIVER) == 0;
}

static int make_child(const char *name, int *owned)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), GADGET_PATH, name) != 0 || mkdir(path, 0700) != 0) return -1;
    *owned = 1;
    return 0;
}

static int create_gadget(struct titan_usb *owner)
{
    static const struct { const char *name, *value; } attributes[] = {
        { "idVendor", "0x1209\n" }, { "idProduct", "0x0005\n" },
        { "bcdUSB", "0x0200\n" }, { "bcdDevice", "0x0100\n" },
        { "bDeviceClass", "0\n" }, { "bDeviceSubClass", "0\n" }, { "bDeviceProtocol", "0\n" }
    };
    if (mkdir(GADGET_PATH, 0700) != 0) return -1;
    owner->gadget = 1;
    for (size_t i = 0; i < sizeof(attributes) / sizeof(attributes[0]); ++i)
        if (write_attribute(attributes[i].name, attributes[i].value) != 0) return -1;
    if (make_child("strings/0x409", &owner->strings) != 0 ||
        write_attribute("strings/0x409/manufacturer", "Titan rescue experiment\n") != 0 ||
        write_attribute("strings/0x409/product", "Titan read-only acquisition\n") != 0 ||
        write_attribute("strings/0x409/serialnumber", "TITAN-RESCUE-EXPERIMENT-0001\n") != 0 ||
        make_child("configs/c.1", &owner->configuration) != 0 ||
        make_child("configs/c.1/strings/0x409", &owner->config_strings) != 0 ||
        write_attribute("configs/c.1/strings/0x409/configuration", "Read-only acquisition\n") != 0 ||
        write_attribute("configs/c.1/bmAttributes", "0x80\n") != 0 ||
        write_attribute("configs/c.1/MaxPower", "50\n") != 0 ||
        make_child("functions/acm.usb0", &owner->function) != 0 ||
        !attribute_equals("functions/acm.usb0/port_num", "0") || !attribute_equals("UDC", "")) return -1;
    /* Configfs resolves the target with kern_path relative to process cwd at
     * creation, so use fixed absolute paths rather than a relative link target. */
    if (symlink(GADGET_PATH "/functions/acm.usb0", GADGET_PATH "/configs/c.1/acm.usb0") != 0) return -1;
    owner->linked = 1;
    return 0;
}

static int raw_check(int fd)
{
    struct termios term;
    if (tcgetattr(fd, &term) != 0) return -1;
    tcflag_t forbidden = IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXOFF | IXANY;
    return (term.c_iflag & forbidden) != 0 || (term.c_oflag & OPOST) != 0 ||
        (term.c_lflag & (ECHO | ECHONL | ICANON | ISIG | IEXTEN)) != 0 ||
        (term.c_cflag & (CSIZE | CREAD | CLOCAL | PARENB | CRTSCTS | HUPCL)) != (CS8 | CREAD | CLOCAL) ||
        term.c_cc[VMIN] != 1 || term.c_cc[VTIME] != 0 ? -1 : 0;
}

static int raw_set(int fd)
{
    struct termios term;
    if (tcgetattr(fd, &term) != 0) return -1;
    cfmakeraw(&term);
    term.c_iflag &= ~(IXON | IXOFF | IXANY);
    term.c_cflag &= ~(CRTSCTS | HUPCL);
    term.c_cflag |= CREAD | CLOCAL;
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    if (cfsetispeed(&term, B115200) != 0 || cfsetospeed(&term, B115200) != 0 ||
        tcsetattr(fd, TCSANOW, &term) != 0 || ioctl(fd, TIOCEXCL) != 0) return -1;
    return raw_check(fd);
}

static int tty_identity(int fd, const char *name, const struct stat *original)
{
    char path[128], value[64], extra;
    struct stat held, node;
    unsigned major_number, minor_number;
    if (snprintf(path, sizeof(path), "/dev/%s", name) >= (int)sizeof(path) ||
        fstat(fd, &held) != 0 || lstat(path, &node) != 0 || !S_ISCHR(held.st_mode) || !S_ISCHR(node.st_mode) ||
        held.st_dev != node.st_dev || held.st_ino != node.st_ino || held.st_rdev != node.st_rdev ||
        (original != NULL && (held.st_dev != original->st_dev || held.st_ino != original->st_ino ||
                              held.st_rdev != original->st_rdev)) ||
        snprintf(path, sizeof(path), "/sys/class/tty/%s/dev", name) >= (int)sizeof(path) ||
        read_text(path, value, sizeof(value)) != 0 ||
        sscanf(value, "%u:%u%c", &major_number, &minor_number, &extra) != 2 ||
        held.st_rdev != makedev(major_number, minor_number)) return -1;
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 || (flags & O_ACCMODE) != O_RDWR || !(flags & O_NONBLOCK) ? -1 : 0;
}

static int open_tty(const char *name, const struct timespec *deadline)
{
    char path[64];
    if (snprintf(path, sizeof(path), "/dev/%s", name) >= (int)sizeof(path)) return -1;
    for (;;) {
        int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            if (tty_identity(fd, name, NULL) != 0 || raw_set(fd) != 0 || remaining(deadline) < 0) {
                close(fd); return -1;
            }
            return fd;
        }
        if ((errno != ENOENT && errno != ENODEV) || pause_probe(deadline) != 0) return -1;
    }
}

static int mount_identity(const struct titan_usb *owner)
{
    struct stat metadata;
    struct statfs filesystem;
    return lstat(CONFIG_ROOT, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_dev != owner->mount_identity.st_dev || metadata.st_ino != owner->mount_identity.st_ino ||
        statfs(CONFIG_ROOT, &filesystem) != 0 || filesystem.f_type != TITAN_CONFIGFS_MAGIC ? -1 : 0;
}

int titan_usb_prepare(struct titan_usb *owner, const char **reason)
{
    struct timespec deadline;
    if (getpid() != 1 || owner == NULL || owner->tty_fd != -1 || owner->directory || owner->mounted || owner->gadget)
        return fail(reason, "usb-owner-state-invalid");
    if (deadline_set(&deadline, 30) != 0 || titan_mount_inventory(TITAN_MOUNTS_BASELINE_6, reason) != 0 ||
        !udc_identity() || !text_equals(UDC_FUNCTION, "") || !absent("/sys/class/tty/ttyGS0") || !absent(CONFIG_ROOT))
        return fail(reason, "usb-baseline-or-udc-unavailable");
    if (mkdir(CONFIG_ROOT, 0700) != 0) return fail(reason, "usb-config-directory-failed");
    owner->directory = 1;
    if (mount("configfs", CONFIG_ROOT, "configfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
        return fail(reason, "usb-config-mount-failed");
    owner->mounted = 1;
    if (lstat(CONFIG_ROOT, &owner->mount_identity) != 0 || mount_identity(owner) != 0 || !directory_empty(GADGET_ROOT))
        return fail(reason, "usb-config-not-empty-or-mismatched");
    if (create_gadget(owner) != 0) return fail(reason, "usb-gadget-create-failed");
    owner->tty_fd = open_tty("ttyGS0", &deadline);
    if (owner->tty_fd < 0 || fstat(owner->tty_fd, &owner->tty_identity) != 0 ||
        !attribute_equals("UDC", "") || !text_equals(UDC_FUNCTION, "") || remaining(&deadline) < 0)
        return fail(reason, "usb-prebind-raw-tty-failed");
    owner->prepared = 1;
    return 0;
}

int titan_usb_bind_and_seal(struct titan_usb *owner, const char **reason)
{
    if (getpid() != 1 || owner == NULL || !owner->prepared || owner->bound || owner->readonly || mount_identity(owner) != 0 ||
        !udc_identity() ||
        tty_identity(owner->tty_fd, "ttyGS0", &owner->tty_identity) != 0 || raw_check(owner->tty_fd) != 0 ||
        !attribute_equals("UDC", "") || !text_equals(UDC_FUNCTION, ""))
        return fail(reason, "usb-bind-precondition-failed");
    if (write_attribute("UDC", UDC_NAME "\n") != 0 || !attribute_equals("UDC", UDC_NAME))
        return fail(reason, "usb-bind-failed");
    owner->bound = 1;
    if (mount("configfs", CONFIG_ROOT, "configfs", MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
        return fail(reason, "usb-seal-failed");
    owner->readonly = 1;
    if (titan_mount_inventory(TITAN_MOUNTS_USB_SEALED_7, reason) != 0 ||
        write_attribute("idProduct", "0x0005\n") != EROFS)
        return fail(reason, "usb-seal-verification-failed");
    return titan_usb_recheck(owner, reason);
}

int titan_usb_recheck(struct titan_usb *owner, const char **reason)
{
    if (owner == NULL || !owner->prepared || !owner->bound || !owner->readonly || mount_identity(owner) != 0 ||
        !udc_identity() ||
        titan_mount_inventory(TITAN_MOUNTS_USB_SEALED_7, reason) != 0 ||
        !attribute_equals("UDC", UDC_NAME) || !attribute_equals("functions/acm.usb0/port_num", "0") ||
        tty_identity(owner->tty_fd, "ttyGS0", &owner->tty_identity) != 0 || raw_check(owner->tty_fd) != 0)
        return fail(reason, "usb-steady-state-mismatch");
    return 0;
}

static int remove_child(const char *child, int *owned, int link)
{
    if (!*owned) return 0;
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), GADGET_PATH, child) != 0 || (link ? unlink(path) : rmdir(path)) != 0) return -1;
    *owned = 0;
    return 0;
}

int titan_usb_cleanup(struct titan_usb *owner, const char **reason)
{
    struct timespec deadline;
    if (getpid() != 1 || owner == NULL || deadline_set(&deadline, 15) != 0)
        return fail(reason, "usb-cleanup-state-invalid");
    if (owner->mounted) {
        if (mount_identity(owner) != 0) return fail(reason, "usb-cleanup-mount-mismatch");
        if (owner->readonly) {
            if (mount("configfs", CONFIG_ROOT, "configfs", MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
                return fail(reason, "usb-unseal-failed");
            owner->readonly = 0;
        }
        if (owner->gadget && !attribute_equals("UDC", "")) {
            if (!attribute_equals("UDC", UDC_NAME) || write_attribute("UDC", "\n") != 0)
                return fail(reason, "usb-unbind-failed");
        }
        if ((owner->gadget && !attribute_equals("UDC", "")) || !text_equals(UDC_FUNCTION, ""))
            return fail(reason, "usb-unbind-not-verified");
        owner->bound = 0;
    }
    /* The caller has closed every other TTY FD and reaped every worker. The
     * last owned TTY closes only after unbind; function removal can wait on it. */
    if (owner->tty_fd >= 0) {
        int fd = owner->tty_fd;
        owner->tty_fd = -1;
        if (close(fd) != 0) return fail(reason, "usb-tty-close-failed");
    }
    if (owner->gadget) {
        if (remove_child("configs/c.1/acm.usb0", &owner->linked, 1) != 0 ||
            remove_child("configs/c.1/strings/0x409", &owner->config_strings, 0) != 0 ||
            remove_child("configs/c.1", &owner->configuration, 0) != 0 ||
            remove_child("functions/acm.usb0", &owner->function, 0) != 0 ||
            remove_child("strings/0x409", &owner->strings, 0) != 0 || rmdir(GADGET_PATH) != 0)
            return fail(reason, "usb-owned-object-removal-failed");
        owner->gadget = 0;
    }
    if (owner->mounted) {
        if (!directory_empty(GADGET_ROOT)) return fail(reason, "usb-foreign-object-present");
        while (!absent("/sys/class/tty/ttyGS0"))
            if (pause_probe(&deadline) != 0) return fail(reason, "usb-tty-removal-deadline");
        if (umount(CONFIG_ROOT) != 0) return fail(reason, "usb-config-unmount-failed");
        owner->mounted = 0;
    }
    if (owner->directory) {
        if (rmdir(CONFIG_ROOT) != 0) return fail(reason, "usb-directory-removal-failed");
        owner->directory = 0;
    }
    owner->prepared = 0;
    return remaining(&deadline) > 0 && titan_mount_inventory(TITAN_MOUNTS_BASELINE_6, reason) == 0 ?
        0 : fail(reason, "usb-cleanup-baseline-or-deadline-failed");
}

#ifdef TITAN_USB_PIPELINE_VM_TEST
int titan_usb_vm_open_host(struct titan_usb *owner, const char **reason)
{
    struct timespec deadline;
    if (titan_usb_recheck(owner, reason) != 0 || deadline_set(&deadline, 15) != 0) return -1;
    int fd = open_tty("ttyACM0", &deadline);
    if (fd < 0) return fail(reason, "usb-vm-host-tty-unavailable");
    char interface[PATH_MAX], driver[PATH_MAX], path[PATH_MAX];
    static const char prefix[] = "/sys/devices/platform/dummy_hcd.0/";
    if (realpath("/sys/class/tty/ttyACM0/device", interface) == NULL ||
        strncmp(interface, prefix, sizeof(prefix) - 1) != 0 ||
        path_join(path, sizeof(path), interface, "driver") != 0 || realpath(path, driver) == NULL ||
        strcmp(driver, "/sys/bus/usb/drivers/cdc_acm") != 0 ||
        path_join(path, sizeof(path), interface, "bInterfaceClass") != 0 || !text_equals(path, "02") ||
        path_join(path, sizeof(path), interface, "bInterfaceSubClass") != 0 || !text_equals(path, "02")) goto invalid;
    char *slash = strrchr(interface, '/');
    if (slash == NULL) goto invalid;
    *slash = '\0';
    static const struct { const char *name, *value; } attributes[] = {
        { "idVendor", "1209" }, { "idProduct", "0005" },
        { "manufacturer", "Titan rescue experiment" }, { "product", "Titan read-only acquisition" },
        { "serial", "TITAN-RESCUE-EXPERIMENT-0001" }
    };
    for (size_t i = 0; i < sizeof(attributes) / sizeof(attributes[0]); ++i)
        if (path_join(path, sizeof(path), interface, attributes[i].name) != 0 || !text_equals(path, attributes[i].value)) goto invalid;
    return fd;
invalid:
    close(fd);
    return fail(reason, "usb-vm-host-identity-mismatch");
}
#endif
