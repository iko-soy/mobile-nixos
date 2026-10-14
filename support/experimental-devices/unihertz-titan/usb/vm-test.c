/* SPDX-License-Identifier: MIT
 * Disposable Linux dummy_hcd fixture only. Never link into a phone ramdisk.
 * Configfs writes affect only the synthetic USB controller; no block writes,
 * production source selection, shell, peer commands or executable overrides.
 */
#define _GNU_SOURCE
#if !defined(TITAN_USB_VM_TEST) || !defined(TITAN_RESCUE_VM_TEST)
#error USB callback requires both explicit VM test macros
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define CONFIG_ROOT "/run/usb-config"
#define GADGET_ROOT CONFIG_ROOT "/usb_gadget"
#define UDC_NAME "dummy_udc.0"
#define UDC_FUNCTION "/sys/class/udc/" UDC_NAME "/function"
#define RUN_SECONDS 30
#define CLEANUP_SECONDS 10
#define PATTERN_BYTES 131329U
/* Linux fs/configfs/mount.c; this filesystem magic is not a UAPI definition. */
#define FIXTURE_CONFIGFS_MAGIC 0x62656570

static const char *const cases[] = {
    "valid", "invalid-udc", "empty-configuration", "occupied-udc", "disconnect"
};

struct gadget {
    const char *path;
    int created, strings, configuration, config_strings, function, linked;
};

struct fixture {
    struct timespec deadline;
    struct gadget primary, contender;
    int directory, mounted, readonly;
    int gadget_fd, host_fd;
};

static int deadline_set(struct timespec *deadline, time_t seconds)
{
    if (clock_gettime(CLOCK_MONOTONIC, deadline) != 0)
        return -1;
    deadline->tv_sec += seconds;
    return 0;
}

static int remaining(const struct timespec *deadline)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    int64_t ns = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000000000LL +
                 deadline->tv_nsec - now.tv_nsec;
    if (ns <= 0)
        return -1;
    int64_t milliseconds = (ns + 999999) / 1000000;
    return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static int pause_probe(const struct timespec *deadline)
{
    int left = remaining(deadline);
    if (left < 0)
        return -1;
    int result;
    do {
        result = poll(NULL, 0, left < 10 ? left : 10);
    } while (result < 0 && errno == EINTR && remaining(deadline) > 0);
    return result < 0 || remaining(deadline) < 0 ? -1 : 0;
}

static int path_join(char *output, size_t size, const char *base, const char *child)
{
    int count = snprintf(output, size, "%s/%s", base, child);
    return count < 0 || (size_t)count >= size ? -1 : 0;
}

static int read_text(const char *path, char *output, size_t size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -1;
    size_t length = 0;
    int result = 0;
    for (;;) {
        ssize_t count = read(fd, output + length, size - 1 - length);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) { result = -1; break; }
        if (count == 0)
            break;
        length += (size_t)count;
        if (length == size - 1) { result = -1; break; }
    }
    if (close(fd) != 0)
        result = -1;
    if (result != 0 || memchr(output, '\0', length) != NULL)
        return -1;
    if (length > 0 && output[length - 1] == '\n')
        --length;
    output[length] = '\0';
    return 0;
}

static int text_equals(const char *path, const char *expected)
{
    char value[256];
    return read_text(path, value, sizeof(value)) == 0 && strcmp(value, expected) == 0;
}

/* Return zero or the exact errno from this single configfs attribute write. */
static int write_attribute(const char *base, const char *attribute, const char *value)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), base, attribute) != 0)
        return ENAMETOOLONG;
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return errno;
    size_t length = strlen(value);
    ssize_t count;
    do { count = write(fd, value, length); } while (count < 0 && errno == EINTR);
    int error = count < 0 ? errno : ((size_t)count == length ? 0 : EIO);
    if (close(fd) != 0 && error == 0)
        error = errno;
    return error;
}

static int attribute_equals(const struct gadget *gadget, const char *attribute,
                            const char *expected)
{
    char path[PATH_MAX];
    return path_join(path, sizeof(path), gadget->path, attribute) == 0 &&
           text_equals(path, expected);
}

static int directory_empty(const char *path)
{
    DIR *directory = opendir(path);
    if (directory == NULL)
        return 0;
    int empty = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                empty = 0;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            empty = 0;
            break;
        }
    }
    if (closedir(directory) != 0)
        empty = 0;
    return empty;
}

static int absent(const char *path)
{
    struct stat metadata;
    return lstat(path, &metadata) < 0 && errno == ENOENT;
}

static int mount_index(const char *path, const char *type)
{
    if (strcmp(path, "/") == 0 && (strcmp(type, "rootfs") == 0 ||
        strcmp(type, "ramfs") == 0 || strcmp(type, "tmpfs") == 0)) return 0;
    if (strcmp(path, "/dev") == 0 && strcmp(type, "devtmpfs") == 0) return 1;
    if (strcmp(path, "/proc") == 0 && strcmp(type, "proc") == 0) return 2;
    if (strcmp(path, "/sys") == 0 && strcmp(type, "sysfs") == 0) return 3;
    if (strcmp(path, "/run") == 0 && strcmp(type, "tmpfs") == 0) return 4;
    if (strcmp(path, "/tmp") == 0 && strcmp(type, "tmpfs") == 0) return 5;
    if (strcmp(path, CONFIG_ROOT) == 0 && strcmp(type, "configfs") == 0) return 6;
    return -1;
}

static int option_present(const char *options, const char *wanted)
{
    size_t length = strlen(wanted);
    for (const char *start = options; start != NULL; ) {
        const char *end = strchr(start, ',');
        size_t amount = end == NULL ? strlen(start) : (size_t)(end - start);
        if (amount == length && memcmp(start, wanted, length) == 0)
            return 1;
        start = end == NULL ? NULL : end + 1;
    }
    return 0;
}

static int mount_inventory(int configfs, int readonly)
{
    FILE *stream = fopen("/proc/self/mountinfo", "r");
    if (stream == NULL)
        return -1;
    char line[8192], root[4096], path[4096], type[32], options[1024];
    unsigned seen = 0, count = 0, major_number, minor_number;
    int result = 0;
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *separator = strstr(line, " - ");
        if (++count > (configfs ? 7U : 6U) || separator == NULL || strchr(line, '\n') == NULL ||
            sscanf(line, "%*u %*u %u:%u %4095s %4095s %1023s", &major_number,
                   &minor_number, root, path, options) != 5 ||
            sscanf(separator + 3, "%31s", type) != 1 || major_number != 0 || strcmp(root, "/") != 0) {
            result = -1;
            break;
        }
        int index = mount_index(path, type);
        if (index < 0 || (!configfs && index == 6) || (seen & (1U << index)) != 0) {
            result = -1;
            break;
        }
        seen |= 1U << index;
        if (index != 0 && (!option_present(options, "nosuid") || !option_present(options, "noexec") ||
            (index != 1 && !option_present(options, "nodev")))) {
            result = -1;
            break;
        }
        if (index != 0) {
            int wanted_ro = index == 2 || index == 3 || (index == 6 && readonly);
            if (!option_present(options, wanted_ro ? "ro" : "rw") ||
                option_present(options, wanted_ro ? "rw" : "ro")) {
                result = -1;
                break;
            }
        }
    }
    if (ferror(stream) || seen != (configfs ? 127U : 63U))
        result = -1;
    fclose(stream);
    return result;
}

static const char *selected_case(void)
{
    char command[4096];
    if (read_text("/proc/cmdline", command, sizeof(command)) != 0)
        return NULL;
    const char *selected = NULL;
    char *state = NULL;
    for (char *word = strtok_r(command, " \t\r\n", &state); word != NULL;
         word = strtok_r(NULL, " \t\r\n", &state)) {
        static const char prefix[] = "titan_usb_test=";
        if (strncmp(word, prefix, sizeof(prefix) - 1) != 0)
            continue;
        if (selected != NULL)
            return NULL;
        for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index)
            if (strcmp(word + sizeof(prefix) - 1, cases[index]) == 0)
                selected = cases[index];
        if (selected == NULL)
            return NULL;
    }
    return selected;
}

static int storage_readonly(void)
{
    int fd = open("/dev/vda", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -1;
    struct stat metadata;
    int readonly = 0;
    int result = fstat(fd, &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
                 ioctl(fd, BLKROGET, &readonly) != 0 || readonly != 1 ? -1 : 0;
    if (close(fd) != 0)
        result = -1;
    return result;
}

static int make_child(struct gadget *gadget, const char *name, int *owned)
{
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), gadget->path, name) != 0 || mkdir(path, 0700) != 0)
        return -1;
    *owned = 1;
    return 0;
}

static int create_gadget(struct gadget *gadget, unsigned port, int link_function)
{
    static const struct { const char *name, *value; } attributes[] = {
        { "idVendor", "0x1d6b\n" }, { "idProduct", "0x0104\n" },
        { "bcdUSB", "0x0200\n" }, { "bcdDevice", "0x0100\n" },
        { "bDeviceClass", "0\n" }, { "bDeviceSubClass", "0\n" },
        { "bDeviceProtocol", "0\n" }
    };
    if (mkdir(gadget->path, 0700) != 0)
        return -1;
    gadget->created = 1;
    for (size_t index = 0; index < sizeof(attributes) / sizeof(attributes[0]); ++index)
        if (write_attribute(gadget->path, attributes[index].name, attributes[index].value) != 0)
            return -1;
    if (make_child(gadget, "strings/0x409", &gadget->strings) != 0 ||
        write_attribute(gadget->path, "strings/0x409/manufacturer", "Titan VM fixture\n") != 0 ||
        write_attribute(gadget->path, "strings/0x409/product", "Titan ACM VM only\n") != 0 ||
        write_attribute(gadget->path, "strings/0x409/serialnumber",
                        port == 0 ? "TITAN-ACM-VM-0001\n" : "TITAN-ACM-VM-0002\n") != 0 ||
        make_child(gadget, "configs/c.1", &gadget->configuration) != 0 ||
        make_child(gadget, "configs/c.1/strings/0x409", &gadget->config_strings) != 0 ||
        write_attribute(gadget->path, "configs/c.1/strings/0x409/configuration", "ACM fixture\n") != 0 ||
        write_attribute(gadget->path, "configs/c.1/bmAttributes", "0x80\n") != 0 ||
        write_attribute(gadget->path, "configs/c.1/MaxPower", "50\n") != 0 ||
        make_child(gadget, "functions/acm.usb0", &gadget->function) != 0)
        return -1;
    if (!attribute_equals(gadget, "functions/acm.usb0/port_num", port == 0 ? "0" : "1") ||
        !attribute_equals(gadget, "UDC", ""))
        return -1;
    if (link_function) {
        char path[PATH_MAX], target[PATH_MAX];
        /* Configfs resolves the supplied target with kern_path() at creation
         * time, relative to process cwd, rather than the link's directory. */
        if (path_join(path, sizeof(path), gadget->path, "configs/c.1/acm.usb0") != 0 ||
            path_join(target, sizeof(target), gadget->path, "functions/acm.usb0") != 0 ||
            symlink(target, path) != 0)
            return -1;
        gadget->linked = 1;
    }
    return 0;
}

static int raw_termios(int fd)
{
    struct termios term;
    if (tcgetattr(fd, &term) != 0)
        return -1;
    cfmakeraw(&term);
    term.c_iflag &= ~(IXON | IXOFF | IXANY);
    term.c_cflag &= ~(CRTSCTS | HUPCL);
    term.c_cflag |= CREAD | CLOCAL;
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    if (cfsetispeed(&term, B115200) != 0 || cfsetospeed(&term, B115200) != 0 ||
        tcsetattr(fd, TCSANOW, &term) != 0 || tcgetattr(fd, &term) != 0)
        return -1;
    tcflag_t forbidden_input = IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXOFF | IXANY;
    if ((term.c_iflag & forbidden_input) != 0 || (term.c_oflag & OPOST) != 0 ||
        (term.c_lflag & (ECHO | ECHONL | ICANON | ISIG | IEXTEN)) != 0 ||
        (term.c_cflag & (CSIZE | CREAD | CLOCAL | PARENB | CRTSCTS | HUPCL)) != (CS8 | CREAD | CLOCAL) ||
        term.c_cc[VMIN] != 1 || term.c_cc[VTIME] != 0)
        return -1;
    return 0;
}

static int open_tty(const char *name, const struct timespec *deadline)
{
    char node[64], identity_path[128], identity[64], extra;
    unsigned major_number, minor_number;
    if (snprintf(node, sizeof(node), "/dev/%s", name) >= (int)sizeof(node) ||
        snprintf(identity_path, sizeof(identity_path), "/sys/class/tty/%s/dev", name) >= (int)sizeof(identity_path))
        return -1;
    for (;;) {
        int fd = open(node, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            struct stat metadata;
            if (fstat(fd, &metadata) != 0 || !S_ISCHR(metadata.st_mode) ||
                read_text(identity_path, identity, sizeof(identity)) != 0 ||
                sscanf(identity, "%u:%u%c", &major_number, &minor_number, &extra) != 2 ||
                metadata.st_rdev != makedev(major_number, minor_number) ||
                raw_termios(fd) != 0 || remaining(deadline) < 0) {
                close(fd);
                return -1;
            }
            return fd;
        }
        if (errno != ENOENT && errno != ENODEV)
            return -1;
        if (pause_probe(deadline) != 0)
            return -1;
    }
}

static int host_identity(void)
{
    char interface[PATH_MAX], driver[PATH_MAX], path[PATH_MAX];
    static const char prefix[] = "/sys/devices/platform/dummy_hcd.0/";
    if (realpath("/sys/class/tty/ttyACM0/device", interface) == NULL ||
        strncmp(interface, prefix, sizeof(prefix) - 1) != 0 ||
        path_join(path, sizeof(path), interface, "driver") != 0 || realpath(path, driver) == NULL ||
        strcmp(driver, "/sys/bus/usb/drivers/cdc_acm") != 0 ||
        path_join(path, sizeof(path), interface, "bInterfaceClass") != 0 || !text_equals(path, "02") ||
        path_join(path, sizeof(path), interface, "bInterfaceSubClass") != 0 || !text_equals(path, "02"))
        return -1;
    char *slash = strrchr(interface, '/');
    if (slash == NULL)
        return -1;
    *slash = '\0';
    static const struct { const char *name, *value; } attributes[] = {
        { "idVendor", "1d6b" }, { "idProduct", "0104" },
        { "manufacturer", "Titan VM fixture" }, { "product", "Titan ACM VM only" },
        { "serial", "TITAN-ACM-VM-0001" }
    };
    for (size_t index = 0; index < sizeof(attributes) / sizeof(attributes[0]); ++index)
        if (path_join(path, sizeof(path), interface, attributes[index].name) != 0 ||
            !text_equals(path, attributes[index].value))
            return -1;
    return 0;
}

static int seal_configfs(struct fixture *fixture, int readonly)
{
    unsigned long flags = MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC | (readonly ? MS_RDONLY : 0);
    if (mount("configfs", CONFIG_ROOT, "configfs", flags, NULL) != 0)
        return -1;
    fixture->readonly = readonly;
    if (mount_inventory(1, readonly) != 0)
        return -1;
    if (readonly && write_attribute(fixture->primary.path, "idProduct", "0x0104\n") != EROFS)
        return -1;
    return 0;
}

static unsigned char pattern_byte(size_t index, unsigned seed)
{
    return (unsigned char)(index * 73U + seed + (index / 256U) * 19U);
}

/* Concurrently pump one direction; never write an entire buffer before reading. */
static int exchange(int writer, int reader, const unsigned char *fixed, size_t length,
                    unsigned seed, const struct timespec *deadline)
{
    static const size_t fragments[] = { 1, 2, 7, 31, 63, 64, 65, 127, 255, 256,
        511, 512, 513, 1023, 1024, 4095, 4096, 8191 };
    unsigned char buffer[8192];
    size_t written = 0, received = 0, fragment = 0;
    while (received < length) {
        int timeout = remaining(deadline);
        if (timeout < 0)
            return -1;
        struct pollfd descriptors[2] = {
            { .fd = writer, .events = written < length ? POLLOUT : 0 },
            { .fd = reader, .events = POLLIN }
        };
        int ready = poll(descriptors, 2, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0 || ((descriptors[0].revents | descriptors[1].revents) &
                          (POLLERR | POLLHUP | POLLNVAL)) != 0)
            return -1;
        if ((descriptors[0].revents & POLLOUT) != 0 && written < length) {
            size_t amount = fragments[fragment % (sizeof(fragments) / sizeof(fragments[0]))];
            if (amount > length - written)
                amount = length - written;
            for (size_t index = 0; index < amount; ++index)
                buffer[index] = fixed == NULL ? pattern_byte(written + index, seed) : fixed[written + index];
            ssize_t count = write(writer, buffer, amount);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            if (count <= 0)
                return -1;
            written += (size_t)count;
            ++fragment;
        }
        if ((descriptors[1].revents & POLLIN) != 0) {
            /* One extra byte detects unwanted echo or duplicated stream data. */
            size_t capacity = length - received + 1;
            if (capacity > sizeof(buffer))
                capacity = sizeof(buffer);
            ssize_t count = read(reader, buffer, capacity);
            if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                continue;
            if (count <= 0 || (size_t)count > length - received || (size_t)count > written - received)
                return -1;
            for (ssize_t index = 0; index < count; ++index) {
                unsigned char expected = fixed == NULL ? pattern_byte(received + (size_t)index, seed) :
                                                        fixed[received + (size_t)index];
                if (buffer[index] != expected)
                    return -1;
            }
            received += (size_t)count;
        }
    }
    return written == length && remaining(deadline) > 0 ? 0 : -1;
}

static int exchange_patterns(struct fixture *fixture)
{
    static const unsigned char host_ack[] = { 'H', 'O', 'S', 'T', 0, 0x11, 0x13, 0xFF };
    static const unsigned char gadget_ack[] = { 'G', 'A', 'D', 'G', 0xFF, 0x13, 0x11, 0 };
    if (exchange(fixture->gadget_fd, fixture->host_fd, NULL, PATTERN_BYTES, 17, &fixture->deadline) != 0 ||
        exchange(fixture->host_fd, fixture->gadget_fd, NULL, PATTERN_BYTES + 37U, 193, &fixture->deadline) != 0 ||
        exchange(fixture->host_fd, fixture->gadget_fd, host_ack, sizeof(host_ack), 0, &fixture->deadline) != 0 ||
        exchange(fixture->gadget_fd, fixture->host_fd, gadget_ack, sizeof(gadget_ack), 0, &fixture->deadline) != 0)
        return -1;
    return 0;
}

static int unbind(struct gadget *gadget)
{
    if (!gadget->created)
        return 0;
    if (!attribute_equals(gadget, "UDC", "")) {
        if (!attribute_equals(gadget, "UDC", UDC_NAME) || write_attribute(gadget->path, "UDC", "\n") != 0)
            return -1;
    }
    return attribute_equals(gadget, "UDC", "") ? 0 : -1;
}

static int remove_child(struct gadget *gadget, const char *child, int *owned, int link)
{
    if (!*owned)
        return 0;
    char path[PATH_MAX];
    if (path_join(path, sizeof(path), gadget->path, child) != 0 ||
        (link ? unlink(path) : rmdir(path)) != 0)
        return -1;
    *owned = 0;
    return 0;
}

static int remove_gadget(struct gadget *gadget)
{
    if (!gadget->created)
        return 0;
    if (!attribute_equals(gadget, "UDC", "") ||
        remove_child(gadget, "configs/c.1/acm.usb0", &gadget->linked, 1) != 0 ||
        remove_child(gadget, "configs/c.1/strings/0x409", &gadget->config_strings, 0) != 0 ||
        remove_child(gadget, "configs/c.1", &gadget->configuration, 0) != 0 ||
        remove_child(gadget, "functions/acm.usb0", &gadget->function, 0) != 0 ||
        remove_child(gadget, "strings/0x409", &gadget->strings, 0) != 0 || rmdir(gadget->path) != 0)
        return -1;
    gadget->created = 0;
    return 0;
}

static int cleanup(struct fixture *fixture)
{
    if (deadline_set(&fixture->deadline, CLEANUP_SECONDS) != 0)
        return -1;
    if (fixture->mounted) {
        if ((fixture->readonly && seal_configfs(fixture, 0) != 0) ||
            unbind(&fixture->contender) != 0 || unbind(&fixture->primary) != 0 ||
            !text_equals(UDC_FUNCTION, ""))
            return -1;
    }
    /* Unbinding precedes all final TTY closes and function removal. */
    if (fixture->host_fd >= 0) {
        if (close(fixture->host_fd) != 0)
            return -1;
        fixture->host_fd = -1;
    }
    if (fixture->gadget_fd >= 0) {
        if (close(fixture->gadget_fd) != 0)
            return -1;
        fixture->gadget_fd = -1;
    }
    if (fixture->mounted) {
        if (remaining(&fixture->deadline) < 0 || remove_gadget(&fixture->contender) != 0 ||
            remove_gadget(&fixture->primary) != 0 || !directory_empty(GADGET_ROOT))
            return -1;
        while (!absent("/sys/class/tty/ttyGS0") || !absent("/sys/class/tty/ttyGS1") ||
               !absent("/sys/class/tty/ttyACM0"))
            if (pause_probe(&fixture->deadline) != 0)
                return -1;
        if (umount(CONFIG_ROOT) != 0)
            return -1;
        fixture->mounted = 0;
    }
    if (fixture->directory) {
        if (rmdir(CONFIG_ROOT) != 0)
            return -1;
        fixture->directory = 0;
    }
    return remaining(&fixture->deadline) > 0 && mount_inventory(0, 0) == 0 && storage_readonly() == 0 ? 0 : -1;
}

static int disconnected(struct fixture *fixture)
{
    static const unsigned char prefix_out[] = { 0, 'G', 0x11, 0x13, '\r', '\n', 0xFF, 0x80 };
    static const unsigned char prefix_in[] = { 0xFF, 'H', '\n', '\r', 0x13, 0x11, 0x80, 0 };
    if (exchange(fixture->gadget_fd, fixture->host_fd, prefix_out, sizeof(prefix_out), 0,
                 &fixture->deadline) != 0 ||
        exchange(fixture->host_fd, fixture->gadget_fd, prefix_in, sizeof(prefix_in), 0,
                 &fixture->deadline) != 0)
        return -1;
    /* Submit only a prefix of an intended PATTERN_BYTES transfer. Do not read
     * its host endpoint before disconnecting, submit its remainder, or send an
     * acknowledgement. A successfully queued prefix is not a complete transfer. */
    unsigned char prefix[4096];
    for (size_t index = 0; index < sizeof(prefix); ++index)
        prefix[index] = pattern_byte(index, 49);
    ssize_t submitted;
    for (;;) {
        int timeout = remaining(&fixture->deadline);
        if (timeout < 0)
            return -1;
        struct pollfd writer = { .fd = fixture->gadget_fd, .events = POLLOUT };
        int ready = poll(&writer, 1, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0 || (writer.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            return -1;
        submitted = write(fixture->gadget_fd, prefix, sizeof(prefix));
        if (submitted < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (submitted <= 0 || (size_t)submitted >= PATTERN_BYTES)
            return -1;
        break;
    }
    if (seal_configfs(fixture, 0) != 0 || unbind(&fixture->primary) != 0 ||
        !text_equals(UDC_FUNCTION, ""))
        return -1;
    unsigned hung_up = 0;
    size_t buffered = 0;
    while (hung_up != 3U) {
        int timeout = remaining(&fixture->deadline);
        if (timeout < 0)
            return -1;
        struct pollfd descriptors[2] = {
            { .fd = (hung_up & 1U) ? -1 : fixture->gadget_fd, .events = POLLIN },
            { .fd = (hung_up & 2U) ? -1 : fixture->host_fd, .events = POLLIN }
        };
        int result = poll(descriptors, 2, timeout);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            return -1;
        for (unsigned index = 0; index < 2; ++index) {
            if (descriptors[index].revents & POLLNVAL)
                return -1;
            if (descriptors[index].revents & (POLLIN | POLLHUP | POLLERR)) {
                unsigned char data[4096];
                ssize_t count = read(descriptors[index].fd, data, sizeof(data));
                if (count > 0) {
                    if (index != 1 || (size_t)count > (size_t)submitted - buffered ||
                        memcmp(data, prefix + buffered, (size_t)count) != 0)
                        return -1;
                    buffered += (size_t)count;
                    continue;
                }
                if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
                    continue;
                if ((descriptors[index].revents & (POLLHUP | POLLERR)) == 0 ||
                    (count < 0 && errno != EIO && errno != ENODEV))
                    return -1;
                hung_up |= 1U << index;
            }
        }
    }
    return 0;
}

int titan_rescue_vm_test(void)
{
    const char *name = selected_case();
    struct fixture fixture = {
        .primary = { .path = GADGET_ROOT "/titan-vm-primary" },
        .contender = { .path = GADGET_ROOT "/titan-vm-contender" },
        .gadget_fd = -1, .host_fd = -1
    };
    const char *failure = "fixture-preflight";
    struct utsname kernel;
    if (name == NULL || getpid() != 1) {
        puts("TITAN_USB_VM_FAIL missing-case-or-not-pid-one");
        return 1;
    }
    printf("TITAN_USB_VM_START %s\n", name);
    if (uname(&kernel) != 0)
        goto failed;
    printf("TITAN_USB_VM_KERNEL %s\n", kernel.release);
    if (deadline_set(&fixture.deadline, RUN_SECONDS) != 0 || mount_inventory(0, 0) != 0 ||
        storage_readonly() != 0 || !text_equals(UDC_FUNCTION, "") ||
        !absent("/sys/class/tty/ttyGS0") || !absent("/sys/class/tty/ttyGS1") ||
        !absent("/sys/class/tty/ttyACM0") || mkdir(CONFIG_ROOT, 0700) != 0)
        goto failed;
    fixture.directory = 1;
    failure = "configfs-mount";
    if (mount("configfs", CONFIG_ROOT, "configfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
        goto failed;
    fixture.mounted = 1;
    struct statfs filesystem;
    if (statfs(CONFIG_ROOT, &filesystem) != 0 || filesystem.f_type != FIXTURE_CONFIGFS_MAGIC ||
        mount_inventory(1, 0) != 0 || !directory_empty(GADGET_ROOT))
        goto failed;
    failure = "gadget-create";
    int empty = strcmp(name, "empty-configuration") == 0;
    int occupied = strcmp(name, "occupied-udc") == 0;
    if (create_gadget(&fixture.primary, 0, !empty) != 0 ||
        (occupied && create_gadget(&fixture.contender, 1, 1) != 0))
        goto failed;
    failure = "prebind-raw-tty";
    fixture.gadget_fd = open_tty("ttyGS0", &fixture.deadline);
    if (fixture.gadget_fd < 0 || !attribute_equals(&fixture.primary, "UDC", "") ||
        !text_equals(UDC_FUNCTION, "") || !absent("/sys/class/tty/ttyACM0"))
        goto failed;
    puts("TITAN_USB_VM_RAW_READY");
    failure = "bind-result";
    int invalid = strcmp(name, "invalid-udc") == 0;
    int result = write_attribute(fixture.primary.path, "UDC", invalid ? "titan-invalid-udc\n" : UDC_NAME "\n");
    if (invalid || empty) {
        /* Linux 6.18's match_existing_only reports EBUSY both for no matching
         * UDC and for a configfs bind callback that could not bind its gadget. */
        if (result != EBUSY || !attribute_equals(&fixture.primary, "UDC", "") ||
            !text_equals(UDC_FUNCTION, "") || !absent("/sys/class/tty/ttyACM0"))
            goto failed;
        printf("TITAN_USB_VM_EXPECTED %s bind-rejected\n", name);
    } else {
        if (result != 0 || !attribute_equals(&fixture.primary, "UDC", UDC_NAME))
            goto failed;
        puts("TITAN_USB_VM_BOUND");
        if (occupied) {
            failure = "occupied-udc-result";
            if (write_attribute(fixture.contender.path, "UDC", UDC_NAME "\n") != EBUSY ||
                !attribute_equals(&fixture.contender, "UDC", "") ||
                !attribute_equals(&fixture.primary, "UDC", UDC_NAME))
                goto failed;
            puts("TITAN_USB_VM_EXPECTED occupied-udc second-bind-rejected");
        }
        failure = "readonly-configfs";
        if (seal_configfs(&fixture, 1) != 0 || remaining(&fixture.deadline) < 0)
            goto failed;
        failure = "host-acm-identity-or-raw";
        fixture.host_fd = open_tty("ttyACM0", &fixture.deadline);
        if (fixture.host_fd < 0 || host_identity() != 0)
            goto failed;
        if (strcmp(name, "disconnect") == 0) {
            failure = "disconnect-not-observed";
            if (disconnected(&fixture) != 0)
                goto failed;
            puts("TITAN_USB_VM_EXPECTED disconnect hangup-observed");
        } else {
            failure = "binary-exchange-or-ack";
            if (exchange_patterns(&fixture) != 0)
                goto failed;
        }
    }
    if (remaining(&fixture.deadline) < 0) {
        failure = "runtime-deadline";
        goto failed;
    }
    if (cleanup(&fixture) != 0) {
        puts("TITAN_USB_VM_FAIL cleanup");
        return 1;
    }
    printf("TITAN_USB_VM_PASS %s\n", name);
    if (fflush(stdout) != 0 || reboot(RB_POWER_OFF) < 0) {
        puts("TITAN_USB_VM_FAIL vm-poweroff");
        return 1;
    }
    puts("TITAN_USB_VM_FAIL vm-poweroff-returned");
    return 1;

failed:
    printf("TITAN_USB_VM_FAIL %s\n", failure);
    if (cleanup(&fixture) != 0)
        puts("TITAN_USB_VM_FAIL cleanup");
    return 1;
}
