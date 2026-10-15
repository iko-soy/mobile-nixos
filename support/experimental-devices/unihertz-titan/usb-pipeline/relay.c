/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "relay.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#define DEVICE_WIRE_LIMIT (64ULL * 1024 * 1024)
#define HOST_WIRE_LIMIT 16384ULL

static int failed(struct titan_usb_vm_relay *relay, const char **reason, const char *message)
{
    relay->failed = 1;
    if (reason != NULL)
        *reason = message;
    return -1;
}

static int raw_check(int descriptor)
{
    struct termios settings;
    if (tcgetattr(descriptor, &settings) != 0)
        return -1;
    tcflag_t forbidden = IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXOFF | IXANY;
    return (settings.c_iflag & forbidden) || (settings.c_oflag & OPOST) ||
        (settings.c_lflag & (ECHO | ECHONL | ICANON | ISIG | IEXTEN)) ||
        (settings.c_cflag & (CSIZE | CREAD | CLOCAL | PARENB | CRTSCTS | HUPCL)) != (CS8 | CREAD | CLOCAL) ||
        settings.c_cc[VMIN] != 1 || settings.c_cc[VTIME] != 0 ? -1 : 0;
}

static int raw_uart(const char *path)
{
    struct stat metadata, node;
    struct termios settings;
    int descriptor = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return -1;
    if (lstat(path, &node) != 0 || fstat(descriptor, &metadata) != 0 ||
        !S_ISCHR(metadata.st_mode) || !S_ISCHR(node.st_mode) ||
        metadata.st_rdev != node.st_rdev || !isatty(descriptor) ||
        ioctl(descriptor, TIOCEXCL) != 0 || tcgetattr(descriptor, &settings) != 0)
        goto bad;
    cfmakeraw(&settings);
    settings.c_iflag &= ~(IXON | IXOFF | IXANY);
    settings.c_cflag &= ~(CRTSCTS | HUPCL);
    settings.c_cflag |= CREAD | CLOCAL;
    settings.c_cc[VMIN] = 1;
    settings.c_cc[VTIME] = 0;
    if (cfsetispeed(&settings, B115200) != 0 || cfsetospeed(&settings, B115200) != 0 ||
        tcsetattr(descriptor, TCSANOW, &settings) != 0 || raw_check(descriptor) != 0)
        goto bad;
    return descriptor;
bad:
    close(descriptor);
    return -1;
}

int titan_usb_vm_relay_init(struct titan_usb_vm_relay *relay, int acm_fd, const char **reason)
{
    struct stat metadata, node;
    if (relay == NULL)
        return -1;
    *relay = (struct titan_usb_vm_relay)TITAN_USB_VM_RELAY_INITIALIZER;
    if (reason != NULL)
        *reason = NULL;
    int flags = fcntl(acm_fd, F_GETFL);
    if (acm_fd < 3 || flags < 0 || (flags & O_ACCMODE) != O_RDWR || !(flags & O_NONBLOCK) ||
        lstat("/dev/ttyACM0", &node) != 0 || fstat(acm_fd, &metadata) != 0 ||
        !S_ISCHR(node.st_mode) || !S_ISCHR(metadata.st_mode) || metadata.st_rdev != node.st_rdev ||
        !isatty(acm_fd) || raw_check(acm_fd) != 0)
        return failed(relay, reason, "relay-acm-not-raw-nonblocking");
    relay->acm_fd = acm_fd;
    relay->uart_fd = raw_uart("/dev/ttyS1");
    relay->control_fd = raw_uart("/dev/ttyS2");
    if (relay->uart_fd < 0 || relay->control_fd < 0) {
        titan_usb_vm_relay_close(relay);
        return failed(relay, reason, "relay-uart-setup-failed");
    }
    return 0;
}

static size_t room(struct titan_vm_queue *queue)
{
    if (queue->offset + queue->length == sizeof(queue->bytes) && queue->offset != 0) {
        memmove(queue->bytes, queue->bytes + queue->offset, queue->length);
        queue->offset = 0;
    }
    return sizeof(queue->bytes) - queue->offset - queue->length;
}

static int read_queue(int descriptor, struct titan_vm_queue *queue, uint64_t *total, uint64_t limit)
{
    size_t available = room(queue);
    if (available == 0)
        return 0;
    if (available > limit - *total + 1)
        available = (size_t)(limit - *total + 1);
    ssize_t count = read(descriptor, queue->bytes + queue->offset + queue->length, available);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    if (count <= 0 || (uint64_t)count > limit - *total)
        return -1;
    queue->length += (size_t)count;
    *total += (uint64_t)count;
    return 0;
}

static int write_queue(int descriptor, struct titan_vm_queue *queue, uint64_t *total)
{
    if (queue->length == 0)
        return 0;
    ssize_t count = write(descriptor, queue->bytes + queue->offset, queue->length);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    if (count <= 0)
        return -1;
    queue->offset += (size_t)count;
    queue->length -= (size_t)count;
    *total += (uint64_t)count;
    if (queue->length == 0)
        queue->offset = 0;
    return 0;
}

static int read_control(struct titan_usb_vm_relay *relay)
{
    if (relay->control_used == sizeof(relay->control))
        return -1;
    ssize_t count = read(relay->control_fd, relay->control + relay->control_used,
                         sizeof(relay->control) - relay->control_used);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    if (count <= 0 || relay->receipt != TITAN_VM_RECEIPT_NONE)
        return -1;
    relay->control_used += (size_t)count;
    if (memchr(relay->control, '\n', relay->control_used) == NULL)
        return relay->control_used == sizeof(relay->control) ? -1 : 0;
    static const char *const values[] = { "TVM1 VERIFIED\n", "TVM1 INCOMPLETE\n", "TVM1 ABORT\n" };
    for (unsigned index = 0; index < sizeof(values) / sizeof(values[0]); ++index) {
        if (relay->control_used == strlen(values[index]) &&
            memcmp(relay->control, values[index], relay->control_used) == 0) {
            relay->receipt = (enum titan_vm_receipt)(TITAN_VM_RECEIPT_VERIFIED + index);
            return 0;
        }
    }
    return -1;
}

int titan_usb_vm_relay_step(struct titan_usb_vm_relay *relay, const char **reason)
{
    if (relay == NULL)
        return -1;
    if (relay->failed || relay->acm_fd < 0 || relay->uart_fd < 0 || relay->control_fd < 0)
        return failed(relay, reason, "relay-state-invalid");
    struct pollfd requests[] = {
        { .fd = relay->acm_fd, .events = (room(&relay->to_host) ? POLLIN : 0) |
                                       (relay->to_gadget.length ? POLLOUT : 0) },
        { .fd = relay->uart_fd, .events = (room(&relay->to_gadget) ? POLLIN : 0) |
                                        (relay->to_host.length ? POLLOUT : 0) },
        { .fd = relay->control_fd, .events = POLLIN }
    };
    int ready = poll(requests, sizeof(requests) / sizeof(requests[0]), 0);
    if (ready < 0 && errno == EINTR)
        return 0;
    if (ready < 0)
        return failed(relay, reason, "relay-poll-failed");
    for (unsigned index = 0; index < sizeof(requests) / sizeof(requests[0]); ++index)
        if (requests[index].revents & (POLLERR | POLLHUP | POLLNVAL))
            return failed(relay, reason, "relay-terminal-disconnected");
    if ((requests[0].revents & POLLOUT) && write_queue(relay->acm_fd, &relay->to_gadget, &relay->acm_written))
        return failed(relay, reason, "relay-acm-write-failed");
    if ((requests[1].revents & POLLOUT) && write_queue(relay->uart_fd, &relay->to_host, &relay->uart_written))
        return failed(relay, reason, "relay-uart-write-failed");
    if ((requests[0].revents & POLLIN) && read_queue(relay->acm_fd, &relay->to_host, &relay->acm_read, DEVICE_WIRE_LIMIT))
        return failed(relay, reason, "relay-acm-read-or-bound-failed");
    if ((requests[1].revents & POLLIN) && read_queue(relay->uart_fd, &relay->to_gadget, &relay->uart_read, HOST_WIRE_LIMIT))
        return failed(relay, reason, "relay-uart-read-or-bound-failed");
    if ((requests[2].revents & POLLIN) && read_control(relay))
        return failed(relay, reason, "relay-control-invalid");
    return 0;
}

int titan_usb_vm_relay_drained(const struct titan_usb_vm_relay *relay)
{
    return relay != NULL && !relay->failed && relay->to_host.length == 0 && relay->to_gadget.length == 0 &&
           relay->acm_read == relay->uart_written && relay->uart_read == relay->acm_written;
}

void titan_usb_vm_relay_close(struct titan_usb_vm_relay *relay)
{
    if (relay == NULL)
        return;
    if (relay->uart_fd >= 0) {
        (void)ioctl(relay->uart_fd, TIOCNXCL);
        close(relay->uart_fd);
        relay->uart_fd = -1;
    }
    if (relay->control_fd >= 0) {
        (void)ioctl(relay->control_fd, TIOCNXCL);
        close(relay->control_fd);
        relay->control_fd = -1;
    }
    relay->acm_fd = -1;
}
