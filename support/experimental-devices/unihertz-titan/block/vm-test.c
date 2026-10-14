/* SPDX-License-Identifier: MIT
 * Full synthetic VM pipeline. Every mutation is confined to disposable guest state.
 */
#define _GNU_SOURCE
#if !defined(TITAN_BLOCK_VM_TEST) || !defined(TITAN_RESCUE_VM_TEST) || !defined(TITAN_SOURCE_VM_TEST)
#error Block pipeline callback requires all three explicit VM test macros
#endif
#include "guard.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/serial.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static const char *const cases[] = {
    "valid", "dirty-filesystem", "wrong-label", "output-limit", "post-readonly-change"
};

static double now(void)
{
    struct timespec value;
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0
        ? value.tv_sec + value.tv_nsec / 1000000000.0 : -1;
}

static const char *selected_case(void)
{
    char command[4096], *save = NULL;
    FILE *stream = fopen("/proc/cmdline", "r");
    if (stream == NULL)
        return NULL;
    size_t length = fread(command, 1, sizeof(command), stream);
    int invalid = ferror(stream) || length == sizeof(command) || memchr(command, 0, length) != NULL;
    fclose(stream);
    if (invalid)
        return NULL;
    command[length] = 0;
    const char *chosen = NULL;
    for (char *word = strtok_r(command, " \r\n\t", &save); word; word = strtok_r(NULL, " \r\n\t", &save)) {
        if (strncmp(word, "titan.block_case=", 17) != 0)
            continue;
        if (chosen != NULL)
            return NULL;
        for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index)
            if (strcmp(word + 17, cases[index]) == 0)
                chosen = cases[index];
        if (chosen == NULL)
            return NULL;
    }
    return chosen;
}

static int fail(const char *name, const char *reason)
{
    printf("TITAN_BLOCK_VM_FAIL %s %s\n", name, reason);
    return 1;
}

static int exclusive(const char *path, int busy)
{
    errno = 0;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_EXCL);
    int error = errno;
    if (descriptor >= 0)
        close(descriptor);
    return busy ? descriptor < 0 && error == EBUSY : descriptor >= 0;
}

static int clear_readonly(void)
{
    const char *paths[] = { "/dev/vda", "/dev/vda1" };
    for (unsigned index = 0; index < 2; ++index) {
        int descriptor = open(paths[index], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        int value = 1;
        struct stat metadata;
        if (descriptor < 0)
            return 0;
        int invalid = fstat(descriptor, &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
                      ioctl(descriptor, BLKROGET, &value) != 0 || value != 1;
        value = 0;
        invalid = invalid || ioctl(descriptor, BLKROSET, &value) != 0 ||
                  ioctl(descriptor, BLKROGET, &value) != 0 || value != 0;
        close(descriptor);
        if (invalid)
            return 0;
    }
    return 1;
}

static void child_fds(const int *all, int first, int second, int third)
{
    for (unsigned index = 0; index < 7; ++index) {
        int descriptor = all[index];
        if (descriptor == first || descriptor == second || descriptor == third) {
            if (fcntl(descriptor, F_SETFD, 0) != 0)
                _exit(127);
        } else {
            close(descriptor);
        }
    }
}

static void stop_children(pid_t *children, int *statuses)
{
    for (unsigned index = 0; index < 2; ++index)
        if (children[index] > 0 && statuses[index] < 0)
            (void) kill(children[index], SIGTERM);
    double deadline = now() + 2;
    while (now() > 0 && now() < deadline) {
        unsigned pending = 0;
        for (unsigned index = 0; index < 2; ++index) {
            if (children[index] <= 0 || statuses[index] >= 0)
                continue;
            int status;
            if (waitpid(children[index], &status, WNOHANG) == children[index])
                statuses[index] = status;
            else
                ++pending;
        }
        if (pending == 0)
            return;
        (void) poll(NULL, 0, 10);
    }
    for (unsigned index = 0; index < 2; ++index)
        if (children[index] > 0 && statuses[index] < 0)
            (void) kill(children[index], SIGKILL);
}

int titan_rescue_vm_test(void)
{
    const char *name = selected_case(), *reason = NULL;
    if (name == NULL)
        return fail("unknown", "invalid-case");
    int successful = strcmp(name, "valid") == 0;
    int mutate = strcmp(name, "post-readonly-change") == 0;
    struct titan_source source = TITAN_SOURCE_INITIALIZER;
    int preflight = titan_source_open(&source, &reason);
    titan_source_close(&source);
    if (strcmp(name, "wrong-label") == 0) {
        if (preflight == 0 || reason == NULL || strcmp(reason, "partition-identity-mismatch") != 0)
            return fail(name, "wrong-label-preflight-mismatch");
    } else if (preflight != 0) {
        printf("TITAN_BLOCK_VM_OBSERVED %s\n", reason ? reason : "missing-reason");
        return fail(name, "source-preflight-failed");
    }
    if (mutate && (rename("/bin/zstd", "/bin/zstd-real") != 0 ||
                   rename("/bin/hold-zstd", "/bin/zstd") != 0))
        return fail(name, "compressor-gate-install-failed");

    int terminal = open("/dev/ttyS1", O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    struct termios raw;
    if (terminal < 0 || !isatty(terminal) || tcgetattr(terminal, &raw) != 0)
        return fail(name, "transfer-terminal-unavailable");
    cfmakeraw(&raw);
    raw.c_iflag &= ~(IXON | IXOFF | IXANY);
    raw.c_cflag &= ~CRTSCTS;
    raw.c_cflag |= CREAD | CLOCAL;
    if (ioctl(terminal, TIOCEXCL) != 0 || cfsetispeed(&raw, B115200) != 0 || cfsetospeed(&raw, B115200) != 0 ||
        tcsetattr(terminal, TCSANOW, &raw) != 0)
        return fail(name, "transfer-terminal-raw-failed");
    int data[2], status[2], relay[2];
    if (pipe2(data, O_CLOEXEC) != 0 || pipe2(status, O_CLOEXEC) != 0 || pipe2(relay, O_CLOEXEC) != 0)
        return fail(name, "fixture-pipes-failed");
    int all[] = { data[0], data[1], status[0], status[1], relay[0], relay[1], terminal };
    char data_read[24], data_write[24], status_write[24], status_read[24], tty_number[24];
    snprintf(data_read, sizeof(data_read), "%d", data[0]);
    snprintf(data_write, sizeof(data_write), "%d", data[1]);
    snprintf(status_write, sizeof(status_write), "%d", status[1]);
    snprintf(status_read, sizeof(status_read), "%d", relay[0]);
    snprintf(tty_number, sizeof(tty_number), "%d", terminal);
    pid_t children[2] = { -1, -1 };
    int statuses[2] = { -1, -1 };
    children[0] = fork();
    if (children[0] == 0) {
        child_fds(all, data[1], status[1], -1);
        execl("/bin/titan-block-produce", "/bin/titan-block-produce", "--output-fd", data_write,
              "--status-fd", status_write, "--max-bytes", strcmp(name, "output-limit") == 0 ? "1" : "33554432",
              "--timeout-seconds", "25", (char *) NULL);
        _exit(127);
    }
    if (children[0] > 0)
        children[1] = fork();
    if (children[1] == 0) {
        child_fds(all, data[0], relay[0], terminal);
        execl("/bin/titan-rescue-send", "/bin/titan-rescue-send", "--input-fd", data_read,
              "--status-fd", status_read, "--transport-fd", tty_number, "--label", "block-fixture",
              "--max-bytes", "33554432", "--timeout-seconds", "35", (char *) NULL);
        _exit(127);
    }
    close(data[0]); close(data[1]); close(status[1]); close(relay[0]);
    if (children[0] <= 0 || children[1] <= 0) {
        stop_children(children, statuses);
        return fail(name, "fixture-fork-failed");
    }
    int flags = fcntl(status[0], F_GETFL);
    if (flags < 0 || fcntl(status[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        stop_children(children, statuses);
        return fail(name, "status-nonblocking-failed");
    }
    (void) signal(SIGPIPE, SIG_IGN);
    printf("TITAN_BLOCK_VM_TRANSFER_READY %s\n", name);
    fflush(stdout);
    unsigned char receipt[9];
    size_t received = 0, forwarded = 0;
    int eof = 0, relay_closed = 0, changed = 0, failed = 0;
    double deadline = now() + 40;
    while (now() > 0 && now() < deadline) {
        if (mutate && !changed) {
            struct stat metadata;
            if (lstat("/run/compressor-ready", &metadata) == 0) {
                if (!S_ISREG(metadata.st_mode) || metadata.st_size != 0 ||
                    !exclusive("/dev/vda", 1) || !clear_readonly()) {
                    failed = 1;
                    break;
                }
                int marker = open("/run/compressor-release", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
                if (marker < 0) { failed = 1; break; }
                close(marker);
                changed = 1;
                puts("TITAN_BLOCK_VM_POST_GUARD_CHANGED");
            }
        }
        struct pollfd request = { .fd = eof ? -1 : status[0], .events = POLLIN };
        if (poll(&request, 1, 10) < 0 && errno != EINTR) { failed = 1; break; }
        if (!eof && (request.revents & (POLLIN | POLLHUP))) {
            ssize_t amount = read(status[0], receipt + received, sizeof(receipt) - received);
            if (amount == 0)
                eof = 1;
            else if (amount > 0)
                received += (size_t) amount;
            else if (errno != EAGAIN && errno != EINTR) { failed = 1; break; }
            if (received > 8) { failed = 1; break; }
        }
        if (forwarded < received) {
            ssize_t amount = write(relay[1], receipt + forwarded, received - forwarded);
            if (amount <= 0) { failed = 1; break; }
            forwarded += (size_t) amount;
        }
        if (eof && !relay_closed && forwarded == received) {
            close(relay[1]);
            relay_closed = 1;
        }
        for (unsigned index = 0; index < 2; ++index) {
            if (statuses[index] < 0) {
                int child_status;
                pid_t waited = waitpid(children[index], &child_status, WNOHANG);
                if (waited == children[index])
                    statuses[index] = child_status;
                else if (waited < 0 && errno != EINTR)
                    failed = 1;
            }
        }
        if (failed)
            break;
        if (statuses[0] >= 0 && statuses[1] >= 0 && eof && relay_closed)
            break;
    }
    close(status[0]);
    if (!relay_closed)
        close(relay[1]);
    if (failed || statuses[0] < 0 || statuses[1] < 0) {
        stop_children(children, statuses);
        close(terminal);
        return fail(name, "pipeline-status-or-deadline-failed");
    }
    unsigned expected = successful ? 0 : strcmp(name, "output-limit") == 0 ? 4 : 2;
    unsigned recorded = received == 8 ? ((unsigned) receipt[4] << 24) | ((unsigned) receipt[5] << 16) |
                        ((unsigned) receipt[6] << 8) | receipt[7] : 255;
    if (received != 8 || memcmp(receipt, "TPST", 4) != 0 || recorded != expected ||
        !WIFEXITED(statuses[0]) || (unsigned) WEXITSTATUS(statuses[0]) != expected ||
        !WIFEXITED(statuses[1]) || WEXITSTATUS(statuses[1]) != (successful ? 0 : 5) ||
        (mutate && !changed)) {
        printf("TITAN_BLOCK_VM_OBSERVED producer_status=%d sender_status=%d receipt_bytes=%zu receipt_status=%u changed=%d\n",
               statuses[0], statuses[1], received, recorded, changed);
        close(terminal);
        return fail(name, "unexpected-pipeline-result");
    }
    if (!exclusive("/dev/vda1", 0) || !exclusive("/dev/vda", 0)) {
        close(terminal);
        return fail(name, "pipeline-left-source-claimed");
    }
    /* Bound UART drain without an unbounded tcdrain: wait for both the kernel
     * queue and the 16550 transmitter to empty before shutting down this VM. */
    int drained = 0;
    while (now() > 0 && now() < deadline) {
        int queued = -1, transmitter = 0;
        if (ioctl(terminal, TIOCOUTQ, &queued) != 0 || ioctl(terminal, TIOCSERGETLSR, &transmitter) != 0)
            break;
        if (queued == 0 && (transmitter & TIOCSER_TEMT)) { drained = 1; break; }
        (void) poll(NULL, 0, 10);
    }
    close(terminal);
    if (!drained)
        return fail(name, "fixture-uart-not-drained");
    printf("TITAN_BLOCK_VM_STATUS %s producer=%u sender=%u status=%u\n", name, expected,
           successful ? 0U : 5U, recorded);
    printf("TITAN_BLOCK_VM_PASS %s\n", name);
    if (fflush(stdout) != 0 || reboot(RB_POWER_OFF) < 0)
        return fail(name, "fixture-poweroff-failed");
    return fail(name, "fixture-poweroff-returned");
}
