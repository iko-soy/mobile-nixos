/* SPDX-License-Identifier: MIT
 * Control acquisition inside the probe profile's PID 1. After the storage guard
 * and the gadget bind, start the fixed region producer and the unchanged TTR1
 * sender, relay the producer's status record to the sender, and restart into
 * the bootloader once the host has acknowledged the transfer or soon after the
 * attempt has failed. The probe's separate deadline process restarts the phone
 * regardless. No peer input selects a source, program or action.
 * The VM-only branch bridges the guest's own host ACM port to a QEMU UART.
 */
#define _GNU_SOURCE
#if !defined(TITAN_USB_CONTROL_PROFILE) || !defined(TITAN_USB_PROBE_PROFILE)
#error The control pipeline requires the control and probe profiles
#endif
#include "owner.h"
#ifdef TITAN_USB_PROBE_VM_TEST
#include "relay.h"
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void titan_usb_probe_tick(void);
_Noreturn void titan_usb_probe_restart(void);

#ifdef TITAN_USB_PROBE_VM_TEST
#define BYTE_CAP "33554432"
/* Longer than the producer's limit plus the sender's grace, as on the phone. */
#define PRODUCER_SECONDS "60"
#define SENDER_SECONDS "90"
#else
/* Limits, not throughput promises: 771719168 region bytes plus the manifest,
 * inside the probe's 1800-second deadline. */
#define BYTE_CAP "1073741824"
#define PRODUCER_SECONDS "1700"
#define SENDER_SECONDS "1740"
#endif
#define TRANSFER_LABEL "control-regions-raw"
#define SUCCESS_GRACE_MS 5000
#define FAILURE_GRACE_MS 10000
/* After a failed producer, time for the sender to report the error to a
 * listening host before it is stopped. */
#define SENDER_GRACE_MS 20000
#define REAP_LIMIT_MS 5000

static void close_fd(int *fd)
{
    if (*fd >= 0) close(*fd);
    *fd = -1;
}

static int nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ? -1 : 0;
}

static long long milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) return -1;
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* Child side: default signals, and only the named descriptors survive exec. */
static void child_descriptors(int first, int second, int third)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigset_t none;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGHUP, &action, NULL) != 0 ||
        sigaction(SIGPIPE, &action, NULL) != 0 || sigaction(SIGCHLD, &action, NULL) != 0 ||
        sigaction(SIGALRM, &action, NULL) != 0 ||
        sigemptyset(&none) != 0 || sigprocmask(SIG_SETMASK, &none, NULL) != 0) _exit(127);
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) _exit(127);
    int descriptors[256];
    size_t count = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) { if (errno) _exit(127); break; }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char *end;
        errno = 0;
        long fd = strtol(entry->d_name, &end, 10);
        if (errno || !*entry->d_name || *end || fd < 0 || fd > INT_MAX || count == 256) _exit(127);
        if (fd != dirfd(directory)) descriptors[count++] = (int)fd;
    }
    if (closedir(directory) != 0) _exit(127);
    for (size_t i = 0; i < count; ++i) {
        int fd = descriptors[i];
        if (fd == first || fd == second || fd == third) {
            if (fd <= STDERR_FILENO || fcntl(fd, F_SETFD, 0) != 0) _exit(127);
        } else if (fd != STDOUT_FILENO && fd != STDERR_FILENO) close(fd);
    }
}

static void wait_ticking(int limit)
{
    for (int waited = 0; waited < limit; waited += 100) {
        titan_usb_probe_tick();
        (void)poll(NULL, 0, 100);
    }
}

static int failed_exit(int status)
{
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

#ifdef TITAN_USB_PROBE_VM_TEST
/* Sectors read through each fixture partition, so the host can confirm that
 * both passes reached the disk instead of the page cache. */
static void vm_read_counters(void)
{
    for (int number = 1; number <= 16; ++number) {
        char path[64], text[256];
        unsigned long long reads, merged, sectors;
        snprintf(path, sizeof(path), "/sys/class/block/vda%d/stat", number);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t count = fd < 0 ? -1 : read(fd, text, sizeof(text) - 1);
        if (fd >= 0) close(fd);
        if (count <= 0) continue;
        text[count] = '\0';
        if (sscanf(text, "%llu %llu %llu", &reads, &merged, &sectors) == 3)
            printf("TITAN_CONTROL_VM_READ %d %llu\n", number, sectors);
    }
}
#endif

int titan_usb_control_run(struct titan_usb *usb)
{
    int data[2] = { -1, -1 }, status[2] = { -1, -1 }, relay[2] = { -1, -1 };
    pid_t workers[2] = { -1, -1 };
    int results[2] = { -1, -1 }, done[2] = { 0, 0 }, status_eof = 0;
    long long producer_failed_at = -1, stopping_at = -1;
    unsigned char record[9];
    size_t received = 0, forwarded = 0;
    const char *reason = "control-preflight";
#ifdef TITAN_USB_PROBE_VM_TEST
    struct titan_usb_vm_relay bridge = TITAN_USB_VM_RELAY_INITIALIZER;
    int host = titan_usb_vm_open_host(usb, &reason);
    if (host < 0 || titan_usb_vm_relay_init(&bridge, host, &reason) != 0) goto failed;
#endif
    if (pipe2(data, O_CLOEXEC) != 0 || pipe2(status, O_CLOEXEC) != 0 || pipe2(relay, O_CLOEXEC) != 0 ||
        nonblocking(status[0]) != 0 || nonblocking(relay[1]) != 0) { reason = "control-pipes-failed"; goto failed; }
    char data_read[24], data_write[24], status_write[24], status_read[24], tty_number[24];
    snprintf(data_read, sizeof(data_read), "%d", data[0]);
    snprintf(data_write, sizeof(data_write), "%d", data[1]);
    snprintf(status_write, sizeof(status_write), "%d", status[1]);
    snprintf(status_read, sizeof(status_read), "%d", relay[0]);
    snprintf(tty_number, sizeof(tty_number), "%d", usb->tty_fd);
    char *const environment[] = { "PATH=/bin", "LC_ALL=C", NULL };
    workers[0] = fork();
    if (workers[0] == 0) {
        child_descriptors(data[1], status[1], -1);
        char *const arguments[] = { "/bin/titan-control-produce", "--output-fd", data_write,
            "--status-fd", status_write, "--max-bytes", BYTE_CAP, "--timeout-seconds", PRODUCER_SECONDS, NULL };
        execve(arguments[0], arguments, environment);
        _exit(127);
    }
    if (workers[0] < 0) { reason = "control-fork-failed"; goto failed; }
    workers[1] = fork();
    if (workers[1] == 0) {
        child_descriptors(data[0], relay[0], usb->tty_fd);
        char *const arguments[] = { "/bin/titan-rescue-send", "--input-fd", data_read,
            "--status-fd", status_read, "--transport-fd", tty_number, "--label", TRANSFER_LABEL,
            "--max-bytes", BYTE_CAP, "--timeout-seconds", SENDER_SECONDS, NULL };
        execve(arguments[0], arguments, environment);
        _exit(127);
    }
    if (workers[1] < 0) { reason = "control-fork-failed"; goto failed; }
    close_fd(&data[0]); close_fd(&data[1]); close_fd(&status[1]); close_fd(&relay[0]);
    puts("TITAN_CONTROL_TRANSFER_READY");
    while (!done[0] || !done[1]) {
        long long now = milliseconds();
        if (now < 0) { reason = "clock-failed"; goto failed; }
        /* Relay the producer's eight-byte status record to the sender. */
        if (!status_eof) {
            ssize_t count = read(status[0], record + received, sizeof(record) - received);
            if (count == 0) { status_eof = 1; close_fd(&status[0]); }
            else if (count > 0) received += (size_t)count;
            else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) { reason = "status-read-failed"; goto failed; }
            if (received > 8) { reason = "status-too-long"; goto failed; }
        }
        if (forwarded < received) {
            ssize_t count = write(relay[1], record + forwarded, received - forwarded);
            if (count > 0) forwarded += (size_t)count;
            else if (count == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                reason = "status-forward-failed"; goto failed;
            }
        }
        if (status_eof && forwarded == received) close_fd(&relay[1]);
        for (int i = 0; i < 2; ++i) {
            if (done[i]) continue;
            pid_t reaped = waitpid(workers[i], &results[i], WNOHANG);
            if (reaped == workers[i]) done[i] = 1;
            else if (reaped < 0 && errno != EINTR) { reason = "worker-wait-failed"; goto failed; }
        }
        /* A failed sender stops the producer at once; a failed producer leaves
         * the sender a bounded time to report the error before it is stopped.
         * Both are then reaped here, within a bound, so the result is reported. */
        if (stopping_at < 0 && done[1] && !done[0] && failed_exit(results[1])) {
            (void)kill(workers[0], SIGKILL);
            stopping_at = now;
        }
        if (done[0] && producer_failed_at < 0 && failed_exit(results[0])) producer_failed_at = now;
        if (stopping_at < 0 && producer_failed_at >= 0 && !done[1] && now - producer_failed_at >= SENDER_GRACE_MS) {
            (void)kill(workers[1], SIGKILL);
            stopping_at = now;
        }
        if (stopping_at >= 0 && (!done[0] || !done[1]) && now - stopping_at >= REAP_LIMIT_MS) {
            reason = "worker-not-reaped"; goto failed;
        }
#ifdef TITAN_USB_PROBE_VM_TEST
        if (titan_usb_vm_relay_step(&bridge, &reason) != 0) goto failed;
#endif
        titan_usb_probe_tick();
        (void)poll(NULL, 0, 10);
    }
    unsigned code = received == 8 && memcmp(record, "TPST", 4) == 0 ?
        ((unsigned)record[4] << 24 | (unsigned)record[5] << 16 | (unsigned)record[6] << 8 | record[7]) : UINT_MAX;
    printf("TITAN_CONTROL_RESULT producer-status=%u producer=%d sender=%d\n", code, results[0], results[1]);
    if (code != 0 || failed_exit(results[0]) || failed_exit(results[1])) { reason = "worker-result-nonzero"; goto failed; }
    /* The sender exits zero only after the host's ACK, which follows its own
     * count, hash, sync and readback checks; then it sends COMPLETE. */
    puts("TITAN_CONTROL_COMPLETE");
#ifdef TITAN_USB_PROBE_VM_TEST
    vm_read_counters();
    for (int waited = 0; waited < 30000 && !(bridge.receipt == TITAN_VM_RECEIPT_VERIFIED &&
                                            titan_usb_vm_relay_drained(&bridge)); waited += 10) {
        if (titan_usb_vm_relay_step(&bridge, &reason) != 0) goto failed;
        titan_usb_probe_tick();
        (void)poll(NULL, 0, 10);
    }
    printf("TITAN_CONTROL_VM_RECEIPT %s\n", bridge.receipt == TITAN_VM_RECEIPT_VERIFIED ? "VERIFIED" : "MISSING");
#endif
    wait_ticking(SUCCESS_GRACE_MS);
#ifdef TITAN_USB_PROBE_VM_TEST
    puts("TITAN_CONTROL_VM_RESTART success");
#endif
    titan_usb_probe_restart();

failed:
    printf("TITAN_CONTROL_FAILED %s\n", reason ? reason : "unspecified");
    /* Stop whatever still runs; a worker stuck in uninterruptible I/O must not
     * hold PID 1 past this bound, so restart regardless afterwards. */
    for (int i = 0; i < 2; ++i)
        if (workers[i] > 0 && !done[i]) (void)kill(workers[i], SIGKILL);
    for (int waited = 0; waited < REAP_LIMIT_MS; waited += 10) {
        int remaining = 0;
        for (int i = 0; i < 2; ++i) {
            if (workers[i] <= 0 || done[i]) continue;
            pid_t reaped = waitpid(workers[i], &results[i], WNOHANG);
            if (reaped == workers[i] || (reaped < 0 && errno == ECHILD)) done[i] = 1;
            else remaining = 1;
        }
        if (!remaining) break;
        titan_usb_probe_tick();
        (void)poll(NULL, 0, 10);
    }
    close_fd(&data[0]); close_fd(&data[1]); close_fd(&status[0]); close_fd(&status[1]);
    close_fd(&relay[0]); close_fd(&relay[1]);
#ifdef TITAN_USB_PROBE_VM_TEST
    for (int waited = 0; waited < 30000 && bridge.acm_fd >= 0 && bridge.receipt == TITAN_VM_RECEIPT_NONE; waited += 10) {
        if (titan_usb_vm_relay_step(&bridge, &reason) != 0) break;
        titan_usb_probe_tick();
        (void)poll(NULL, 0, 10);
    }
    printf("TITAN_CONTROL_VM_RECEIPT %s\n", bridge.receipt == TITAN_VM_RECEIPT_INCOMPLETE ? "INCOMPLETE" :
           bridge.receipt == TITAN_VM_RECEIPT_VERIFIED ? "VERIFIED" : "MISSING");
#endif
    wait_ticking(FAILURE_GRACE_MS);
#ifdef TITAN_USB_PROBE_VM_TEST
    puts("TITAN_CONTROL_VM_RESTART failure");
#endif
    titan_usb_probe_restart();
}
