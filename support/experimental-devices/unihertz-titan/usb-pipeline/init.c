/* SPDX-License-Identifier: MIT
 * Separate experimental PID1 profile: fixed userdata producer over fixed ACM.
 * No peer command interpreter, source/program overrides, disk writes or reboot.
 * The VM-only branch adds synthetic fault injection, a relay and final poweroff.
 */
#define _GNU_SOURCE
#if !defined(TITAN_USB_PIPELINE_PROFILE) || !defined(TITAN_USB_MOUNT_PROFILE)
#error USB pipeline requires both explicit production integration profiles
#endif
#ifdef TITAN_USB_PIPELINE_VM_TEST
#if !defined(TITAN_SOURCE_VM_TEST) || !defined(TITAN_RESCUE_VM_TEST)
#error USB pipeline fixture requires source and rescue VM profiles
#endif
#include "relay.h"
#include <sys/reboot.h>
#include <sys/utsname.h>
#endif
#include "owner.h"
#include "guard.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Supplied by rescue/init.c: re-guard every block node and require the fixed
 * disk and partition set, without the USB profile's own rescans. */
int titan_rescue_guard_storage(void);

#ifdef TITAN_USB_PIPELINE_VM_TEST
#define BYTE_CAP "33554432"
#define PRODUCER_SECONDS "25"
#define SENDER_SECONDS "35"
#define GLOBAL_SECONDS 90
#define TRANSFER_LABEL "usb-userdata-fixture"
#else
/* Limits, not space reservations or measured throughput promises. */
#define BYTE_CAP "125074145280"
#define PRODUCER_SECONDS "21600"
#define SENDER_SECONDS "21900"
#define GLOBAL_SECONDS 21960
#define TRANSFER_LABEL "userdata-sparse"
#endif
#define CHILD_LIMIT 128U

struct pipeline {
    struct titan_usb usb;
    pid_t workers[2];
    int statuses[2];
    int status_fd, relay_fd;
    unsigned char status_bytes[9];
    size_t received, forwarded;
    int status_eof, no_children, workers_started;
    unsigned adopted, child_scans;
    double deadline;
#ifdef TITAN_USB_PIPELINE_VM_TEST
    const char *name;
    struct titan_usb_vm_relay relay;
    int host_fd, mutated, forced;
#endif
};

static double now(void)
{
    struct timespec value;
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0 ?
        value.tv_sec + value.tv_nsec / 1000000000.0 : -1;
}

static int fail(const char **reason, const char *value)
{
    if (reason != NULL) *reason = value;
    return -1;
}

static void close_fd(int *fd)
{
    if (*fd >= 0) close(*fd);
    *fd = -1;
}

static int step_relay(struct pipeline *pipeline, const char **reason)
{
#ifdef TITAN_USB_PIPELINE_VM_TEST
    if (pipeline->relay.uart_fd >= 0)
        return titan_usb_vm_relay_step(&pipeline->relay, reason);
#else
    (void)pipeline;
    (void)reason;
#endif
    return 0;
}

static int reap(struct pipeline *pipeline, const char **reason)
{
    pipeline->no_children = 0;
    for (unsigned count = 0; count < CHILD_LIMIT; ++count) {
        int status;
        pid_t child = waitpid(-1, &status, WNOHANG);
        if (child == 0) return 0;
        if (child < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) { pipeline->no_children = 1; return 0; }
            return fail(reason, "child-wait-failed");
        }
        int known = 0;
        for (unsigned i = 0; i < 2; ++i)
            if (child == pipeline->workers[i]) {
                if (pipeline->statuses[i] >= 0) return fail(reason, "duplicate-child-status");
                pipeline->statuses[i] = status;
                known = 1;
            }
        if (!known) ++pipeline->adopted;
    }
    return fail(reason, "child-reap-limit");
}

/* Read only bounded status records. The numeric directory name and Pid field
 * must agree, and PPid is unique. A disappearing unrelated process is skipped;
 * malformed, inaccessible or oversized metadata fails closed.
 */
static int parse_process_status(char *data, size_t used, pid_t pid, pid_t *parent)
{
    if (used == 0 || used >= 16384 || data[used - 1] != '\n' || memchr(data, 0, used) != NULL) return -1;
    data[used] = 0;
    unsigned seen = 0;
    char *save = NULL;
    for (char *line = strtok_r(data, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        unsigned bit;
        char *value;
        if (strncmp(line, "Pid:", 4) == 0) { bit = 1; value = line + 4; }
        else if (strncmp(line, "PPid:", 5) == 0) { bit = 2; value = line + 5; }
        else continue;
        if (seen & bit) return -1;
        seen |= bit;
        if (*value != ' ' && *value != '\t') return -1;
        while (*value == ' ' || *value == '\t') ++value;
        if (*value < '0' || *value > '9') return -1;
        errno = 0;
        char *end;
        unsigned long number = strtoul(value, &end, 10);
        while (*end == ' ' || *end == '\t') ++end;
        if (errno || *end || number > INT_MAX || (bit == 1 && (pid_t)number != pid)) return -1;
        if (bit == 2) *parent = (pid_t)number;
    }
    return seen == 3 ? 0 : -1;
}

static int process_parent(pid_t pid, pid_t *parent)
{
    char path[64], data[16384];
    int length = snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    if (length < 0 || (size_t)length >= sizeof(path)) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT || errno == ESRCH ? 1 : -1;
    size_t used = 0;
    for (;;) {
        ssize_t amount = read(fd, data + used, sizeof(data) - 1 - used);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) {
            int gone = errno == ENOENT || errno == ESRCH;
            close(fd);
            return gone ? 1 : -1;
        }
        if (amount == 0) break;
        used += (size_t)amount;
        if (used == sizeof(data) - 1) { close(fd); return -1; }
    }
    if (close(fd) != 0) return -1;
    return parse_process_status(data, used, pid, parent);
}

/* Single-threaded PID1 never auto-reaps SIGCHLD. Do not reap between this
 * bounded PPid snapshot and signalling its direct-child PIDs: even an exited
 * child remains a zombie, reserving its PID. This uses baseline /proc status,
 * not the optional CONFIG_PROC_CHILDREN interface. Newly adopted descendants
 * that changed parent during a scan are caught by the next scan before ECHILD.
 */
static int signal_children(int signal_number, const char **reason)
{
    pid_t children[CHILD_LIMIT];
    size_t count = 0, processes = 0;
    DIR *directory = opendir("/proc");
    if (directory == NULL) return fail(reason, "child-inventory-unavailable");
    int invalid = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) { if (errno) invalid = 1; break; }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        if (++processes > 4096) { invalid = 1; break; }
        errno = 0;
        char *end;
        unsigned long value = strtoul(entry->d_name, &end, 10);
        if (errno || *end || value == 0 || value > INT_MAX) { invalid = 1; break; }
        if (value == 1) continue;
        pid_t parent = -1;
        int observed = process_parent((pid_t)value, &parent);
        if (observed == 1) continue;
        if (observed < 0) { invalid = 1; break; }
        if (parent != 1) continue;
        if (count == CHILD_LIMIT) { invalid = 1; break; }
        for (size_t i = 0; i < count; ++i)
            if (children[i] == (pid_t)value) invalid = 1;
        if (invalid) break;
        children[count++] = (pid_t)value;
    }
    if (closedir(directory) != 0) invalid = 1;
    if (invalid) return fail(reason, "child-inventory-invalid-or-overflow");
    for (size_t i = 0; i < count; ++i)
        if (kill(children[i], signal_number) != 0 && errno != ESRCH)
            return fail(reason, "child-signal-failed");
    return 0;
}

/* This does not rely on producer process groups: its helpers have independent
 * groups and are adopted by PID1 if it dies. No configfs unseal or TTY close is
 * permitted unless this reaches ECHILD. Kernel-uninterruptible I/O can prevent
 * that, in which case the caller retains the sealed gadget and waits forever.
 */
static int stop_tree(struct pipeline *pipeline, const char **reason)
{
    double start = now();
    if (start < 0) return fail(reason, "cleanup-clock-failed");
    close_fd(&pipeline->relay_fd);
    close_fd(&pipeline->status_fd);
    if (reap(pipeline, reason) != 0) return -1;
    if (pipeline->no_children) return 0;
    while (now() >= 0 && now() < start + 10) {
        ++pipeline->child_scans;
        if (signal_children(now() < start + 2 ? SIGTERM : SIGKILL, reason) != 0 || reap(pipeline, reason) != 0)
            return -1;
        if (pipeline->no_children) return 0;
        /* Continue draining fixture bytes without making relay failure a
         * reason to abandon process cleanup. No relay exists in production. */
        (void)step_relay(pipeline, NULL);
        if (poll(NULL, 0, 10) < 0 && errno != EINTR) return fail(reason, "cleanup-poll-failed");
    }
    return fail(reason, "children-not-reaped-before-cleanup-deadline");
}

static int nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 ? -1 : 0;
}

static void child_descriptors(int first, int second, int third)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGHUP, &action, NULL) != 0 ||
        sigaction(SIGPIPE, &action, NULL) != 0 || sigaction(SIGCHLD, &action, NULL) != 0) _exit(127);
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

static int start_workers(struct pipeline *pipeline, const char **reason)
{
    int data[2] = { -1, -1 }, status[2] = { -1, -1 }, relay[2] = { -1, -1 };
    if (pipe2(data, O_CLOEXEC) != 0 || pipe2(status, O_CLOEXEC) != 0 || pipe2(relay, O_CLOEXEC) != 0) goto bad;
    if (nonblocking(status[0]) != 0 || nonblocking(relay[1]) != 0) goto bad;
    char data_read[24], data_write[24], status_write[24], status_read[24], tty_number[24];
    snprintf(data_read, sizeof(data_read), "%d", data[0]);
    snprintf(data_write, sizeof(data_write), "%d", data[1]);
    snprintf(status_write, sizeof(status_write), "%d", status[1]);
    snprintf(status_read, sizeof(status_read), "%d", relay[0]);
    snprintf(tty_number, sizeof(tty_number), "%d", pipeline->usb.tty_fd);
    char *const environment[] = { "PATH=/bin", "LC_ALL=C", NULL };
    const char *limit = BYTE_CAP;
#ifdef TITAN_USB_PIPELINE_VM_TEST
    if (strcmp(pipeline->name, "output-limit") == 0) limit = "1";
#endif
    pipeline->workers_started = 1;
    pipeline->workers[0] = fork();
    if (pipeline->workers[0] == 0) {
        child_descriptors(data[1], status[1], -1);
        char *const arguments[] = { "/bin/titan-block-produce", "--output-fd", data_write,
            "--status-fd", status_write, "--max-bytes", (char *)limit,
            "--timeout-seconds", PRODUCER_SECONDS, NULL };
        execve(arguments[0], arguments, environment);
        _exit(127);
    }
    if (pipeline->workers[0] < 0) goto bad;
    pipeline->workers[1] = fork();
    if (pipeline->workers[1] == 0) {
        child_descriptors(data[0], relay[0], pipeline->usb.tty_fd);
        char *const arguments[] = { "/bin/titan-rescue-send", "--input-fd", data_read,
            "--status-fd", status_read, "--transport-fd", tty_number, "--label", TRANSFER_LABEL,
            "--max-bytes", BYTE_CAP, "--timeout-seconds", SENDER_SECONDS, NULL };
        execve(arguments[0], arguments, environment);
        _exit(127);
    }
    if (pipeline->workers[1] < 0) goto bad;
    close(data[0]); close(data[1]); close(status[1]); close(relay[0]);
    pipeline->status_fd = status[0];
    pipeline->relay_fd = relay[1];
    return 0;
bad:
    close_fd(&data[0]); close_fd(&data[1]); close_fd(&status[0]); close_fd(&status[1]);
    close_fd(&relay[0]); close_fd(&relay[1]);
    return fail(reason, "worker-pipe-or-fork-failed");
}

static int status_step(struct pipeline *pipeline, const char **reason)
{
    if (!pipeline->status_eof) {
        ssize_t count = read(pipeline->status_fd, pipeline->status_bytes + pipeline->received,
                             sizeof(pipeline->status_bytes) - pipeline->received);
        if (count == 0) { pipeline->status_eof = 1; close_fd(&pipeline->status_fd); }
        else if (count > 0) pipeline->received += (size_t)count;
        else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return fail(reason, "producer-status-read-failed");
        if (pipeline->received > 8) return fail(reason, "producer-status-too-long");
    }
    if (pipeline->forwarded < pipeline->received) {
        ssize_t count = write(pipeline->relay_fd, pipeline->status_bytes + pipeline->forwarded,
                              pipeline->received - pipeline->forwarded);
        if (count > 0) pipeline->forwarded += (size_t)count;
        else if (count == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK))
            return fail(reason, "producer-status-forward-failed");
    }
    if (pipeline->status_eof && pipeline->forwarded == pipeline->received) close_fd(&pipeline->relay_fd);
    return 0;
}

static unsigned producer_status(const struct pipeline *pipeline)
{
    if (!pipeline->status_eof || pipeline->received != 8 || memcmp(pipeline->status_bytes, "TPST", 4) != 0)
        return UINT_MAX;
    return ((unsigned)pipeline->status_bytes[4] << 24) | ((unsigned)pipeline->status_bytes[5] << 16) |
           ((unsigned)pipeline->status_bytes[6] << 8) | pipeline->status_bytes[7];
}

#ifdef TITAN_USB_PIPELINE_VM_TEST
/* Malformed metadata regressions use the same parser as real PID cleanup.
 * They never signal a fixture PID or access a host process. */
static int status_parser_fixture(void)
{
    static const struct { const char *text; int valid; } records[] = {
        { "Name:\ttest\nPid:\t42\nPPid:\t1\n", 1 },
        { "PPid: 1\nPid: 42\n", 1 },
        { "Pid:\t42\n", 0 },
        { "Pid:\t42\nPPid:\t1\nPPid:\t2\n", 0 },
        { "Pid:\t42\nPid:\t42\nPPid:\t1\n", 0 },
        { "Pid:\t43\nPPid:\t1\n", 0 },
        { "Pid:\t42\nPPid:\t-1\n", 0 },
        { "Pid:\t42\nPPid:\t+1\n", 0 },
        { "Pid:\t42\nPPid:\t4294967296\n", 0 },
        { "Pid:\t42\nPPid:\t1 trailing\n", 0 },
        { "Pid:\t42\nPPid:1\n", 0 },
        { "Pid:\t42\nPPid:\t1", 0 }
    };
    for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); ++i) {
        char text[128];
        size_t length = strlen(records[i].text);
        memcpy(text, records[i].text, length + 1);
        pid_t parent = -1;
        int valid = parse_process_status(text, length, 42, &parent) == 0;
        if (valid != records[i].valid || (valid && parent != 1)) return -1;
    }
    char embedded[] = "Pid:\t42\nPPid:\t1\n\0extra\n";
    pid_t parent = -1;
    return parse_process_status(embedded, sizeof(embedded) - 1, 42, &parent) != 0 ? 0 : -1;
}

static const char *selected_case(void)
{
    static const char *const cases[] = { "valid", "dirty-filesystem", "wrong-label", "output-limit",
                                       "post-readonly-change", "forced-producer-death" };
    char data[4096];
    int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    ssize_t length = read(fd, data, sizeof(data));
    close(fd);
    if (length <= 0 || length >= (ssize_t)sizeof(data) || memchr(data, 0, (size_t)length) != NULL) return NULL;
    data[length] = 0;
    const char *chosen = NULL;
    char *save = NULL;
    static const char prefix[] = "titan_usb_pipeline_test=";
    for (char *word = strtok_r(data, " \r\n\t", &save); word; word = strtok_r(NULL, " \r\n\t", &save)) {
        if (strncmp(word, prefix, sizeof(prefix) - 1) != 0) continue;
        if (chosen != NULL) return NULL;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
            if (strcmp(word + sizeof(prefix) - 1, cases[i]) == 0) chosen = cases[i];
        if (chosen == NULL) return NULL;
    }
    return chosen;
}

static int exclusive(const char *path, int busy)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_EXCL);
    int error = errno;
    if (fd >= 0) close(fd);
    return busy ? fd < 0 && error == EBUSY : fd >= 0;
}

static int vm_fault_step(struct pipeline *pipeline, const char **reason)
{
    int force = strcmp(pipeline->name, "forced-producer-death") == 0;
    if ((!force && strcmp(pipeline->name, "post-readonly-change") != 0) || pipeline->mutated || pipeline->forced)
        return 0;
    struct stat metadata;
    if (lstat("/run/compressor-ready", &metadata) != 0)
        return errno == ENOENT ? 0 : fail(reason, "vm-compressor-gate-stat-failed");
    if (!S_ISREG(metadata.st_mode) || metadata.st_size != 0 || !exclusive("/dev/vda", 1))
        return fail(reason, "vm-source-claim-not-held-at-gate");
    if (force) {
        if (kill(pipeline->workers[0], SIGKILL) != 0) return fail(reason, "vm-producer-kill-failed");
        pipeline->forced = 1;
        puts("TITAN_USB_PIPELINE_VM_FORCED_PRODUCER_DEATH");
        return 0;
    }
    const char *const paths[] = { "/dev/vda", "/dev/vda1" };
    for (unsigned i = 0; i < 2; ++i) {
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        int value = 1;
        if (fd < 0) return fail(reason, "vm-ro-node-open-failed");
        int bad = fstat(fd, &metadata) != 0 || !S_ISBLK(metadata.st_mode) ||
                  ioctl(fd, BLKROGET, &value) != 0 || value != 1;
        value = 0;
        bad = bad || ioctl(fd, BLKROSET, &value) != 0 || ioctl(fd, BLKROGET, &value) != 0 || value != 0;
        close(fd);
        if (bad) return fail(reason, "vm-ro-clear-failed");
    }
    int marker = open("/run/compressor-release", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (marker < 0) return fail(reason, "vm-compressor-release-failed");
    close(marker);
    pipeline->mutated = 1;
    puts("TITAN_USB_PIPELINE_VM_POST_GUARD_CHANGED");
    return 0;
}
#endif

static int run_pipeline(struct pipeline *pipeline, const char **reason)
{
    double next_check = now(), sender_finished_at = -1;
    for (;;) {
        double current = now();
        if (current < 0 || current >= pipeline->deadline) return fail(reason, "pipeline-global-deadline");
        if (step_relay(pipeline, reason) != 0 || status_step(pipeline, reason) != 0 || reap(pipeline, reason) != 0)
            return -1;
        if (pipeline->adopted || (pipeline->statuses[0] >= 0 &&
            (!WIFEXITED(pipeline->statuses[0]) || WEXITSTATUS(pipeline->statuses[0]) == 127)))
            return fail(reason, "worker-exited-before-owned-cleanup");
        /* A sender may finish after TPST EOF but before the producer gets its
         * final scheduling slice to exit. Allow that ordering, while bounding
         * continued source work after the transport process has disappeared. */
        if (pipeline->statuses[1] >= 0 && pipeline->statuses[0] < 0) {
            if (sender_finished_at < 0) sender_finished_at = current;
            if (current >= sender_finished_at + 2) return fail(reason, "producer-outlived-sender-grace");
        }
#ifdef TITAN_USB_PIPELINE_VM_TEST
        if (vm_fault_step(pipeline, reason) != 0) return -1;
        if (pipeline->forced) return fail(reason, "vm-forced-producer-death");
#endif
        if (current >= next_check) {
            if (titan_usb_recheck(&pipeline->usb, reason) != 0) return -1;
            next_check = current + 1;
        }
        if (pipeline->statuses[0] >= 0 && pipeline->statuses[1] >= 0 &&
            pipeline->status_eof && pipeline->relay_fd < 0) {
            if (!pipeline->no_children || pipeline->adopted) return fail(reason, "unexpected-worker-descendants");
            return 0;
        }
        if (poll(NULL, 0, 10) < 0 && errno != EINTR) return fail(reason, "pipeline-poll-failed");
    }
}

#ifndef TITAN_USB_PIPELINE_VM_TEST
static _Noreturn void retain_failure(const char *reason)
{
    printf("TITAN_USB_PIPELINE_FAILED_RETAINED %s\n", reason ? reason : "unexpected-idle-child");
    for (;;) (void)poll(NULL, 0, 1000);
}

static _Noreturn void success_wait(struct pipeline *pipeline)
{
    struct titan_source source = TITAN_SOURCE_INITIALIZER;
    const char *reason = NULL;
    puts("TITAN_USB_PIPELINE_COMPLETE_SENT_GADGET_HELD");
    /* There is no receipt after TTR1 COMPLETE. Keep the same raw FD and bound
     * gadget alive indefinitely; sender exit alone cannot prove host receipt.
     * No production command can trigger cleanup, a retry, reboot or a new read.
     */
    if (titan_source_open(&source, &reason) != 0) goto retained_failure;
    for (;;) {
        if (titan_usb_recheck(&pipeline->usb, &reason) != 0 || titan_source_recheck(&source, &reason) != 0 ||
            reap(pipeline, &reason) != 0 || !pipeline->no_children) break;
        if (poll(NULL, 0, 1000) < 0 && errno != EINTR) {
            reason = "steady-wait-poll-failed"; break;
        }
    }
retained_failure:
    /* A failure after sending COMPLETE cannot authorize teardown either: the
     * host may still be receiving it. Retain any idle source claim and gadget
     * descriptors without another acquisition or automated recovery action. */
    retain_failure(reason);
}
#endif

int titan_usb_pipeline_run(void)
{
    struct pipeline pipeline = {
        .usb = TITAN_USB_INITIALIZER, .workers = { -1, -1 }, .statuses = { -1, -1 },
        .status_fd = -1, .relay_fd = -1,
#ifdef TITAN_USB_PIPELINE_VM_TEST
        .relay = TITAN_USB_VM_RELAY_INITIALIZER, .host_fd = -1,
#endif
    };
    const char *reason = "pipeline-preflight";
    int completed = 0;
    if (getpid() != 1 || now() < 0) goto failure;
    struct sigaction child_action;
    memset(&child_action, 0, sizeof(child_action));
    child_action.sa_handler = SIG_DFL;
    if (sigemptyset(&child_action.sa_mask) != 0 || sigaction(SIGCHLD, &child_action, NULL) != 0) {
        reason = "pid-one-child-signal-setup-failed"; goto failure;
    }
    pipeline.deadline = now() + GLOBAL_SECONDS;
    if (reap(&pipeline, &reason) != 0 || !pipeline.no_children) goto failure;
#ifdef TITAN_USB_PIPELINE_VM_TEST
    pipeline.name = selected_case();
    if (pipeline.name == NULL) { reason = "vm-case-invalid"; goto failure; }
    if (status_parser_fixture() != 0) { reason = "vm-process-status-parser-regression"; goto failure; }
    printf("TITAN_USB_PIPELINE_VM_START %s\n", pipeline.name);
    struct utsname kernel;
    if (uname(&kernel) != 0) { reason = "vm-kernel-unavailable"; goto failure; }
    printf("TITAN_USB_PIPELINE_VM_KERNEL %s\n", kernel.release);
    if ((strcmp(pipeline.name, "post-readonly-change") == 0 || strcmp(pipeline.name, "forced-producer-death") == 0) &&
        (rename("/bin/zstd", "/bin/zstd-real") != 0 || rename("/bin/hold-zstd", "/bin/zstd") != 0)) {
        reason = "vm-compressor-gate-install-failed"; goto failure;
    }
#endif
    /* Devices can register after READY; guard again before any USB setup. */
    if (titan_rescue_guard_storage() != 0) { reason = "storage-guard-incomplete"; goto failure; }
    if (titan_usb_prepare(&pipeline.usb, &reason) != 0) goto failure;
    puts("TITAN_USB_PIPELINE_RAW_READY");
    if (titan_usb_bind_and_seal(&pipeline.usb, &reason) != 0) goto failure;
    puts("TITAN_USB_PIPELINE_BOUND_SEALED");
#ifdef TITAN_USB_PIPELINE_VM_TEST
    pipeline.host_fd = titan_usb_vm_open_host(&pipeline.usb, &reason);
    if (pipeline.host_fd < 0 || titan_usb_vm_relay_init(&pipeline.relay, pipeline.host_fd, &reason) != 0) goto failure;
    struct titan_source probe = TITAN_SOURCE_INITIALIZER;
    int opened = titan_source_open(&probe, &reason);
    int checked = opened == 0 ? titan_source_recheck(&probe, &reason) : -1;
    titan_source_close(&probe);
    if (strcmp(pipeline.name, "wrong-label") == 0) {
        if (opened == 0 || reason == NULL || strcmp(reason, "partition-identity-mismatch") != 0) {
            reason = "vm-wrong-label-preflight-mismatch"; goto failure;
        }
    } else if (opened != 0 || checked != 0) goto failure;
#endif
    if (now() < 0 || now() >= pipeline.deadline || titan_usb_recheck(&pipeline.usb, &reason) != 0 ||
        start_workers(&pipeline, &reason) != 0) goto failure;
    puts("TITAN_USB_PIPELINE_TRANSFER_READY");
    int ran = run_pipeline(&pipeline, &reason);
#ifdef TITAN_USB_PIPELINE_VM_TEST
    if (pipeline.forced) {
        if (ran == 0 || stop_tree(&pipeline, &reason) != 0 || !pipeline.no_children ||
            pipeline.adopted == 0 || pipeline.child_scans == 0 ||
            !WIFSIGNALED(pipeline.statuses[0]) || WTERMSIG(pipeline.statuses[0]) != SIGKILL ||
            producer_status(&pipeline) == 0) { reason = "vm-orphan-cleanup-mismatch"; goto failure; }
        puts("TITAN_USB_PIPELINE_VM_ORPHANS_REAPED proc-status");
    } else {
        unsigned expected = strcmp(pipeline.name, "valid") == 0 ? 0 :
                            strcmp(pipeline.name, "output-limit") == 0 ? 4 : 2;
        if (ran != 0 || producer_status(&pipeline) != expected ||
            !WIFEXITED(pipeline.statuses[0]) || (unsigned)WEXITSTATUS(pipeline.statuses[0]) != expected ||
            !WIFEXITED(pipeline.statuses[1]) || WEXITSTATUS(pipeline.statuses[1]) != (expected == 0 ? 0 : 5) ||
            (strcmp(pipeline.name, "post-readonly-change") == 0 && !pipeline.mutated)) {
            printf("TITAN_USB_PIPELINE_VM_OBSERVED producer=%d sender=%d status=%u\n",
                   pipeline.statuses[0], pipeline.statuses[1], producer_status(&pipeline));
            reason = "vm-pipeline-result-mismatch"; goto failure;
        }
    }
    if (!exclusive("/dev/vda1", 0) || !exclusive("/dev/vda", 0)) {
        reason = "vm-source-claim-leaked"; goto failure;
    }
    puts("TITAN_USB_PIPELINE_VM_WORKERS_REAPED");
    enum titan_vm_receipt wanted = strcmp(pipeline.name, "valid") == 0 ?
        TITAN_VM_RECEIPT_VERIFIED : TITAN_VM_RECEIPT_INCOMPLETE;
    for (;;) {
        if (now() < 0 || now() >= pipeline.deadline || step_relay(&pipeline, &reason) != 0 ||
            titan_usb_recheck(&pipeline.usb, &reason) != 0) goto failure;
        if (pipeline.relay.receipt != TITAN_VM_RECEIPT_NONE && pipeline.relay.receipt != wanted) {
            reason = "vm-host-receipt-mismatch"; goto failure;
        }
        if (pipeline.relay.receipt == wanted && titan_usb_vm_relay_drained(&pipeline.relay)) break;
        if (poll(NULL, 0, 10) < 0 && errno != EINTR) { reason = "vm-receipt-poll-failed"; goto failure; }
    }
    printf("TITAN_USB_PIPELINE_VM_RECEIPT %s\n", wanted == TITAN_VM_RECEIPT_VERIFIED ? "VERIFIED" : "INCOMPLETE");
    completed = 1;
#else
    if (ran != 0) goto failure;
    if (producer_status(&pipeline) != 0 || !pipeline.no_children ||
        !WIFEXITED(pipeline.statuses[0]) || WEXITSTATUS(pipeline.statuses[0]) != 0 ||
        !WIFEXITED(pipeline.statuses[1]) || WEXITSTATUS(pipeline.statuses[1]) != 0) {
        /* Plain integers only: the producer status code and both wait statuses. */
        printf("TITAN_USB_PIPELINE_RESULT producer-status=%u producer=%d sender=%d\n",
               producer_status(&pipeline), pipeline.statuses[0], pipeline.statuses[1]);
        reason = "worker-result-nonzero";
        goto failure;
    }
    success_wait(&pipeline);
#endif

failure:
    if (!completed) printf("TITAN_USB_PIPELINE_FAILED %s\n", reason ? reason : "unspecified");
    /* Even setup failure must establish ECHILD before entering cleanup. */
    if (stop_tree(&pipeline, &reason) != 0) {
        printf("TITAN_USB_PIPELINE_FAILED_RETAINED %s\n", reason ? reason : "cleanup-failed");
        return 1;
    }
#ifndef TITAN_USB_PIPELINE_VM_TEST
    /* After any worker-start attempt the sender may have queued COMPLETE, even
     * when it died before we observed exit zero. With no independent production
     * host receipt, no status or timeout authorizes USB teardown. Stop/reap all
     * source readers, then keep the raw gadget and perform no further reads. */
    if (pipeline.workers_started) retain_failure(reason);
#endif
#ifdef TITAN_USB_PIPELINE_VM_TEST
    titan_usb_vm_relay_close(&pipeline.relay);
    close_fd(&pipeline.host_fd);
#endif
    if (titan_usb_cleanup(&pipeline.usb, &reason) != 0) {
        printf("TITAN_USB_PIPELINE_FAILED_RETAINED %s\n", reason ? reason : "usb-cleanup-failed");
        return 1;
    }
#ifdef TITAN_USB_PIPELINE_VM_TEST
    if (completed) {
        printf("TITAN_USB_PIPELINE_VM_PASS %s\n", pipeline.name);
        if (fflush(stdout) == 0 && reboot(RB_POWER_OFF) == 0) return 1;
    }
    puts("TITAN_USB_PIPELINE_VM_FAIL pipeline-or-poweroff-failed");
#endif
    return 1;
}

#ifdef TITAN_USB_PIPELINE_VM_TEST
int titan_rescue_vm_test(void)
{
    return titan_usb_pipeline_run();
}
#endif
