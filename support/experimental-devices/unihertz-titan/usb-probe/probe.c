/* SPDX-License-Identifier: MIT
 * Separate experimental PID 1 profile for a first boot of a new ramdisk. After
 * the rescue storage guard it binds the fixed ACM gadget, writes a bounded
 * status line every two seconds and restarts into the bootloader at a fixed
 * deadline counted from PID 1 start, whether or not the earlier steps
 * succeeded. It reads no storage contents, accepts no input and starts no
 * acquisition, shell or service. The VM-only branch reads the report back
 * through dummy_hcd, adds faults and prints restart markers. The separate
 * control profile replaces the report loop with the fixed control-region
 * acquisition in control/pipeline.c and lengthens the deadline.
 */
#define _GNU_SOURCE
#if !defined(TITAN_USB_PROBE_PROFILE) || !defined(TITAN_USB_MOUNT_PROFILE)
#error USB probe requires the explicit probe and seven-mount profiles
#endif
#ifdef TITAN_USB_PIPELINE_PROFILE
#error The USB probe and USB acquisition profiles are exclusive
#endif
#if defined(TITAN_USB_PROBE_VM_TEST) && (!defined(TITAN_USB_PIPELINE_VM_TEST) || !defined(TITAN_RESCUE_VM_TEST))
#error USB probe fixture requires the dummy-UDC and rescue VM profiles
#endif
#include "owner.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/reboot.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* Supplied by rescue/init.c: re-guard every block node and require the fixed
 * disk and partition set. */
int titan_rescue_guard_storage(void);

#if defined(TITAN_PIPELINE_DIAG) && defined(TITAN_USB_PROBE_VM_TEST)
#define DEADLINE_SECONDS 180
#elif defined(TITAN_PIPELINE_DIAG)
/* The diagnostic transfer is small; restart regardless after five minutes. */
#define DEADLINE_SECONDS 300
#elif defined(TITAN_USB_CONTROL_PROFILE) && defined(TITAN_USB_PROBE_VM_TEST)
#define DEADLINE_SECONDS 180
#elif defined(TITAN_USB_CONTROL_PROFILE)
/* The control acquisition transfers about 736 MiB at an unmeasured USB rate;
 * restart regardless after thirty minutes. */
#define DEADLINE_SECONDS 1800
#elif defined(TITAN_USB_PROBE_VM_TEST)
#define DEADLINE_SECONDS 45
#else
#define DEADLINE_SECONDS 150
#endif
/* PID 1 reboots by itself this long after the deadline if the separate
 * deadline process has not. */
#define BACKSTOP_SECONDS 10
#define REPORT_MILLISECONDS 2000

static struct timespec start, deadline;
static pid_t deadline_process = -1;
static int armed;

static int boottime(struct timespec *value)
{
    return clock_gettime(CLOCK_BOOTTIME, value);
}

static _Noreturn void restart_now(void)
{
    /* Only PID 1 or its deadline process may restart: running this binary
     * elsewhere, for example under qemu-user, must never reboot a host. */
    if (getpid() != 1 && getppid() != 1) _exit(1);
    /* Nothing writable is mounted from storage; every block node is read-only. */
    sync();
    for (;;) {
        /* Restart into bootloader fastboot, where the original recovery can be
         * written back; the vendor kernel maps this argument to its fastboot
         * marker. An ordinary restart is the fallback if the call fails. */
        (void)syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                      LINUX_REBOOT_CMD_RESTART2, "bootloader");
        (void)reboot(RB_AUTOBOOT);
        sleep(1);
    }
}

#ifdef TITAN_USB_PROBE_VM_TEST
/* VM-only restart markers. The phone build writes nothing on its restart
 * paths, so a stalled console cannot delay the restart. */
static void console_marker(const char *name)
{
    struct timespec now;
    char text[96];
    int length = snprintf(text, sizeof(text), "%s now=%lld\n", name,
                          boottime(&now) == 0 ? (long long)now.tv_sec : -1LL);
    int fd = open("/dev/console", O_WRONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return;
    if (length > 0 && length < (int)sizeof(text)) (void)!write(fd, text, (size_t)length);
    close(fd);
}
#else
#define console_marker(name) ((void)0)
#endif

/* Separate from PID 1: it holds no gadget or block descriptor, keeps only the
 * descriptors inherited from the kernel and sleeps until the deadline. */
static _Noreturn void deadline_main(void)
{
    sigset_t all;
    sigfillset(&all);
    (void)sigprocmask(SIG_BLOCK, &all, NULL);
    for (;;) {
        struct timespec now, pause = { .tv_sec = 1, .tv_nsec = 0 };
        if (boottime(&now) != 0 || now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) break;
        (void)nanosleep(&pause, NULL);
    }
    console_marker("TITAN_PROBE_DEADLINE_REBOOT");
    restart_now();
}

/* Called by PID 1 before any mount or device access. Without a clock or a
 * separate deadline process there is no guaranteed return, so reboot now. */
void titan_usb_probe_arm(void)
{
    if (getpid() != 1) return;
    if (boottime(&start) != 0) restart_now();
    deadline.tv_sec = start.tv_sec + DEADLINE_SECONDS;
    deadline.tv_nsec = start.tv_nsec;
    deadline_process = fork();
    if (deadline_process < 0) restart_now();
    if (deadline_process == 0) deadline_main();
    armed = 1;
}

void titan_usb_probe_announce(void)
{
    printf("TITAN_PROBE_ARMED start=%lld deadline=%lld backstop=%d\n", (long long)start.tv_sec,
           (long long)deadline.tv_sec, BACKSTOP_SECONDS);
}

/* PID 1 backstop, called from every wait loop including the failure path. */
void titan_usb_probe_tick(void)
{
    struct timespec now;
    if (!armed) restart_now();
    if (boottime(&now) != 0 || now.tv_sec >= deadline.tv_sec + BACKSTOP_SECONDS) {
        console_marker("TITAN_PROBE_BACKSTOP_REBOOT");
        restart_now();
    }
}

static void wait_milliseconds(int milliseconds)
{
    titan_usb_probe_tick();
    if (poll(NULL, 0, milliseconds) < 0 && errno != EINTR) restart_now();
    titan_usb_probe_tick();
}

static _Noreturn void fail_wait(const char *reason)
{
    printf("TITAN_PROBE_FAILED %s\n", reason ? reason : "unspecified");
    /* Keep any gadget state; there are no workers or storage claims. Only the
     * deadline reboot or the backstop ends this state. */
    for (;;) wait_milliseconds(1000);
}

static void sanitized(char *text)
{
    for (char *p = text; *p; ++p)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '+' && *p != '-' && *p != '_') *p = '_';
}

#ifdef TITAN_USB_CONTROL_PROFILE
int titan_usb_control_run(struct titan_usb *usb);

/* The control pipeline's way out: the same restart into the bootloader. */
_Noreturn void titan_usb_probe_restart(void)
{
    restart_now();
}
#endif

#if defined(TITAN_USB_PROBE_VM_TEST) && !defined(TITAN_USB_CONTROL_PROFILE)
static const char *selected_case(void)
{
    static const char *const cases[] = { "valid", "stuck", "child-killed", NULL };
    static const char prefix[] = "titan_usb_probe_test=";
    char line[4096];
    FILE *stream = fopen("/proc/cmdline", "r");
    if (stream == NULL) return NULL;
    char *found = fgets(line, sizeof(line), stream) ? strstr(line, prefix) : NULL;
    fclose(stream);
    if (found == NULL) return NULL;
    found += sizeof(prefix) - 1;
    found[strcspn(found, " \n")] = '\0';
    for (const char *const *name = cases; *name; ++name)
        if (strcmp(found, *name) == 0) return *name;
    return NULL;
}

/* Read complete report lines back through the guest's own cdc_acm host. */
static void vm_receive(int fd, char *buffer, size_t *used, unsigned *received)
{
    for (;;) {
        if (*used >= 1023) { puts("TITAN_PROBE_VM_FAIL overlong-report"); *used = 0; }
        ssize_t count = read(fd, buffer + *used, 1023 - *used);
        if (count <= 0) return;
        *used += (size_t)count;
        buffer[*used] = '\0';
        char *newline;
        while ((newline = strchr(buffer, '\n')) != NULL) {
            unsigned sequence;
            *newline = '\0';
            if (sscanf(buffer, "TITAN_PROBE v1 seq=%u ", &sequence) == 1) {
                printf("TITAN_PROBE_VM_RECEIVED seq=%u\n", sequence);
                ++*received;
            } else {
                puts("TITAN_PROBE_VM_FAIL malformed-report");
            }
            size_t rest = *used - (size_t)(newline + 1 - buffer);
            memmove(buffer, newline + 1, rest);
            *used = rest;
            buffer[*used] = '\0';
        }
    }
}

#endif
#ifdef TITAN_USB_PROBE_VM_TEST
int titan_rescue_vm_test(void);
#endif

int titan_usb_probe_run(void)
{
    struct titan_usb usb = TITAN_USB_INITIALIZER;
    const char *reason = "probe-preflight";
    struct utsname kernel;
    char release[sizeof(kernel.release)];
    if (getpid() != 1 || !armed) fail_wait(reason);
#if defined(TITAN_USB_PROBE_VM_TEST) && !defined(TITAN_USB_CONTROL_PROFILE)
    const char *name = selected_case();
    if (name == NULL) fail_wait("vm-case-invalid");
    printf("TITAN_PROBE_VM_START %s\n", name);
    if (strcmp(name, "child-killed") == 0) {
        if (kill(deadline_process, SIGKILL) != 0 || waitpid(deadline_process, NULL, 0) != deadline_process)
            fail_wait("vm-child-kill-failed");
        puts("TITAN_PROBE_VM_CHILD_KILLED");
    }
#endif
    if (uname(&kernel) != 0) fail_wait("kernel-release-unavailable");
    memcpy(release, kernel.release, sizeof(release));
    release[sizeof(release) - 1] = '\0';
    sanitized(release);
    printf("TITAN_PROBE_KERNEL %s\n", release);
    if (titan_rescue_guard_storage() != 0) fail_wait("storage-guard-incomplete");
    if (titan_usb_prepare(&usb, &reason) != 0 || titan_usb_bind_and_seal(&usb, &reason) != 0)
        fail_wait(reason);
    puts("TITAN_PROBE_USB_BOUND");
#ifdef TITAN_USB_CONTROL_PROFILE
    (void)titan_usb_control_run(&usb);
    fail_wait("control-returned");
#else
#ifdef TITAN_USB_PROBE_VM_TEST
    if (strcmp(name, "stuck") == 0) {
        /* A PID 1 that never returns to its loop: only the separate deadline
         * process can end it. */
        puts("TITAN_PROBE_VM_STUCK");
        for (;;) (void)poll(NULL, 0, -1);
    }
    int host = titan_usb_vm_open_host(&usb, &reason);
    if (host < 0) fail_wait(reason);
    char buffer[1024] = "";
    size_t used = 0;
    unsigned received = 0;
    int announced = 0;
#endif
    for (unsigned sequence = 1;; ++sequence) {
        struct timespec now;
        char line[256];
        if (titan_usb_recheck(&usb, &reason) != 0) fail_wait(reason);
        if (titan_rescue_guard_storage() != 0) fail_wait("storage-changed");
        if (boottime(&now) != 0) restart_now();
        int length = snprintf(line, sizeof(line),
            "TITAN_PROBE v1 seq=%u uptime=%lld deadline=%lld kernel=%s storage=guarded usb=bound\n",
            sequence, (long long)now.tv_sec, (long long)deadline.tv_sec, release);
        if (length <= 0 || length >= (int)sizeof(line)) fail_wait("report-format");
        /* The descriptor is non-blocking: without a reading host the line is
         * dropped, and a full or absent host never stalls this loop. */
        ssize_t written = write(usb.tty_fd, line, (size_t)length);
        /* A hung-up gadget TTY (EIO) means the host went away; keep guarding. */
        if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != EIO)
            fail_wait("report-write-failed");
        /* Drop queued output after a short or refused write, so a later host
         * receives whole lines rather than an old fragment. */
        if (written != length) (void)tcflush(usb.tty_fd, TCOFLUSH);
        if (sequence <= 3) printf("TITAN_PROBE_REPORT seq=%u\n", sequence);
#ifdef TITAN_USB_PROBE_VM_TEST
        vm_receive(host, buffer, &used, &received);
        if (received >= 3 && !announced) { puts("TITAN_PROBE_VM_REPORTS_RECEIVED"); announced = 1; }
#endif
        wait_milliseconds(REPORT_MILLISECONDS);
    }
#endif
}

#ifdef TITAN_USB_PROBE_VM_TEST
int titan_rescue_vm_test(void)
{
    return titan_usb_probe_run();
}
#endif
