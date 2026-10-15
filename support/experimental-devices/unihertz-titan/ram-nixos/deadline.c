/* SPDX-License-Identifier: MIT
 * Hard deadline of the RAM NixOS session (README.adoc in this directory).
 * Stage 0 starts it first; it survives the switch into NixOS and restarts the
 * phone with reboot(2) once the kernel has been up for the given number of
 * seconds, whatever state userspace is in, so a hang during the handover or a
 * frozen service manager still ends in a restart. Normal shutdown stops it
 * like any other process. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <sys/reboot.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char *end;
    errno = 0;
    long seconds = strtol(argv[1], &end, 10);
    if (errno || end == argv[1] || *end || seconds < 60 || seconds > 86400) return 2;
    struct timespec deadline = { .tv_sec = seconds, .tv_nsec = 0 };
    /* Restart only once the uptime has really reached the deadline; an
     * unexpected sleep error falls back to one-second steps. */
    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_BOOTTIME, &now) == 0 && now.tv_sec >= seconds) break;
        int result = clock_nanosleep(CLOCK_BOOTTIME, TIMER_ABSTIME, &deadline, NULL);
        if (result != 0 && result != EINTR) sleep(1);
    }
    sync();
    reboot(RB_AUTOBOOT);
    return 1;
}
