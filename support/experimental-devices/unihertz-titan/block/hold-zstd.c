/* SPDX-License-Identifier: MIT
 * VM-only completion gate around the real, fixed compressor. No production hook.
 */
#define _GNU_SOURCE
#ifndef TITAN_BLOCK_VM_TEST
#error Compressor completion gate is restricted to the synthetic VM fixture
#endif
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
    struct timespec value;
    return clock_gettime(CLOCK_MONOTONIC, &value) == 0
        ? value.tv_sec + value.tv_nsec / 1000000000.0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 3 || strcmp(argv[1], "-q") != 0 || strcmp(argv[2], "-c") != 0)
        return 1;
    double deadline = now() + 22;
    pid_t child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        execl("/bin/zstd-real", "/bin/zstd-real", "-q", "-c", (char *) NULL);
        _exit(127);
    }
    int status = 0, reaped = 0;
    while (now() > 0 && now() < deadline) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            reaped = 1;
            break;
        }
        if (result < 0)
            break;
        (void) poll(NULL, 0, 10);
    }
    if (!reaped) {
        (void) kill(child, SIGKILL);
        fputs("titan-hold-zstd: fixture compressor did not finish\n", stderr);
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;
    /* Real compressed bytes and EOF reach the supervisor before its child has
     * exited. Its source claim must remain active throughout this gate. */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    int marker = open("/run/compressor-ready", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (marker < 0)
        return 1;
    close(marker);
    while (now() > 0 && now() < deadline) {
        struct stat metadata;
        if (lstat("/run/compressor-release", &metadata) == 0) {
            if (S_ISREG(metadata.st_mode) && metadata.st_size == 0)
                return 0;
            break;
        }
        (void) poll(NULL, 0, 10);
    }
    fputs("titan-hold-zstd: fixture completion gate failed\n", stderr);
    return 1;
}
