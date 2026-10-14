/* SPDX-License-Identifier: MIT
 * Build-only producer supervision. The default target accepts already-open
 * regular image fixtures. A separate block target uses the fixed source guard;
 * neither target mounts, repairs, configures a gadget, or boots a device.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(TITAN_PRODUCER_BLOCK_SOURCE) && defined(TITAN_PRODUCER_TEST_ONLY)
#error The fixed block-source producer must not accept executable overrides
#endif

#ifdef TITAN_PRODUCER_BLOCK_SOURCE
#include "guard.h"
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#define SOURCE_LIMIT UINT64_C(1099511627776)
#define QUEUE_SIZE 65536U
#define DIAGNOSTIC_SIZE 8192U
#define FD_LIMIT 4096U
#define CLEANUP_MILLISECONDS 1000

enum {
    OK = 0, ERR_ARGUMENT = 1, ERR_SOURCE = 2, ERR_IO = 3, ERR_LIMIT = 4,
    ERR_DIAGNOSTIC = 5, ERR_CHILD = 6, ERR_TIMEOUT = 7,
    ERR_INTERRUPTED = 8, ERR_CLEANUP = 9
};

struct options {
    int input;
    int output;
    int status;
    uint64_t limit;
    unsigned int timeout;
    const char *e2image;
    const char *zstd;
};

struct child {
    pid_t pid;
    int exited;
    int successful;
    int reaped;
};

struct pipe_pair { int read_end, write_end; };

struct diagnostic {
    int fd;
    unsigned char bytes[DIAGNOSTIC_SIZE];
    size_t length;
    int eof;
};

struct context {
    struct timespec deadline;
    struct child children[2];
    struct pipe_pair raw, compressed, errors[2], barrier;
    int inherited[FD_LIMIT];
    size_t inherited_count;
};

static volatile sig_atomic_t interrupted;
static const unsigned char expected_banner[] = "e2image 1.47.4 (6-Mar-2025)\n";

static void signal_handler(int number)
{
    (void) number;
    interrupted = 1;
}

static uint16_t le16(const unsigned char *p)
{
    return (uint16_t) ((uint16_t) p[0] | ((uint16_t) p[1] << 8));
}

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static int decimal(const char *text, uint64_t maximum, uint64_t *value)
{
    uint64_t result = 0;
    if (*text == '\0')
        return 0;
    for (; *text != '\0'; ++text) {
        if (*text < '0' || *text > '9')
            return 0;
        unsigned int digit = (unsigned int) (*text - '0');
        if (result > maximum / 10 ||
            (result == maximum / 10 && digit > maximum % 10))
            return 0;
        result = result * 10 + digit;
    }
    *value = result;
    return 1;
}

static int parse_options(int argc, char **argv, struct options *options)
{
    unsigned int seen = 0;
    options->e2image = "/bin/e2image";
    options->zstd = "/bin/zstd";
    for (int i = 1; i < argc; i += 2) {
        unsigned int bit;
        uint64_t number;
        if (i + 1 == argc)
            return ERR_ARGUMENT;
        if (strcmp(argv[i], "--max-bytes") == 0) {
            bit = 1U;
            if (!decimal(argv[i + 1], SOURCE_LIMIT, &number) || number == 0)
                return ERR_ARGUMENT;
            options->limit = number;
        } else if (strcmp(argv[i], "--timeout-seconds") == 0) {
            bit = 2U;
            if (!decimal(argv[i + 1], INT_MAX, &number) || number == 0)
                return ERR_ARGUMENT;
            options->timeout = (unsigned int) number;
#ifdef TITAN_PRODUCER_TEST_ONLY
        } else if (strcmp(argv[i], "--e2image") == 0 || strcmp(argv[i], "--zstd") == 0) {
            bit = strcmp(argv[i], "--e2image") == 0 ? 32U : 64U;
            if (argv[i + 1][0] != '/' || strlen(argv[i + 1]) >= PATH_MAX)
                return ERR_ARGUMENT;
            if (bit == 32U)
                options->e2image = argv[i + 1];
            else
                options->zstd = argv[i + 1];
#endif
        } else {
#ifndef TITAN_PRODUCER_BLOCK_SOURCE
            if (strcmp(argv[i], "--input-fd") == 0)
                bit = 4U;
            else
#endif
            if (strcmp(argv[i], "--output-fd") == 0)
                bit = 8U;
            else if (strcmp(argv[i], "--status-fd") == 0)
                bit = 16U;
            else
                return ERR_ARGUMENT;
            if (!decimal(argv[i + 1], INT_MAX, &number) || number < 3)
                return ERR_ARGUMENT;
            if (bit == 4U)
                options->input = (int) number;
            else if (bit == 8U)
                options->output = (int) number;
            else
                options->status = (int) number;
        }
        if ((seen & bit) != 0)
            return ERR_ARGUMENT;
        seen |= bit;
    }
#ifdef TITAN_PRODUCER_BLOCK_SOURCE
    const unsigned int required = 27U;
#else
    const unsigned int required = 31U;
#endif
    if ((seen & required) != required || options->input == options->output ||
        options->input == options->status || options->output == options->status)
        return ERR_ARGUMENT;
    return OK;
}

static int remaining_ms(const struct timespec *deadline, int *milliseconds)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return ERR_IO;
    int64_t seconds = (int64_t) deadline->tv_sec - (int64_t) now.tv_sec;
    int64_t nanos = (int64_t) deadline->tv_nsec - (int64_t) now.tv_nsec;
    if (nanos < 0) {
        --seconds;
        nanos += INT64_C(1000000000);
    }
    if (seconds < 0 || (seconds == 0 && nanos == 0))
        return ERR_TIMEOUT;
    *milliseconds = seconds >= INT_MAX / 1000 ? INT_MAX :
        (int) (seconds * 1000 + (nanos + 999999) / 1000000);
    return OK;
}

static int active(const struct context *context, int *milliseconds)
{
    if (interrupted)
        return ERR_INTERRUPTED;
    return remaining_ms(&context->deadline, milliseconds);
}

static int nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return ERR_IO;
    return OK;
}

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        /* Never retry close: EINTR may already have released the descriptor. */
        (void) close(*fd);
        *fd = -1;
    }
}

static void close_pair(struct pipe_pair *pair)
{
    close_fd(&pair->read_end);
    close_fd(&pair->write_end);
}

static int make_pipe(struct pipe_pair *pair)
{
    int descriptors[2];
    if (pipe(descriptors) != 0)
        return ERR_IO;
    pair->read_end = descriptors[0];
    pair->write_end = descriptors[1];
    int *ends[] = { &pair->read_end, &pair->write_end };
    for (size_t i = 0; i < 2; ++i) {
        if (*ends[i] <= STDERR_FILENO) {
            int replacement = fcntl(*ends[i], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
            if (replacement < 0)
                return ERR_IO;
            close_fd(ends[i]);
            *ends[i] = replacement;
        }
    }
    if (fcntl(pair->read_end, F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pair->write_end, F_SETFD, FD_CLOEXEC) != 0)
        return ERR_IO;
    return OK;
}

#ifndef TITAN_PRODUCER_BLOCK_SOURCE
static int unchanged(const struct stat *before, const struct stat *after)
{
#ifdef __APPLE__
#define TTR_MTIME st_mtimespec
#define TTR_CTIME st_ctimespec
#else
#define TTR_MTIME st_mtim
#define TTR_CTIME st_ctim
#endif
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode && before->st_nlink == after->st_nlink &&
           before->st_size == after->st_size &&
           before->TTR_MTIME.tv_sec == after->TTR_MTIME.tv_sec &&
           before->TTR_MTIME.tv_nsec == after->TTR_MTIME.tv_nsec &&
           before->TTR_CTIME.tv_sec == after->TTR_CTIME.tv_sec &&
           before->TTR_CTIME.tv_nsec == after->TTR_CTIME.tv_nsec;
#undef TTR_MTIME
#undef TTR_CTIME
}
#endif

static int read_superblock(const struct context *context, int fd, unsigned char *bytes)
{
    size_t done = 0;
    while (done < 1024) {
        int milliseconds;
        int result = active(context, &milliseconds);
        if (result != OK)
            return result;
        ssize_t amount = pread(fd, bytes + done, 1024 - done, (off_t) (1024 + done));
        if (amount < 0) {
            if (errno == EINTR)
                continue;
            return ERR_SOURCE;
        }
        if (amount == 0)
            return ERR_SOURCE;
        done += (size_t) amount;
    }
    return OK;
}

static int valid_superblock(const unsigned char *bytes, uint64_t logical_size)
{
    uint32_t incompat = le32(bytes + 0x60);
    uint32_t log_size = le32(bytes + 0x18);
    if (le16(bytes + 0x38) != 0xef53 || le16(bytes + 0x3a) != 1 ||
        (incompat & 0x4U) != 0 || le32(bytes + 0xe8) != 0 ||
        (le32(bytes + 0x64) & 0x10000U) != 0 || log_size > 6)
        return 0;
    uint64_t blocks = le32(bytes + 0x04);
    if ((incompat & 0x80U) != 0)
        blocks |= (uint64_t) le32(bytes + 0x150) << 32;
    else if (le32(bytes + 0x150) != 0)
        return 0;
    uint64_t block_size = UINT64_C(1024) << log_size;
    return blocks != 0 && blocks <= SOURCE_LIMIT / block_size &&
           blocks * block_size == logical_size;
}

#ifndef TITAN_PRODUCER_BLOCK_SOURCE
static int verify_source(const struct context *context, int fd,
                         const struct stat *initial, const unsigned char *superblock)
{
    struct stat before, after;
    unsigned char current[1024];
    if (fstat(fd, &before) != 0 || !unchanged(initial, &before))
        return ERR_SOURCE;
    int result = read_superblock(context, fd, current);
    if (result != OK)
        return result;
    if (fstat(fd, &after) != 0 || !unchanged(initial, &after) ||
        memcmp(superblock, current, sizeof(current)) != 0 ||
        !valid_superblock(current, (uint64_t) after.st_size) || lseek(fd, 0, SEEK_CUR) != 0)
        return ERR_SOURCE;
    int milliseconds;
    return active(context, &milliseconds);
}
#else
/* This descriptor remains owned by the guard. Block st_size and timestamps
 * are not content-stability evidence and are deliberately unused here. */
static int guarded_size(const struct context *context, struct titan_source *source,
                        uint64_t *logical_size)
{
    int milliseconds;
    int result = active(context, &milliseconds);
    if (result != OK)
        return result;
    const char *reason = NULL;
    int checked = titan_source_recheck(source, &reason);
    result = active(context, &milliseconds);
    if (result != OK)
        return result;
    if (checked != 0)
        return ERR_SOURCE;
    uint64_t size = 0;
    int queried = ioctl(source->partition_fd, BLKGETSIZE64, &size);
    result = active(context, &milliseconds);
    if (result != OK)
        return result;
    if (queried != 0 || size < 2048 || size > SOURCE_LIMIT ||
        lseek(source->partition_fd, 0, SEEK_CUR) != 0)
        return ERR_SOURCE;
    *logical_size = size;
    return active(context, &milliseconds);
}

static int open_block_source(const struct context *context, struct options *options,
                             struct titan_source *source, uint64_t *logical_size,
                             unsigned char *superblock)
{
    int milliseconds;
    int result = active(context, &milliseconds);
    if (result != OK)
        return result;
    const char *reason = NULL;
    int opened = titan_source_open(source, &reason);
    if (opened == 0)
        options->input = source->partition_fd;
    /* O_NONBLOCK does not prevent an open or ioctl from stalling in kernel
     * code; check the deadline again as soon as each guard call returns. */
    result = active(context, &milliseconds);
    if (result != OK)
        return result;
    if (opened != 0)
        return ERR_SOURCE;
    result = guarded_size(context, source, logical_size);
    if (result != OK)
        return result;
    result = read_superblock(context, source->partition_fd, superblock);
    if (result != OK)
        return result;
    if (!valid_superblock(superblock, *logical_size))
        return ERR_SOURCE;
    uint64_t current_size;
    result = guarded_size(context, source, &current_size);
    if (result != OK)
        return result;
    return current_size == *logical_size ? OK : ERR_SOURCE;
}

static int verify_block_source(const struct context *context, struct titan_source *source,
                               uint64_t logical_size, const unsigned char *superblock)
{
    uint64_t current_size;
    unsigned char current[1024];
    int result = guarded_size(context, source, &current_size);
    if (result != OK)
        return result;
    if (current_size != logical_size)
        return ERR_SOURCE;
    result = read_superblock(context, source->partition_fd, current);
    if (result != OK)
        return result;
    if (memcmp(superblock, current, sizeof(current)) != 0 ||
        !valid_superblock(current, logical_size))
        return ERR_SOURCE;
    result = guarded_size(context, source, &current_size);
    if (result != OK)
        return result;
    return current_size == logical_size ? OK : ERR_SOURCE;
}
#endif

/* Inventory after creating every helper pipe, before fork. This bounded list
 * avoids close_range (absent on 4.14), huge close loops, and leaked unrelated
 * inherited descriptors. No other thread opens descriptors during this step. */
static int inventory_descriptors(struct context *context)
{
#ifdef __APPLE__
    DIR *directory = opendir("/dev/fd");
#else
    DIR *directory = opendir("/proc/self/fd");
#endif
    if (directory == NULL)
        return ERR_IO;
    int result = OK;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                result = ERR_IO;
            break;
        }
        uint64_t descriptor;
        if (!decimal(entry->d_name, INT_MAX, &descriptor))
            continue;
        if (context->inherited_count == FD_LIMIT) {
            result = ERR_LIMIT;
            break;
        }
        context->inherited[context->inherited_count++] = (int) descriptor;
    }
    if (closedir(directory) != 0)
        result = ERR_IO;
    return result;
}

static void child_failure(void)
{
    static const char message[] = "producer child setup failed\n";
    (void) write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(127);
}

static void run_child(const struct context *context, const struct options *options,
                      int compressor)
{
    struct sigaction action = { 0 };
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGPIPE, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0 || setpgid(0, 0) != 0)
        _exit(127);
    int out = compressor ? context->compressed.write_end : context->raw.write_end;
    if (dup2(out, STDOUT_FILENO) < 0 ||
        dup2(context->errors[compressor].write_end, STDERR_FILENO) < 0)
        _exit(127);
    if (compressor) {
        if (dup2(context->raw.read_end, STDIN_FILENO) < 0)
            child_failure();
    } else {
        (void) close(STDIN_FILENO);
        int flags = fcntl(options->input, F_GETFD);
        if (flags < 0 || fcntl(options->input, F_SETFD, flags & ~FD_CLOEXEC) != 0)
            child_failure();
    }
    for (size_t i = 0; i < context->inherited_count; ++i) {
        int fd = context->inherited[i];
        if (fd > STDERR_FILENO && fd != context->barrier.read_end &&
            (compressor || fd != options->input))
            (void) close(fd);
    }
    /* The parent establishes both process groups before releasing this gate.
     * EOF is the release signal; a byte or read failure is not authorization. */
    unsigned char gate;
    ssize_t amount;
    do {
        amount = read(context->barrier.read_end, &gate, 1);
    } while (amount < 0 && errno == EINTR);
    if (amount != 0)
        child_failure();
    (void) close(context->barrier.read_end);
    char *environment[] = { "LC_ALL=C", "LANG=C", "PATH=/bin", NULL };
    if (compressor) {
        char *arguments[] = { (char *) options->zstd, "-q", "-c", NULL };
        execve(options->zstd, arguments, environment);
    } else {
        char source[64];
        int count = snprintf(source, sizeof(source), "/proc/self/fd/%d", options->input);
        if (count < 0 || (size_t) count >= sizeof(source))
            child_failure();
        char *arguments[] = { (char *) options->e2image, "-ra", source, "-", NULL };
        execve(options->e2image, arguments, environment);
    }
    child_failure();
}

static int launch(struct context *context, const struct options *options)
{
    int milliseconds;
    int result = active(context, &milliseconds);
    if (result != OK)
        return result;
    if (make_pipe(&context->raw) != OK || make_pipe(&context->compressed) != OK ||
        make_pipe(&context->errors[0]) != OK || make_pipe(&context->errors[1]) != OK ||
        make_pipe(&context->barrier) != OK)
        return ERR_IO;
    result = inventory_descriptors(context);
    if (result != OK)
        return result;
    for (size_t i = 0; i < 2; ++i) {
        result = active(context, &milliseconds);
        if (result != OK)
            return result;
        pid_t child = fork();
        if (child < 0)
            return ERR_CHILD;
        if (child == 0)
            run_child(context, options, (int) i);
        context->children[i].pid = child;
        if (setpgid(child, child) != 0)
            return ERR_CHILD;
    }
    result = active(context, &milliseconds);
    if (result != OK)
        return result;
    close_pair(&context->raw);
    close_fd(&context->compressed.write_end);
    close_fd(&context->errors[0].write_end);
    close_fd(&context->errors[1].write_end);
    close_pair(&context->barrier);
    if (nonblocking(context->compressed.read_end) != OK ||
        nonblocking(context->errors[0].read_end) != OK ||
        nonblocking(context->errors[1].read_end) != OK)
        return ERR_IO;
    return OK;
}

/* WNOWAIT keeps a zombie leader's PID reserved until group cleanup. Reaping
 * early and later signalling its old process-group ID could target a reused ID. */
static int observe_children(struct context *context)
{
    for (size_t i = 0; i < 2; ++i) {
        struct child *child = &context->children[i];
        if (child->exited)
            continue;
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        if (waitid(P_PID, (id_t) child->pid, &info, WEXITED | WNOHANG | WNOWAIT) != 0) {
            if (errno == EINTR)
                continue;
            return ERR_CHILD;
        }
        if (info.si_pid == child->pid) {
            child->exited = 1;
            child->successful = info.si_code == CLD_EXITED && info.si_status == 0;
            if (!child->successful)
                return ERR_CHILD;
        }
    }
    return OK;
}

static int drain_diagnostic(struct diagnostic *diagnostic)
{
    unsigned char excess;
    size_t capacity = DIAGNOSTIC_SIZE - diagnostic->length;
    unsigned char *target = capacity ? diagnostic->bytes + diagnostic->length : &excess;
    if (capacity > 4096)
        capacity = 4096;
    ssize_t amount = read(diagnostic->fd, target, capacity ? capacity : 1);
    if (amount < 0)
        return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ? OK : ERR_IO;
    if (amount == 0) {
        diagnostic->eof = 1;
        return OK;
    }
    if (diagnostic->length == DIAGNOSTIC_SIZE)
        return ERR_DIAGNOSTIC;
    diagnostic->length += (size_t) amount;
    return OK;
}

static int pump(struct context *context, const struct options *options)
{
    unsigned char queue[QUEUE_SIZE];
    size_t head = 0, queued = 0;
    uint64_t total = 0;
    int output_eof = 0;
    struct diagnostic diagnostics[2] = {
        { .fd = context->errors[0].read_end }, { .fd = context->errors[1].read_end }
    };
    for (;;) {
        int milliseconds;
        int result = active(context, &milliseconds);
        if (result != OK)
            return result;
        result = observe_children(context);
        if (result != OK)
            return result;
        if (output_eof && queued == 0 && diagnostics[0].eof && diagnostics[1].eof &&
            context->children[0].exited && context->children[1].exited)
            break;
        struct pollfd requests[4] = {
            { .fd = !output_eof && queued < QUEUE_SIZE ? context->compressed.read_end : -1,
              .events = POLLIN },
            { .fd = diagnostics[0].eof ? -1 : diagnostics[0].fd, .events = POLLIN },
            { .fd = diagnostics[1].eof ? -1 : diagnostics[1].fd, .events = POLLIN },
            { .fd = queued ? options->output : -1, .events = POLLOUT }
        };
        /* Regular polling also notices child exits whose pipe descriptors are
         * retained by a descendant, without trusting EOF alone. */
        if (milliseconds > 50)
            milliseconds = 50;
        int ready = poll(requests, 4, milliseconds);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return ERR_IO;
        }
        result = active(context, &milliseconds);
        if (result != OK)
            return result;
        for (size_t i = 0; i < 4; ++i) {
            if ((requests[i].revents & (POLLERR | POLLNVAL)) != 0)
                return ERR_IO;
        }
        for (size_t i = 0; i < 2; ++i) {
            if ((requests[i + 1].revents & (POLLIN | POLLHUP)) != 0) {
                result = drain_diagnostic(&diagnostics[i]);
                if (result != OK)
                    return result;
            }
        }
        if ((requests[3].revents & POLLHUP) != 0)
            return ERR_IO;
        if ((requests[3].revents & POLLOUT) != 0) {
            size_t amount = queued < QUEUE_SIZE - head ? queued : QUEUE_SIZE - head;
            if (amount > 32768)
                amount = 32768;
            ssize_t written = write(options->output, queue + head, amount);
            if (written < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                    return ERR_IO;
            } else if (written == 0) {
                return ERR_IO;
            } else {
                head = (head + (size_t) written) % QUEUE_SIZE;
                queued -= (size_t) written;
            }
        }
        if ((requests[0].revents & (POLLIN | POLLHUP)) != 0) {
            size_t tail = (head + queued) % QUEUE_SIZE;
            size_t capacity = QUEUE_SIZE - queued;
            if (capacity > QUEUE_SIZE - tail)
                capacity = QUEUE_SIZE - tail;
            if (capacity > 32768)
                capacity = 32768;
            /* At most one byte beyond the bound is read to establish failure. */
            if ((uint64_t) capacity > options->limit - total + 1)
                capacity = (size_t) (options->limit - total + 1);
            ssize_t received = read(context->compressed.read_end, queue + tail, capacity);
            if (received < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                    return ERR_IO;
            } else if (received == 0) {
                output_eof = 1;
            } else {
                if ((uint64_t) received > options->limit - total)
                    return ERR_LIMIT;
                queued += (size_t) received;
                total += (uint64_t) received;
            }
        }
    }
    if (diagnostics[0].length != sizeof(expected_banner) - 1 ||
        memcmp(diagnostics[0].bytes, expected_banner, sizeof(expected_banner) - 1) != 0 ||
        diagnostics[1].length != 0)
        return ERR_DIAGNOSTIC;
    return OK;
}

static int cancel_and_reap(struct context *context, int require_success)
{
    int result = OK;
    /* Leaders have not been reaped: these process-group IDs cannot be reused. */
    for (size_t i = 0; i < 2; ++i) {
        if (context->children[i].pid > 0) {
            if (kill(-context->children[i].pid, SIGKILL) != 0 && errno != ESRCH)
                result = ERR_CLEANUP;
            /* Also cover failure before either side established the group. */
            if (kill(context->children[i].pid, SIGKILL) != 0 && errno != ESRCH)
                result = ERR_CLEANUP;
        }
    }
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
        return ERR_CLEANUP;
    deadline.tv_sec += CLEANUP_MILLISECONDS / 1000;
    for (;;) {
        int remaining = 0;
        for (size_t i = 0; i < 2; ++i) {
            struct child *child = &context->children[i];
            if (child->pid <= 0 || child->reaped)
                continue;
            int status;
            pid_t waited = waitpid(child->pid, &status, WNOHANG);
            if (waited == child->pid) {
                child->reaped = 1;
                if (require_success && (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
                    result = ERR_CHILD;
            } else if (waited < 0 && errno != EINTR) {
                child->reaped = 1;
                result = ERR_CLEANUP;
            } else {
                ++remaining;
            }
        }
        if (remaining == 0)
            return result;
        int milliseconds;
        if (remaining_ms(&deadline, &milliseconds) != OK)
            return ERR_CLEANUP;
        if (milliseconds > 10)
            milliseconds = 10;
        (void) poll(NULL, 0, milliseconds);
    }
}

static int send_status(const struct context *context, int fd, int status)
{
    unsigned char record[8] = { 'T', 'P', 'S', 'T', 0, 0, 0, (unsigned char) status };
    size_t done = 0;
    while (done < sizeof(record)) {
        int milliseconds;
        int result = active(context, &milliseconds);
        if (result != OK)
            return result;
        struct pollfd request = { .fd = fd, .events = POLLOUT };
        int ready = poll(&request, 1, milliseconds);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return ERR_IO;
        }
        if (ready == 0)
            continue;
        if ((request.revents & (POLLERR | POLLNVAL | POLLHUP)) != 0)
            return ERR_IO;
        result = active(context, &milliseconds);
        if (result != OK)
            return result;
        ssize_t written = write(fd, record + done, sizeof(record) - done);
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return ERR_IO;
        }
        if (written == 0)
            return ERR_IO;
        done += (size_t) written;
    }
    return OK;
}

static void report_failure(void)
{
    static const char message[] = "titan-producer: acquisition was not verified\n";
    int flags = fcntl(STDERR_FILENO, F_GETFL);
    if (flags >= 0 && fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK) == 0) {
        (void) write(STDERR_FILENO, message, sizeof(message) - 1);
        (void) fcntl(STDERR_FILENO, F_SETFL, flags);
    }
}

int main(int argc, char **argv)
{
    struct options options = { .input = -1, .output = -1, .status = -1 };
    struct context context = {
        .raw = { -1, -1 }, .compressed = { -1, -1 },
        .errors = { { -1, -1 }, { -1, -1 } }, .barrier = { -1, -1 }
    };
    int output_flags = -1, status_flags = -1, status_ready = 0;
    struct stat output, status;
#ifdef TITAN_PRODUCER_BLOCK_SOURCE
    struct titan_source source = TITAN_SOURCE_INITIALIZER;
    uint64_t logical_size = 0;
#else
    struct stat source, after;
#endif
    unsigned char superblock[1024];
    int result = parse_options(argc, argv, &options);
    if (result != OK)
        goto done;
    if (clock_gettime(CLOCK_MONOTONIC, &context.deadline) != 0 ||
        (int64_t) context.deadline.tv_sec > INT64_MAX - options.timeout) {
        result = ERR_IO;
        goto done;
    }
    context.deadline.tv_sec += options.timeout;
    struct sigaction action = { 0 };
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) {
        result = ERR_IO;
        goto done;
    }
    action.sa_handler = signal_handler;
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        result = ERR_IO;
        goto done;
    }
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &action, NULL) != 0) {
        result = ERR_IO;
        goto done;
    }
    output_flags = fcntl(options.output, F_GETFL);
    status_flags = fcntl(options.status, F_GETFL);
    result = ERR_ARGUMENT;
    /* In the block target this must complete before opening any storage. */
    if (output_flags < 0 || status_flags < 0 ||
        (output_flags & O_ACCMODE) != O_WRONLY || (status_flags & O_ACCMODE) != O_WRONLY ||
        fstat(options.output, &output) != 0 || fstat(options.status, &status) != 0 ||
        !S_ISFIFO(output.st_mode) || !S_ISFIFO(status.st_mode) ||
        (output.st_dev == status.st_dev && output.st_ino == status.st_ino))
        goto done;
#ifndef TITAN_PRODUCER_BLOCK_SOURCE
    int input_flags = fcntl(options.input, F_GETFL);
    if (input_flags < 0 || (input_flags & O_ACCMODE) != O_RDONLY ||
        fstat(options.input, &source) != 0 || !S_ISREG(source.st_mode) ||
        source.st_size < 2048 || (uint64_t) source.st_size > SOURCE_LIMIT ||
        lseek(options.input, 0, SEEK_CUR) != 0)
        goto done;
#endif
    if (nonblocking(options.output) != OK || nonblocking(options.status) != OK) {
        result = ERR_IO;
        goto done;
    }
    status_ready = 1;
#ifdef TITAN_PRODUCER_BLOCK_SOURCE
    result = open_block_source(&context, &options, &source, &logical_size, superblock);
    if (result != OK)
        goto done;
#else
    result = read_superblock(&context, options.input, superblock);
    if (result != OK)
        goto done;
    if (!valid_superblock(superblock, (uint64_t) source.st_size) || fstat(options.input, &after) != 0 ||
        !unchanged(&source, &after)) {
        result = ERR_SOURCE;
        goto done;
    }
#endif
    result = launch(&context, &options);
    if (result == OK)
        result = pump(&context, &options);

done:
    /* Close data before status, including all failure paths. The launcher's
     * duplicate writer must also be closed for the receiver to observe EOF. */
    if (output_flags >= 0)
        (void) fcntl(options.output, F_SETFL, output_flags);
    close_fd(&options.output);
    close_pair(&context.raw);
    close_pair(&context.compressed);
    close_pair(&context.errors[0]);
    close_pair(&context.errors[1]);
    /* Keep the startup gate closed until all groups have been cancelled. */
    int cleanup = cancel_and_reap(&context, result == OK);
    close_pair(&context.barrier);
    if (cleanup != OK)
        result = cleanup;
    if (result == OK) {
#ifdef TITAN_PRODUCER_BLOCK_SOURCE
        result = verify_block_source(&context, &source, logical_size, superblock);
#else
        result = verify_source(&context, options.input, &source, superblock);
#endif
    }
    if (status_ready) {
        int sent = send_status(&context, options.status, result);
        if (sent != OK)
            result = sent;
    }
    if (status_flags >= 0)
        (void) fcntl(options.status, F_SETFL, status_flags);
    close_fd(&options.status);
#ifdef TITAN_PRODUCER_BLOCK_SOURCE
    /* The exclusive claim outlives children, final verification and status EOF.
     * Never close options.input separately: it is owned by this guard. */
    titan_source_close(&source);
#endif
    if (result != OK)
        report_failure();
    return result;
}
