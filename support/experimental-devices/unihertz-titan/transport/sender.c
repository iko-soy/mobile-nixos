/* SPDX-License-Identifier: MIT
 * Off-device, one-shot TTR1 sender. See protocol.adoc. No path is opened here. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define HEADER_SIZE 48U
#define PAYLOAD_SIZE 32768U
#define ABSOLUTE_LIMIT UINT64_C(1099511627776)

enum { HELLO = 1, BEGIN, DATA, END, ACK, COMPLETE, ERROR_FRAME };
enum {
    OK = 0, ERR_ARGUMENT = 1, ERR_IO = 2, ERR_PROTOCOL = 3,
    ERR_LIMIT = 4, ERR_PRODUCER = 5, ERR_TIMEOUT = 6, ERR_CRYPTO = 7
};

struct descriptor {
    int fd;
    int original_status;
    int original_descriptor;
    int saved;
};

struct session {
    int transport;
    struct timespec deadline;
    unsigned char nonce[32];
    int have_nonce;
    uint32_t sequence;
};

struct options {
    int input;
    int transport;
    int status;
    const char *label;
    uint64_t limit;
    unsigned int timeout;
};

static volatile sig_atomic_t interrupted;

static void interrupt_handler(int signal_number)
{
    (void) signal_number;
    interrupted = 1;
}

static void put32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char) (value >> 24);
    p[1] = (unsigned char) (value >> 16);
    p[2] = (unsigned char) (value >> 8);
    p[3] = (unsigned char) value;
}

static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | p[3];
}

static void put64(unsigned char *p, uint64_t value)
{
    put32(p, (uint32_t) (value >> 32));
    put32(p + 4, (uint32_t) value);
}

static uint64_t get64(const unsigned char *p)
{
    return ((uint64_t) get32(p) << 32) | get32(p + 4);
}

static int alphanumeric(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static int valid_label(const char *label)
{
    size_t length = strlen(label);
    if (length == 0 || length > 64 || !alphanumeric((unsigned char) label[0]))
        return 0;
    for (size_t i = 1; i < length; ++i) {
        unsigned char c = (unsigned char) label[i];
        if (!alphanumeric(c) && c != '.' && c != '_' && c != '-')
            return 0;
    }
    return 1;
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
    options->status = -1;
    for (int i = 1; i < argc; i += 2) {
        unsigned int bit;
        uint64_t value;
        if (i + 1 == argc)
            return ERR_ARGUMENT;
        if (strcmp(argv[i], "--label") == 0) {
            bit = 1U;
            if (!valid_label(argv[i + 1]))
                return ERR_ARGUMENT;
            options->label = argv[i + 1];
        } else if (strcmp(argv[i], "--max-bytes") == 0) {
            bit = 2U;
            if (!decimal(argv[i + 1], ABSOLUTE_LIMIT, &value) || value == 0)
                return ERR_ARGUMENT;
            options->limit = value;
        } else if (strcmp(argv[i], "--timeout-seconds") == 0) {
            bit = 4U;
            if (!decimal(argv[i + 1], INT_MAX, &value) || value == 0)
                return ERR_ARGUMENT;
            options->timeout = (unsigned int) value;
        } else {
            if (strcmp(argv[i], "--input-fd") == 0)
                bit = 8U;
            else if (strcmp(argv[i], "--transport-fd") == 0)
                bit = 16U;
            else if (strcmp(argv[i], "--status-fd") == 0)
                bit = 32U;
            else
                return ERR_ARGUMENT;
            /* Descriptor 2 is reserved for fixed local diagnostics. */
            if (!decimal(argv[i + 1], INT_MAX, &value) || value == STDERR_FILENO)
                return ERR_ARGUMENT;
            if (bit == 8U)
                options->input = (int) value;
            else if (bit == 16U)
                options->transport = (int) value;
            else
                options->status = (int) value;
        }
        if ((seen & bit) != 0)
            return ERR_ARGUMENT;
        seen |= bit;
    }
    if ((seen & 31U) != 31U || options->input == options->transport ||
        options->status == options->input || options->status == options->transport)
        return ERR_ARGUMENT;
    return OK;
}

/* Every data syscall is preceded by poll and a fresh absolute-deadline check.
 * Nonblocking descriptors prevent the subsequent read/write from waiting for
 * transport readiness. A regular-file syscall can still stall in the kernel. */
static int remaining_ms(const struct session *session, int *milliseconds)
{
    struct timespec now;
    if (interrupted)
        return ERR_IO;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return ERR_IO;
    int64_t seconds = (int64_t) session->deadline.tv_sec - (int64_t) now.tv_sec;
    int64_t nanos = (int64_t) session->deadline.tv_nsec - (int64_t) now.tv_nsec;
    if (nanos < 0) {
        --seconds;
        nanos += INT64_C(1000000000);
    }
    if (seconds < 0 || (seconds == 0 && nanos == 0))
        return ERR_TIMEOUT;
    if (seconds >= INT_MAX / 1000)
        *milliseconds = INT_MAX;
    else
        *milliseconds = (int) (seconds * 1000 + (nanos + 999999) / 1000000);
    return OK;
}

static int wait_ready(const struct session *session, int fd, short events)
{
    for (;;) {
        int milliseconds;
        int result = remaining_ms(session, &milliseconds);
        if (result != OK)
            return result;
        struct pollfd request = { .fd = fd, .events = events, .revents = 0 };
        int ready = poll(&request, 1, milliseconds);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return ERR_IO;
        }
        if (ready == 0)
            continue;
        if ((request.revents & (POLLNVAL | POLLERR)) != 0)
            return ERR_IO;
        if ((request.revents & events) != 0 ||
            (events == POLLIN && (request.revents & POLLHUP) != 0))
            return remaining_ms(session, &milliseconds);
        if ((request.revents & POLLHUP) != 0)
            return ERR_IO;
    }
}

static int read_some(const struct session *session, int fd, void *buffer,
                     size_t capacity, size_t *length)
{
    for (;;) {
        int result = wait_ready(session, fd, POLLIN);
        if (result != OK)
            return result;
        ssize_t amount = read(fd, buffer, capacity);
        if (amount >= 0) {
            *length = (size_t) amount;
            return OK;
        }
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            return ERR_IO;
    }
}

static int read_exact(const struct session *session, int fd, unsigned char *buffer,
                      size_t length, int eof_error)
{
    while (length > 0) {
        size_t amount;
        int result = read_some(session, fd, buffer, length, &amount);
        if (result != OK)
            return result;
        if (amount == 0)
            return eof_error;
        buffer += amount;
        length -= amount;
    }
    return OK;
}

static int write_exact(const struct session *session, const unsigned char *buffer,
                       size_t length)
{
    while (length > 0) {
        int result = wait_ready(session, session->transport, POLLOUT);
        if (result != OK)
            return result;
        ssize_t amount = write(session->transport, buffer, length);
        if (amount < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return ERR_IO;
        }
        if (amount == 0)
            return ERR_IO;
        buffer += amount;
        length -= (size_t) amount;
    }
    return OK;
}

static int send_frame(const struct session *session, unsigned char type,
                      uint32_t sequence, const unsigned char *payload,
                      uint32_t length)
{
    unsigned char header[HEADER_SIZE] = { 'T', 'T', 'R', '1' };
    header[4] = type;
    put32(header + 8, sequence);
    put32(header + 12, length);
    memcpy(header + 16, session->nonce, sizeof(session->nonce));
    int result = write_exact(session, header, sizeof(header));
    if (result != OK)
        return result;
    return write_exact(session, payload, length);
}

static int receive_frame(struct session *session, unsigned char type,
                         uint32_t sequence, unsigned char *payload,
                         uint32_t minimum, uint32_t maximum, uint32_t *length)
{
    unsigned char header[HEADER_SIZE];
    int result = read_exact(session, session->transport, header, sizeof(header),
                            ERR_PROTOCOL);
    if (result != OK)
        return result;
    *length = get32(header + 12);
    if (memcmp(header, "TTR1", 4) != 0 || header[4] != type ||
        header[5] != 0 || header[6] != 0 || header[7] != 0 ||
        get32(header + 8) != sequence || *length < minimum ||
        *length > maximum || *length > PAYLOAD_SIZE)
        return ERR_PROTOCOL;
    if (session->have_nonce) {
        if (memcmp(header + 16, session->nonce, sizeof(session->nonce)) != 0)
            return ERR_PROTOCOL;
    } else {
        memcpy(session->nonce, header + 16, sizeof(session->nonce));
        session->have_nonce = 1;
    }
    return read_exact(session, session->transport, payload, *length, ERR_PROTOCOL);
}

static int save_descriptor(struct descriptor *descriptor)
{
    descriptor->original_status = fcntl(descriptor->fd, F_GETFL);
    descriptor->original_descriptor = fcntl(descriptor->fd, F_GETFD);
    if (descriptor->original_status < 0 || descriptor->original_descriptor < 0)
        return ERR_ARGUMENT;
    descriptor->saved = 1;
    return OK;
}

static int prepare_descriptor(const struct descriptor *descriptor)
{
    if (fcntl(descriptor->fd, F_SETFD,
              descriptor->original_descriptor | FD_CLOEXEC) != 0 ||
        fcntl(descriptor->fd, F_SETFL,
              descriptor->original_status | O_NONBLOCK) != 0)
        return ERR_IO;
    return OK;
}

static int restore_descriptor(const struct descriptor *descriptor)
{
    if (!descriptor->saved)
        return OK;
    int status = fcntl(descriptor->fd, F_SETFL, descriptor->original_status);
    int flags = fcntl(descriptor->fd, F_SETFD, descriptor->original_descriptor);
    return status == 0 && flags == 0 ? OK : ERR_IO;
}

static int unchanged(const struct stat *initial, const struct stat *final)
{
#ifdef __APPLE__
#define TTR_MTIME st_mtimespec
#define TTR_CTIME st_ctimespec
#else
#define TTR_MTIME st_mtim
#define TTR_CTIME st_ctim
#endif
    return initial->st_dev == final->st_dev && initial->st_ino == final->st_ino &&
           initial->st_mode == final->st_mode && initial->st_nlink == final->st_nlink &&
           initial->st_size == final->st_size &&
           initial->TTR_MTIME.tv_sec == final->TTR_MTIME.tv_sec &&
           initial->TTR_MTIME.tv_nsec == final->TTR_MTIME.tv_nsec &&
           initial->TTR_CTIME.tv_sec == final->TTR_CTIME.tv_sec &&
           initial->TTR_CTIME.tv_nsec == final->TTR_CTIME.tv_nsec;
#undef TTR_MTIME
#undef TTR_CTIME
}

static int transfer(struct session *session, const struct options *options,
                    const struct stat *initial, EVP_MD_CTX *digest)
{
    unsigned char payload[PAYLOAD_SIZE];
    unsigned char end_payload[40];
    uint32_t length;
    uint64_t total = 0;
    int is_pipe = S_ISFIFO(initial->st_mode);
    size_t label_length = strlen(options->label);
    int result = receive_frame(session, HELLO, 0, payload, 11, 74, &length);
    if (result != OK)
        return result;
    uint64_t host_limit = get64(payload);
    unsigned int peer_label_length = ((unsigned int) payload[8] << 8) | payload[9];
    if (host_limit == 0 || host_limit > ABSOLUTE_LIMIT ||
        peer_label_length != label_length || length != 10U + label_length ||
        memcmp(payload + 10, options->label, label_length) != 0)
        return ERR_PROTOCOL;
    uint64_t limit = host_limit < options->limit ? host_limit : options->limit;
    if (!is_pipe && (uint64_t) initial->st_size > limit)
        return ERR_LIMIT;

    put64(payload, limit);
    payload[8] = (unsigned char) is_pipe;
    put64(payload + 9, is_pipe ? UINT64_MAX : (uint64_t) initial->st_size);
    payload[17] = 0;
    payload[18] = (unsigned char) label_length;
    memcpy(payload + 19, options->label, label_length);
    result = send_frame(session, BEGIN, 0, payload, (uint32_t) (19 + label_length));
    if (result != OK)
        return result;
    session->sequence = 1;

    for (;;) {
        size_t amount;
        /* Probe one byte for EOF when exactly at the bound; never transmit it. */
        size_t capacity = limit == total ? 1 :
            (limit - total < PAYLOAD_SIZE ? (size_t) (limit - total) : PAYLOAD_SIZE);
        result = read_some(session, options->input, payload, capacity, &amount);
        if (result != OK)
            return result;
        if (amount == 0)
            break;
        if (amount > limit - total || session->sequence == UINT32_MAX)
            return ERR_LIMIT;
        if (EVP_DigestUpdate(digest, payload, amount) != 1)
            return ERR_CRYPTO;
        result = send_frame(session, DATA, session->sequence, payload, (uint32_t) amount);
        if (result != OK)
            return result;
        total += amount;
        ++session->sequence;
    }

    if (is_pipe) {
        result = read_exact(session, options->status, payload, 8, ERR_PRODUCER);
        if (result != OK)
            return result;
        if (memcmp(payload, "TPST", 4) != 0 || get32(payload + 4) != 0)
            return ERR_PRODUCER;
        size_t extra;
        result = read_some(session, options->status, payload, 1, &extra);
        if (result != OK)
            return result;
        if (extra != 0)
            return ERR_PRODUCER;
    } else {
        struct stat final;
        if (fstat(options->input, &final) != 0)
            return ERR_IO;
        if (total != (uint64_t) initial->st_size || !unchanged(initial, &final) ||
            lseek(options->input, 0, SEEK_CUR) != initial->st_size)
            return ERR_LIMIT;
    }

    unsigned int digest_length;
    put64(end_payload, total);
    if (EVP_DigestFinal_ex(digest, end_payload + 8, &digest_length) != 1 ||
        digest_length != 32)
        return ERR_CRYPTO;
    result = send_frame(session, END, session->sequence, end_payload, sizeof(end_payload));
    if (result != OK)
        return result;
    result = receive_frame(session, ACK, session->sequence, payload,
                           sizeof(end_payload), sizeof(end_payload), &length);
    if (result != OK)
        return result;
    if (memcmp(payload, end_payload, sizeof(end_payload)) != 0)
        return ERR_PROTOCOL;
    return send_frame(session, COMPLETE, session->sequence, end_payload, sizeof(end_payload));
}

static const char *diagnostic(int error)
{
    switch (error) {
    case ERR_ARGUMENT: return "titan-sender: invalid arguments or descriptors\n";
    case ERR_IO: return "titan-sender: I/O failure or interruption\n";
    case ERR_PROTOCOL: return "titan-sender: invalid protocol exchange\n";
    case ERR_LIMIT: return "titan-sender: byte limit or source consistency failure\n";
    case ERR_PRODUCER: return "titan-sender: producer completion was not verified\n";
    case ERR_TIMEOUT: return "titan-sender: absolute deadline expired\n";
    default: return "titan-sender: digest operation failed\n";
    }
}

static void report_error(int error)
{
    /* A full inherited diagnostic pipe must not outlive the transfer deadline. */
    int original = fcntl(STDERR_FILENO, F_GETFL);
    if (original < 0 || fcntl(STDERR_FILENO, F_SETFL, original | O_NONBLOCK) != 0)
        return;
    const char *message = diagnostic(error);
    (void) write(STDERR_FILENO, message, strlen(message));
    (void) fcntl(STDERR_FILENO, F_SETFL, original);
}

int main(int argc, char **argv)
{
    struct options options = { 0 };
    struct session session = { 0 };
    struct descriptor descriptors[3] = { { .fd = -1 }, { .fd = -1 }, { .fd = -1 } };
    struct stat source, transport, status;
    struct termios original_termios;
    int termios_saved = 0;
    EVP_MD_CTX *digest = NULL;
    int result;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        fputs("Usage: titan-sender --input-fd N --transport-fd N --label LABEL "
              "--max-bytes N --timeout-seconds N [--status-fd N]\n"
              "Read-only regular file (offset zero) or FIFO; FIFO needs a separate "
              "read-only status FIFO. Descriptor 2 is reserved for diagnostics.\n", stdout);
        return 0;
    }
    result = parse_options(argc, argv, &options);
    if (result != OK)
        goto done;
    session.transport = options.transport;
    if (clock_gettime(CLOCK_MONOTONIC, &session.deadline) != 0 ||
        (int64_t) session.deadline.tv_sec > INT64_MAX - options.timeout) {
        result = ERR_IO;
        goto done;
    }
    session.deadline.tv_sec += options.timeout;

    struct sigaction action = { 0 };
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL) != 0) {
        result = ERR_IO;
        goto done;
    }
    action.sa_handler = interrupt_handler;
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGHUP, &action, NULL) != 0) {
        result = ERR_IO;
        goto done;
    }

    descriptors[0].fd = options.input;
    descriptors[1].fd = options.transport;
    descriptors[2].fd = options.status;
    for (size_t i = 0; i < 3; ++i) {
        if (descriptors[i].fd >= 0 && (result = save_descriptor(&descriptors[i])) != OK)
            goto done;
    }
    result = ERR_ARGUMENT;
    if ((descriptors[0].original_status & O_ACCMODE) != O_RDONLY ||
        (descriptors[1].original_status & O_ACCMODE) != O_RDWR ||
        fstat(options.input, &source) != 0 || fstat(options.transport, &transport) != 0 ||
        (!S_ISREG(source.st_mode) && !S_ISFIFO(source.st_mode)))
        goto done;
    if (S_ISREG(source.st_mode)) {
        if (options.status >= 0 || source.st_size < 0 ||
            (uint64_t) source.st_size > options.limit || lseek(options.input, 0, SEEK_CUR) != 0)
            goto done;
    } else {
        if (options.status < 0 ||
            (descriptors[2].original_status & O_ACCMODE) != O_RDONLY ||
            fstat(options.status, &status) != 0 || !S_ISFIFO(status.st_mode) ||
            (source.st_dev == status.st_dev && source.st_ino == status.st_ino))
            goto done;
    }
    if (S_ISSOCK(transport.st_mode)) {
        int socket_type;
        socklen_t size = sizeof(socket_type);
        if (getsockopt(options.transport, SOL_SOCKET, SO_TYPE, &socket_type, &size) != 0 ||
            socket_type != SOCK_STREAM)
            goto done;
    } else if (S_ISCHR(transport.st_mode) && isatty(options.transport)) {
        struct termios raw;
        if (tcgetattr(options.transport, &original_termios) != 0)
            goto done;
        raw = original_termios;
        raw.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXOFF);
#ifdef IXANY
        raw.c_iflag &= ~IXANY;
#endif
        raw.c_oflag &= ~OPOST;
        raw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        raw.c_cflag &= ~(CSIZE | PARENB);
#ifdef CRTSCTS
        raw.c_cflag &= ~CRTSCTS;
#endif
#ifdef CCTS_OFLOW
        raw.c_cflag &= ~CCTS_OFLOW;
#endif
#ifdef CRTS_IFLOW
        raw.c_cflag &= ~CRTS_IFLOW;
#endif
#ifdef CDTR_IFLOW
        raw.c_cflag &= ~CDTR_IFLOW;
#endif
#ifdef CDSR_OFLOW
        raw.c_cflag &= ~CDSR_OFLOW;
#endif
#ifdef CCAR_OFLOW
        raw.c_cflag &= ~CCAR_OFLOW;
#endif
#ifdef MDMBUF
        raw.c_cflag &= ~MDMBUF;
#endif
        raw.c_cflag |= CS8 | CREAD | CLOCAL;
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        termios_saved = 1;
        if (tcsetattr(options.transport, TCSANOW, &raw) != 0) {
            result = ERR_IO;
            goto done;
        }
    } else {
        goto done;
    }
    for (size_t i = 0; i < 3; ++i) {
        if (descriptors[i].fd >= 0 && (result = prepare_descriptor(&descriptors[i])) != OK)
            goto done;
    }
    if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
        result = ERR_CRYPTO;
        goto done;
    }
    digest = EVP_MD_CTX_new();
    if (digest == NULL || EVP_DigestInit_ex(digest, EVP_sha256(), NULL) != 1) {
        result = ERR_CRYPTO;
        goto done;
    }
    result = transfer(&session, &options, &source, digest);

done:
    if (result != OK && session.have_nonce) {
        unsigned char error_payload[4];
        put32(error_payload, (uint32_t) result);
        (void) send_frame(&session, ERROR_FRAME, session.sequence, error_payload, sizeof(error_payload));
    }
    if (digest != NULL)
        EVP_MD_CTX_free(digest);
    if (termios_saved && tcsetattr(options.transport, TCSANOW, &original_termios) != 0)
        result = ERR_IO;
    for (size_t i = 0; i < 3; ++i) {
        if (restore_descriptor(&descriptors[i]) != OK)
            result = ERR_IO;
    }
    if (result != OK)
        report_error(result);
    return result;
}
