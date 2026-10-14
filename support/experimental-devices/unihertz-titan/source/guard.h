/* SPDX-License-Identifier: MIT */
#ifndef TITAN_SOURCE_GUARD_H
#define TITAN_SOURCE_GUARD_H

#include <sys/stat.h>

#define TITAN_SOURCE_PATH_MAX 4096

/* Initialize with TITAN_SOURCE_INITIALIZER. Do not replace, close, or modify
 * these descriptors/fields while a claim is active. The two block descriptors
 * are read-only; the partition descriptor retains the exclusive kernel claim.
 * Recheck failure retains that claim until titan_source_close(). Passing a
 * check is not a snapshot, an acquisition authorization, or a deadline promise.
 */
struct titan_source {
    int disk_fd;
    int partition_fd;
    int disk_sysfs_fd;
    int partition_sysfs_fd;
    int namespace_fd;
    int root_fd;
    int ready;
    struct stat disk_identity;
    struct stat partition_identity;
    struct stat disk_sysfs_identity;
    struct stat partition_sysfs_identity;
    struct stat namespace_identity;
    struct stat root_identity;
    char disk_sysfs_path[TITAN_SOURCE_PATH_MAX];
    char partition_sysfs_path[TITAN_SOURCE_PATH_MAX];
};

#define TITAN_SOURCE_INITIALIZER { \
    .disk_fd = -1, .partition_fd = -1, \
    .disk_sysfs_fd = -1, .partition_sysfs_fd = -1, \
    .namespace_fd = -1, .root_fd = -1 \
}

/* Return zero on success, nonzero on failure. reason, when non-NULL, receives
 * a fixed sanitized string with static lifetime. A failed open releases any
 * partial claim. Opening an already-open object fails without closing it.
 */
int titan_source_open(struct titan_source *source, const char **reason);
int titan_source_recheck(struct titan_source *source, const char **reason);
void titan_source_close(struct titan_source *source);

#endif
