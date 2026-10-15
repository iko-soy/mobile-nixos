/* SPDX-License-Identifier: MIT */
#ifndef TITAN_MOUNT_POLICY_H
#define TITAN_MOUNT_POLICY_H

#define TITAN_USB_CONFIGFS_PATH "/run/usb-config"

/* Internal lifecycle phases, never selected through peer input or a CLI.
 * Source acquisition in the USB profile always requires USB_SEALED_7.
 * BASELINE_6 is only for PID 1 before setup and after complete teardown.
 */
enum titan_mount_phase {
    TITAN_MOUNTS_BASELINE_6,
    TITAN_MOUNTS_USB_SEALED_7
};

/* Read-only observation of this process's current mount inventory. Zero means
 * the exact fixed inventory matched. This is not a mount lock or an assertion
 * about gadget contents, open descriptors, other namespaces or future changes.
 * The lifecycle owner must stop/reap all acquisition workers before unsealing.
 * reason, when non-NULL, receives a sanitized string with static lifetime.
 */
int titan_mount_inventory(enum titan_mount_phase phase, const char **reason);

#ifdef TITAN_MOUNT_POLICY_PARSER_TEST
/* Host parser fixtures only: read a synthetic inventory instead. */
void titan_mount_policy_test_path(const char *path);
#endif

#endif
