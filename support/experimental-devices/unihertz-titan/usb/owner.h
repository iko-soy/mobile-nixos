/* SPDX-License-Identifier: MIT */
#ifndef TITAN_USB_OWNER_H
#define TITAN_USB_OWNER_H

#include <sys/stat.h>

/* PID1-only, fixed-profile USB ownership. Never close/replace tty_fd or mutate
 * these fields. It is raw and held before bind. Failed operations preserve
 * ownership for cleanup; they never silently remove a partially built gadget.
 */
struct titan_usb {
    int tty_fd;
    int directory, mounted, readonly, prepared, bound;
    int gadget, strings, configuration, config_strings, function, linked;
    struct stat mount_identity, tty_identity;
};
#define TITAN_USB_INITIALIZER { .tty_fd = -1 }

/* Zero succeeds; reason receives a fixed sanitized string on failure. The
 * fixed polling deadlines cannot interrupt a stalled kernel syscall.
 */
int titan_usb_prepare(struct titan_usb *owner, const char **reason);
int titan_usb_bind_and_seal(struct titan_usb *owner, const char **reason);
int titan_usb_recheck(struct titan_usb *owner, const char **reason);

/* Caller MUST first stop/reap every worker and close all other gadget/host TTY
 * descriptors. This remounts configfs RW, unbinds, closes the retained TTY,
 * removes only owned objects and ordinarily unmounts. Never call while workers
 * can read storage. A failure retains remaining ownership and must fail closed.
 */
int titan_usb_cleanup(struct titan_usb *owner, const char **reason);

#ifdef TITAN_USB_PIPELINE_VM_TEST
/* Disposable dummy_hcd profile only. Caller owns the returned raw host FD. */
int titan_usb_vm_open_host(struct titan_usb *owner, const char **reason);
#endif
#endif
