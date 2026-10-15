/* SPDX-License-Identifier: MIT
 * VM-only transparent ACM/UART bridge. Never link into a phone image.
 */
#ifndef TITAN_USB_VM_RELAY_H
#define TITAN_USB_VM_RELAY_H
#ifndef TITAN_USB_PIPELINE_VM_TEST
#error The ACM/UART relay is restricted to the disposable VM profile
#endif
#include <stddef.h>
#include <stdint.h>

#define TITAN_VM_RELAY_BUFFER 65536U
enum titan_vm_receipt {
    TITAN_VM_RECEIPT_NONE,
    TITAN_VM_RECEIPT_VERIFIED,
    TITAN_VM_RECEIPT_INCOMPLETE,
    TITAN_VM_RECEIPT_ABORT
};

struct titan_vm_queue {
    unsigned char bytes[TITAN_VM_RELAY_BUFFER];
    size_t offset, length;
};

struct titan_usb_vm_relay {
    int acm_fd, uart_fd, control_fd;
    struct titan_vm_queue to_host, to_gadget;
    uint64_t acm_read, uart_written, uart_read, acm_written;
    char control[32];
    size_t control_used;
    enum titan_vm_receipt receipt;
    int failed;
};

#define TITAN_USB_VM_RELAY_INITIALIZER { .acm_fd = -1, .uart_fd = -1, .control_fd = -1 }

/* Borrow already raw/nonblocking identity-checked ttyACM0; open and own fixed
 * ttyS1 data + ttyS2 receipt UARTs. Both UARTs are configured raw/exclusive.
 * Host sends exactly one TVM1 VERIFIED\n, INCOMPLETE\n or ABORT\n receipt on
 * ttyS2. VERIFIED is sent only after host protocol AND restore validation.
 */
int titan_usb_vm_relay_init(struct titan_usb_vm_relay *relay, int acm_fd,
                          const char **reason);
/* Bounded work, poll timeout zero, all I/O nonblocking. Caller provides an
 * overall deadline and calls at least every 10ms while supervising children.
 * No TTR1 parsing, byte transformation, retries, resynchronization or dropping.
 */
int titan_usb_vm_relay_step(struct titan_usb_vm_relay *relay, const char **reason);
/* Only userspace queues/counters, not USB/UART hardware drainage. A VERIFIED
 * host receipt supplies delivery and independent restore-validation evidence. */
int titan_usb_vm_relay_drained(const struct titan_usb_vm_relay *relay);
/* Closes only the two owned UARTs; the caller retains ownership of acm_fd. */
void titan_usb_vm_relay_close(struct titan_usb_vm_relay *relay);
#endif
