#!/bin/sh
# Stage 0 of the RAM-only NixOS system (README.adoc in this directory), PID 1
# of the recovery image. It never mounts or opens storage and refuses to go on
# while any disk exists. It binds a USB gadget with a network function and a
# status port, offers the Mac one DHCP lease, receives the NixOS store
# squashfs over TCP, and starts NixOS only from a squashfs with the size and
# SHA-256 pinned below. Any failure, and its own deadline, restarts the phone;
# a separate hard deadline started first survives into NixOS. Values in @...@
# are substituted at build time.
export PATH=/bin

SYSTEM_BYTES=@systemBytes@
SYSTEM_SHA256=@systemSha256@
NIXOS_INIT=@nixosInit@
UDC=@udc@
DATA_INTERFACE=@dataInterface@
DEADLINE_SECONDS=@deadlineSeconds@
HARD_DEADLINE_SECONDS=@hardDeadlineSeconds@
GADGET=/sys/kernel/config/usb_gadget/titan-ram
PORT=7000
STATUS=

say() {
  echo "TITAN_RAM $*"
  echo "<5>titan-ram: $*" > /dev/kmsg 2>/dev/null
  [ -z "$STATUS" ] && [ -f /run/titan-ram-status ] && STATUS=$(cat /run/titan-ram-status)
  # The status port buffers a few KiB while no host reads; never block on it.
  [ -n "$STATUS" ] && [ -c "$STATUS" ] &&
    timeout 2 sh -c 'echo "TITAN_RAM $1" > "$2"' sh "$*" "$STATUS" 2>/dev/null
}

restart() {
  say "restart reason=$1"
  sync
  reboot -f
  # Only if the restart call itself failed: PID 1 exiting panics the kernel,
  # which restarts after the command line's panic timeout.
  exit 1
}

check_storage() {
  for entry in /sys/class/block/*; do
    [ -e "$entry" ] || continue
    name=${entry##*/}
    case "$name" in
      loop*|ram*|zram*) ;;
      *) restart "storage-present-$name" ;;
    esac
  done
}

write() {
  echo "$2" > "$GADGET/$1" || restart "gadget-write-$1"
}

mount -t proc -o nosuid,nodev,noexec proc /proc || restart mount-proc
mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || restart mount-sys
mount -t devtmpfs -o nosuid,mode=0755 devtmpfs /dev || restart mount-dev
mkdir -p /dev/pts /dev/shm
mount -t devpts -o nosuid,noexec,mode=0620,ptmxmode=0666,gid=3 devpts /dev/pts || restart mount-devpts
mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /dev/shm || restart mount-shm
mount -t tmpfs -o nosuid,nodev,strictatime,mode=0755,size=25% tmpfs /run || restart mount-run
say "stage0 start"

# Restarts at a fixed uptime from here on, in stage 0 or in NixOS.
titan-deadline "$HARD_DEADLINE_SECONDS" &
sleep 1
kill -0 $! 2>/dev/null || restart hard-deadline
( sleep "$DEADLINE_SECONDS"; say "deadline"; sync; reboot -f ) &
DEADLINE_PID=$!

# Only the VM build carries modules; the phone kernel has everything built in.
if [ -d /vm-modules ]; then
  for module in /vm-modules/*.ko; do
    [ -f "$module" ] || continue
    insmod "$module" || restart "insmod-${module##*/}"
  done
fi
mount -t configfs configfs /sys/kernel/config || restart mount-configfs

mkdir "$GADGET" || restart gadget-create
write idVendor 0x1209
write idProduct 0x0005
write bcdUSB 0x0200
write bcdDevice 0x0200
write bDeviceClass 0xef
write bDeviceSubClass 0x02
write bDeviceProtocol 0x01
mkdir "$GADGET/strings/0x409" || restart gadget-strings
write strings/0x409/manufacturer "Titan rescue experiment"
write strings/0x409/product "Titan RAM NixOS"
write strings/0x409/serialnumber "TITAN-RAM-NIXOS-0001"
mkdir "$GADGET/configs/c.1" "$GADGET/configs/c.1/strings/0x409" || restart gadget-config
write configs/c.1/strings/0x409/configuration "RAM NixOS"
write configs/c.1/bmAttributes 0x80
write configs/c.1/MaxPower 50
mkdir "$GADGET/functions/ncm.usb0" "$GADGET/functions/acm.usb0" || restart gadget-functions
write functions/ncm.usb0/dev_addr 02:74:69:74:61:01
write functions/ncm.usb0/host_addr 02:74:69:74:61:02
ln -s "$GADGET/functions/ncm.usb0" "$GADGET/configs/c.1/ncm.usb0" || restart gadget-link-ncm
ln -s "$GADGET/functions/acm.usb0" "$GADGET/configs/c.1/acm.usb0" || restart gadget-link-acm
waited=0
while [ ! -e "/sys/class/udc/$UDC" ]; do
  waited=$((waited + 1))
  [ "$waited" -le 30 ] || restart udc-missing
  sleep 1
done
write UDC "$UDC"
STATUS=/dev/ttyGS$(cat "$GADGET/functions/acm.usb0/port_num") || restart acm-port
echo "$STATUS" > /run/titan-ram-status
say "usb-bound udc=$UDC"

# Checked once the status port can report a refusal, before any networking.
sleep 2
check_storage
say "storage-none block=$(ls /sys/class/block | tr '\n' ' ')"

interface=$(cat "$GADGET/functions/ncm.usb0/ifname") || restart ncm-ifname
[ -n "$DATA_INTERFACE" ] && interface=$DATA_INTERFACE
ip link set "$interface" up || restart "link-up-$interface"
ip addr add 172.16.42.1/24 dev "$interface" || restart "address-$interface"
# One lease, 172.16.42.2, with no router or name server options.
cat > /run/udhcpd.conf <<EOF || restart udhcpd-config
start 172.16.42.2
end 172.16.42.2
interface $interface
max_leases 1
lease_file /run/udhcpd.leases
pidfile /run/udhcpd.pid
opt subnet 255.255.255.0
opt lease 3600
EOF
: > /run/udhcpd.leases || restart udhcpd-leases
udhcpd -f /run/udhcpd.conf &
UDHCPD_PID=$!
sleep 1
kill -0 "$UDHCPD_PID" 2>/dev/null || restart udhcpd-exited
say "network-up interface=$interface address=172.16.42.1"

mount -t tmpfs -o mode=0755,size=50% tmpfs /sysroot || restart mount-sysroot
mkdir -p /sysroot/nix/.ro-store /sysroot/nix/.rw-store/store /sysroot/nix/.rw-store/work /sysroot/nix/store ||
  restart sysroot-layout
image=/sysroot/nix/.system.squashfs
attempt=0
while :; do
  attempt=$((attempt + 1))
  say "waiting-for-system port=$PORT bytes=$SYSTEM_BYTES attempt=$attempt"
  rm -f "$image"
  # Never more than the pinned size is written; a short or wrong stream is
  # discarded and the port listens again until the deadline.
  nc -l -p "$PORT" < /dev/null | head -c "$SYSTEM_BYTES" > "$image"
  size=$(stat -c %s "$image" 2>/dev/null)
  if [ "$size" = "$SYSTEM_BYTES" ] && echo "$SYSTEM_SHA256  $image" | sha256sum -c -s; then
    break
  fi
  say "system-rejected bytes=${size:-0}"
done
say "system-verified sha256=$SYSTEM_SHA256"

mount -t squashfs -o ro,loop "$image" /sysroot/nix/.ro-store || restart mount-squashfs
mount -t overlay overlay \
  -o lowerdir=/sysroot/nix/.ro-store,upperdir=/sysroot/nix/.rw-store/store,workdir=/sysroot/nix/.rw-store/work \
  /sysroot/nix/store || restart mount-overlay
[ -x "/sysroot$NIXOS_INIT" ] || restart nixos-init-missing
check_storage

kill "$UDHCPD_PID" 2>/dev/null
kill "$DEADLINE_PID" 2>/dev/null
say "starting-nixos init=$NIXOS_INIT"
mkdir -p /sysroot/proc /sysroot/sys /sysroot/dev /sysroot/run || restart sysroot-mountpoints
for mountpoint in /proc /sys /dev /run; do
  mount -o move "$mountpoint" "/sysroot$mountpoint" || restart "move-$mountpoint"
done
exec env -i /bin/switch_root /sysroot "$NIXOS_INIT"
restart switch-root
