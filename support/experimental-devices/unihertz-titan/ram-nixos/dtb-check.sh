# Checks that a replacement device tree keeps the running system's memory
# layout (titan-kexec --dtb; README.adoc in this directory). Every reserved
# region and memory node of the running tree, normally /sys/firmware/fdt as
# the bootloader passed it, must be present in the new tree with identical
# properties, the root's cell sizes must match, and the new tree may describe
# no memory node the running tree lacks. Extra reserved regions are allowed.
# Prints nothing and exits 0 when this holds; otherwise names the first
# difference and exits 1. Any unreadable tree or node refuses.
if [ "$#" -ne 2 ]; then
  echo "titan-dtb-check RUNNING_TREE NEW_TREE" >&2
  exit 2
fi
live=$1 new=$2
fail() { echo "titan-dtb-check: $*; nothing was loaded." >&2; exit 1; }
[ -r "$live" ] || fail "cannot read the running tree $live"
[ -r "$new" ] || fail "cannot read the new tree $new"

# A node's properties as sorted "name=hex bytes" lines, or "absent".
signature() {
  local file=$1 node=$2 prop
  local -a props
  if ! fdtget -p "$file" "$node" > /dev/null 2>&1; then
    echo absent
    return 0
  fi
  mapfile -t props < <(fdtget -p "$file" "$node" | LC_ALL=C sort)
  for prop in "${props[@]}"; do
    printf '%s=%s\n' "$prop" "$(fdtget -t bx "$file" "$node" "$prop" | tr -d '\n')"
  done
}

same() {
  local want have
  want=$(signature "$live" "$1")
  have=$(signature "$new" "$1")
  [ "$want" != absent ] || fail "the running tree has no $1"
  [ "$want" = "$have" ] || fail "$1 differs from the running tree"
}

# Root nodes whose device_type is "memory".
memory_nodes() {
  local file=$1 node
  local -a nodes
  fdtget -l "$file" / > /dev/null || fail "cannot list the root of $file"
  mapfile -t nodes < <(fdtget -l "$file" /)
  for node in "${nodes[@]}"; do
    if [ "$(fdtget -t s "$file" "/$node" device_type 2>/dev/null || true)" = memory ]; then
      echo "$node"
    fi
  done
}

for cells in '#address-cells' '#size-cells'; do
  want=$(fdtget -t bx "$live" / "$cells") || fail "the running tree has no root $cells"
  have=$(fdtget -t bx "$new" / "$cells" 2>/dev/null) || fail "the new tree has no root $cells"
  [ "$want" = "$have" ] || fail "the root $cells differs from the running tree"
done

same /reserved-memory
fdtget -l "$live" /reserved-memory > /dev/null || fail "cannot list the running tree's reserved memory"
mapfile -t reserved < <(fdtget -l "$live" /reserved-memory)
for node in "${reserved[@]}"; do
  same "/reserved-memory/$node"
done

live_memory=$(memory_nodes "$live")
new_memory=$(memory_nodes "$new")
[ -n "$live_memory" ] || fail "the running tree has no memory node"
[ "$live_memory" = "$new_memory" ] || fail "the memory nodes differ from the running tree's"
while IFS= read -r node; do
  same "/$node"
done <<< "$live_memory"
