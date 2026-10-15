{ pkgs, name, init, programs ? {}, modules }:

# Shared bootstrap for the new mount-policy and integrated USB VM fixtures.
# This is never used to construct an AArch64 phone ramdisk.
let
  inherit (pkgs) lib;
  kernel = pkgs.linux;
  binaries = { busybox = "${pkgs.pkgsStatic.busybox}/bin/busybox"; } // programs;
in pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.xz pkgs.zstd pkgs.kmod pkgs.binutils ];
  meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
} ''
  set -o pipefail
  mkdir -p root/{bin,dev,proc,sys,run,tmp,vm-modules} "$out"
  install -m 0555 ${init}/bin/init root/rescue-init
  ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: path:
    "install -m 0555 ${path} root/bin/${name}") binaries)}
  for binary in root/rescue-init root/bin/*; do
    readelf -h "$binary" > "$out/$(basename "$binary").elf.txt"
    readelf -l "$binary" > "$out/$(basename "$binary").segments.txt"
    readelf -d "$binary" > "$out/$(basename "$binary").dynamic.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$out/$(basename "$binary").elf.txt"
    grep -Eq 'Machine:.*X86-64' "$out/$(basename "$binary").elf.txt"
    if grep -q INTERP "$out/$(basename "$binary").segments.txt" \
        || grep -q '(NEEDED)' "$out/$(basename "$binary").dynamic.txt"; then
      echo "Unexpected dynamic VM binary: $binary" >&2
      exit 1
    fi
  done
  for module in ${lib.concatStringsSep " " modules}; do
    modprobe --set-version ${kernel.modDirVersion} --dirname ${kernel.modules} \
      --show-depends "$module"
  done | awk '$1 == "insmod" && !seen[$2]++ { print $2 }' > modules.list
  number=0
  while IFS= read -r module; do
    destination=$(printf 'root/vm-modules/%03d.ko' "$number")
    case "$module" in
      *.xz) xz -dc "$module" > "$destination" ;;
      *.zst) zstd -dc "$module" > "$destination" ;;
      *.gz) gzip -dc "$module" > "$destination" ;;
      *.ko) cp "$module" "$destination" ;;
      *) echo "Unexpected module format: $module" >&2; exit 1 ;;
    esac
    number=$((number + 1))
  done < modules.list
  cat > root/init <<'EOF'
  #!/bin/busybox sh
  for module in /vm-modules/*.ko; do
    [ -f "$module" ] || continue
    /bin/busybox insmod "$module" || exit 1
  done
  exec /rescue-init
  EOF
  chmod 0555 root/init
  find root -exec touch -h -d @1 -- {} +
  (cd root; find . -print0 | LC_ALL=C sort -z \
    | cpio --null -o -H newc --reproducible --owner=0:0 \
    | gzip -n -9) > "$out/initramfs.cpio.gz"
  (cd "$out"; sha256sum initramfs.cpio.gz) > "$out/SHA256SUMS"
  cp modules.list "$out/modules.list"
''
