{ pkgs }:

# Fixed-profile, read-only source preflight. The production checker neither
# reads partition contents nor launches the producer or configures the phone.
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  source = lib.cleanSourceWith {
    src = ./source;
    filter = path: type:
      let name = baseNameOf path;
      in (type == "directory" && name != "__pycache__")
        || (type == "regular" && (lib.hasSuffix ".c" name || lib.hasSuffix ".h" name));
  };
  checker = target.stdenv.mkDerivation {
    pname = "titan-storage-preflight";
    version = "1";
    src = source;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        guard.c check.c -o titan-storage-preflight
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-storage-preflight "$out/bin/titan-storage-preflight"
    '';
    meta = {
      description = "Fixed-profile Titan userdata preflight; no acquisition or phone boot claim";
      license = lib.licenses.mit;
      platforms = lib.platforms.linux;
      hydraPlatforms = [];
    };
  };
  vmInit = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "titan-storage-VM-TEST-ONLY-init";
    version = "1";
    src = source;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5 \
        -DTITAN_SOURCE_VM_TEST ${./rescue/init.c} guard.c vm-test.c -o init
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 init "$out/bin/init"
    '';
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  };
  vmKernel = pkgs.linux;
  vmRamdisk = pkgs.runCommand "titan-storage-VM-TEST-ONLY-initramfs" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.xz pkgs.zstd pkgs.kmod ];
    meta.hydraPlatforms = [];
  } ''
    set -o pipefail
    mkdir -p root/{bin,dev,proc,sys,run,tmp,vm-modules} "$out"
    install -m 0555 ${vmInit}/bin/init root/rescue-init
    install -m 0555 ${pkgs.pkgsStatic.busybox}/bin/busybox root/bin/busybox
    for module in virtio_pci virtio_blk; do
      modprobe --set-version ${vmKernel.modDirVersion} --dirname ${vmKernel.modules} \
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
  '';
  vmTests = pkgs.runCommand "titan-storage-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    python3 ${./source/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${vmKernel}/bzImage \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$out"
    readelf -h ${checker}/bin/titan-storage-preflight > "$out/checker.elf.txt"
    readelf -l ${checker}/bin/titan-storage-preflight > "$out/checker.segments.txt"
    readelf -d ${checker}/bin/titan-storage-preflight > "$out/checker.dynamic.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$out/checker.elf.txt"
    grep -Eq 'Machine:[[:space:]]+AArch64' "$out/checker.elf.txt"
    if grep -q INTERP "$out/checker.segments.txt" \
        || grep -q '(NEEDED)' "$out/checker.dynamic.txt"; then
      echo 'Storage preflight unexpectedly depends on a dynamic loader or library' >&2
      exit 1
    fi
    # Production must not accept an alternative device/profile at runtime.
    status=0
    ${pkgs.qemu-user}/bin/qemu-aarch64 ${checker}/bin/titan-storage-preflight \
      --device /dev/vda1 > "$out/override.stdout" 2> "$out/override.stderr" || status=$?
    test "$status" = 2
    test ! -s "$out/override.stdout"
    grep -Fx 'TITAN_SOURCE_REFUSED arguments' "$out/override.stderr"
    sha256sum ${checker}/bin/titan-storage-preflight > "$out/checker-SHA256SUMS"
  '';
  # Host parser fixtures with Linux 4.14 numbering (initramfs rootfs = mount 0),
  # which the disposable 6.18 VMs cannot produce. No storage is opened.
  parserTests = pkgs.runCommandCC "titan-storage-mount-parser-tests" {
    meta = { platforms = lib.platforms.linux; hydraPlatforms = []; };
  } ''
    $CC -std=c11 -O2 -Wall -Wextra -Werror -DTITAN_SOURCE_PARSER_TEST \
      -I ${source} ${source}/guard.c ${source}/mount-parser-test.c -o mount-parser-test
    ./mount-parser-test > results || { cat results; exit 1; }
    cat results
    cp results "$out"
  '';
in {
  inherit checker vmRamdisk vmTests parserTests;
}
