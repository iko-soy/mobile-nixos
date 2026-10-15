{ pkgs }:

# Build-only preservation userspace. This is neither a Mobile NixOS stage 1 nor
# an Android boot image, and does not inherit the Ubuntu Touch startup scripts.
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  busybox = target.busybox.override {
    enableMinimal = true;
    enableAppletSymlinks = false;
    extraConfig = ''
      CONFIG_CAT y
      CONFIG_DD y
      CONFIG_FEATURE_DD_IBS_OBS y
      CONFIG_FEATURE_DD_STATUS y
      CONFIG_FEATURE_DD_THIRD_STATUS_LINE y
      CONFIG_HEXDUMP y
      CONFIG_LS y
      CONFIG_STAT y
      CONFIG_READLINK y
      CONFIG_FEATURE_READLINK_FOLLOW y
      CONFIG_SHA256SUM y
      CONFIG_FEATURE_MD5_SHA1_SUM_CHECK y
      CONFIG_TRUE y
      CONFIG_FALSE y
      CONFIG_UNAME y
      CONFIG_WC y
    '';
  };
  e2fsprogs = target.e2fsprogs.override { withFuse = false; };
  zstd = target.zstd;
  mkInit = staticPkgs: vmTest: staticPkgs.stdenv.mkDerivation {
    pname = "titan-rescue-init${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "0";
    # Only the compiled sources: untracked files such as bytecode caches must
    # not change this derivation.
    src = lib.cleanSourceWith {
      src = ./rescue;
      filter = path: type: type == "regular"
        && builtins.elem (baseNameOf path) [ "init.c" "vm-test.c" ];
    };
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        ${lib.optionalString vmTest "-DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5"} \
        init.c ${lib.optionalString vmTest "vm-test.c"} -o init
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 init "$out/bin/init"
    '';
    meta = {
      description = "Build-only Titan preservation PID 1${lib.optionalString vmTest " (VM test variant)"}";
      platforms = lib.platforms.linux;
      license = lib.licenses.mit;
      hydraPlatforms = [];
    };
  };
  init = mkInit target false;
  vmInit = mkInit pkgs.pkgsStatic true;
  mkRamdisk = name: initPackage: includeTools: pkgs.runCommand name {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.findutils pkgs.binutils ];
    meta = {
      description = "Build-only rescue initramfs; no phone boot or recovery claim";
      platforms = [ "x86_64-linux" ];
      hydraPlatforms = [];
    };
  } ''
    set -o pipefail
    mkdir -p root/{bin,dev,proc,sys,run,tmp} "$out"
    install -m 0555 ${initPackage}/bin/init root/init
    ${lib.optionalString includeTools ''
      install -m 0555 ${busybox}/bin/busybox root/bin/busybox
      install -m 0555 ${lib.getBin e2fsprogs}/bin/e2image root/bin/e2image
      install -m 0555 ${lib.getBin zstd}/bin/zstd root/bin/zstd
    ''}
    chmod 1777 root/tmp
    # Reject a hidden dynamic-loader/library dependency in this standalone RAM
    # filesystem. No Nix store, systemd or firmware payload is included.
    for binary in root/init root/bin/*; do
      [ -f "$binary" ] || continue
      readelf -h "$binary" > "$out/$(basename "$binary").elf.txt"
      grep -Eq 'Class:[[:space:]]+ELF64' "$out/$(basename "$binary").elf.txt"
      grep -Eq 'Machine:[[:space:]]+AArch64' "$out/$(basename "$binary").elf.txt"
      readelf -l "$binary" > "$out/$(basename "$binary").segments.txt"
      readelf -d "$binary" > "$out/$(basename "$binary").dynamic.txt"
      if grep -q INTERP "$out/$(basename "$binary").segments.txt"; then
        echo "Unexpected ELF interpreter: $binary" >&2
        exit 1
      fi
      if grep -q '(NEEDED)' "$out/$(basename "$binary").dynamic.txt"; then
        echo "Unexpected dynamic dependency: $binary" >&2
        exit 1
      fi
    done
    find root -exec touch -h -d @1 -- {} +
    (cd root; find . -print0 | LC_ALL=C sort -z \
      | cpio --null -o -H newc --reproducible --owner=0:0 \
      | gzip -n -9) > "$out/initramfs.cpio.gz"
    (cd root; sha256sum init ${lib.optionalString includeTools "bin/*"}) \
      > "$out/payload-SHA256SUMS"
    (cd "$out"; sha256sum initramfs.cpio.gz) > "$out/SHA256SUMS"
    cp -r root "$out/root"
    cp ${./rescue/init.c} "$out/init.c"
    cat > "$out/README" <<'EOF'
    Build-only AArch64 preservation ramdisk, not an Android boot image.
    Startup mounts only virtual/RAM filesystems and verifies BLKROSET/BLKROGET
    for discovered block devices. It starts no shell, USB service, Android
    service, repair, acquisition or automatic reboot. Kernel/firmware writers
    are outside this guard's scope. No Titan boot or recovery has been tested.
    Static musl executables: independent MIT-licensed PID 1, BusyBox
    ${busybox.version}, e2image ${e2fsprogs.version}, Zstandard ${zstd.version}.
    Package sources, patches and licenses are pinned through this repository's
    Nixpkgs input. No inherited Ubuntu Touch ramdisk binary is included.
    EOF
  '';
  ramdisk = mkRamdisk "titan-rescue-initramfs-aarch64" init true;
  vmKernel = pkgs.linux;
  # The distribution's VM kernel keeps virtio storage in modules. This separate
  # bootstrap loads only those modules before exec'ing the tested PID 1. None of
  # the VM bootstrap, modules, test callback or poweroff code enters ramdisk.
  vmRamdisk = pkgs.runCommand "titan-rescue-VM-TEST-ONLY-initramfs" {
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
  vmTests = pkgs.runCommand "titan-rescue-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    python3 ${./rescue/test-vm-markers.py} ${./rescue/vm-check.py}
    python3 ${./rescue/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${vmKernel}/bzImage \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$out"
  '';
  toolTests = pkgs.runCommand "titan-rescue-aarch64-tool-tests" {
    nativeBuildInputs = [ pkgs.e2fsprogs pkgs.zstd pkgs.diffutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    set -o pipefail
    mkdir -p "$out"
    qemu=${pkgs.qemu-user}/bin/qemu-aarch64
    # Refuse PID 1 operations when called as an ordinary emulated process.
    status=0
    "$qemu" ${init}/bin/init > "$out/init.stdout" 2> "$out/init.stderr" || status=$?
    test "$status" = 1
    grep -Fx 'TITAN_RESCUE_REFUSED not-pid-one' "$out/init.stderr"
    "$qemu" ${busybox}/bin/busybox true
    "$qemu" ${lib.getBin zstd}/bin/zstd --version > "$out/zstd-version.txt"
    printf 'Titan rescue AArch64 tool fixture\n' > payload
    "$qemu" ${busybox}/bin/busybox cat payload > busybox-copy
    cmp payload busybox-copy
    sha256sum payload > "$out/busybox-SHA256SUMS"
    "$qemu" ${busybox}/bin/busybox sha256sum -c "$out/busybox-SHA256SUMS" \
      > "$out/busybox-check.log"
    truncate -s 16M filesystem.ext4
    mke2fs -q -t ext4 -F filesystem.ext4
    debugfs -w -R 'write payload /payload' filesystem.ext4 > "$out/fixture-setup.log" 2>&1
    "$qemu" ${lib.getBin e2fsprogs}/bin/e2image -ra filesystem.ext4 - \
      2> "$out/e2image.stderr" \
      | "$qemu" ${lib.getBin zstd}/bin/zstd -q -c > filesystem.ext4.zst
    zstd -q -d --sparse filesystem.ext4.zst -o restored.ext4
    e2fsck -fn restored.ext4 > "$out/e2fsck.log" 2>&1
    debugfs -R 'dump /payload recovered' restored.ext4 > "$out/extract.log" 2>&1
    cmp payload recovered
    sha256sum payload recovered > "$out/payload-SHA256SUMS"
    # e2image can report read failures without a nonzero exit. This fixture
    # requires its normal version line and rejects all additional diagnostics.
    test "$(wc -l < "$out/e2image.stderr")" = 1
    grep -E '^e2image [0-9]+\.[0-9]+' "$out/e2image.stderr"
    printf '%s\n' 'AArch64 static tool fixture passed under qemu-user; host kernel, not Titan kernel.' \
      > "$out/README"
  '';
in {
  inherit init busybox e2fsprogs zstd ramdisk vmRamdisk vmTests toolTests;
}
