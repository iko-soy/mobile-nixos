{ pkgs }:

# Separate build-only experiment for a first temporary boot: rescue PID 1 with
# the fixed ACM gadget, a bounded status report and a fixed-deadline reboot.
# This does not replace rescue.ramdisk or produce an Android boot image.
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  headers = directory: lib.cleanSourceWith {
    src = directory;
    filter = path: type: type == "regular" && lib.hasSuffix ".h" (baseNameOf path);
  };
  mkInit = staticPkgs: vmTest: staticPkgs.stdenv.mkDerivation {
    pname = "titan-usb-probe-init${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "1";
    src = ./usb-probe/probe.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_USB_PROBE_PROFILE -DTITAN_USB_MOUNT_PROFILE \
        ${lib.optionalString vmTest "-DTITAN_USB_PROBE_VM_TEST -DTITAN_USB_PIPELINE_VM_TEST -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5"} \
        -I ${headers ./rescue} -I ${headers ./usb} \
        ${./rescue/init.c} ${./usb/owner.c} ${./rescue/mount-policy.c} \
        -x c "$src" -o init
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 init "$out/bin/init"
    '';
    meta = { platforms = lib.platforms.linux; hydraPlatforms = []; };
  };
  init = mkInit target false;
  vmInit = mkInit pkgs.pkgsStatic true;
  ramdisk = pkgs.runCommand "titan-usb-probe-initramfs-aarch64" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.findutils pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    set -o pipefail
    mkdir -p root/{dev,proc,sys,run,tmp} "$out"
    install -m 0555 ${init}/bin/init root/init
    chmod 1777 root/tmp
    readelf -h root/init > "$out/init.elf.txt"
    readelf -l root/init > "$out/init.segments.txt"
    readelf -d root/init > "$out/init.dynamic.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$out/init.elf.txt"
    grep -Eq 'Machine:[[:space:]]+AArch64' "$out/init.elf.txt"
    if grep -q INTERP "$out/init.segments.txt" || grep -q '(NEEDED)' "$out/init.dynamic.txt"; then
      echo "Unexpected dynamic dependency in the probe init" >&2
      exit 1
    fi
    # VM-only cases, controller and host-side strings must not enter the phone profile.
    strings root/init > "$out/init.strings.txt"
    # The phone build also writes nothing on its restart paths.
    if grep -E 'dummy_udc|dummy_hcd|ttyACM0|TITAN_PROBE_VM_|titan_usb_probe_test=|/dev/vda|TITAN_PROBE_DEADLINE_REBOOT|TITAN_PROBE_BACKSTOP_REBOOT' "$out/init.strings.txt"; then
      echo "VM fixture strings leaked into the probe init" >&2
      exit 1
    fi
    find root -exec touch -h -d @1 -- {} +
    (cd root; find . -print0 | LC_ALL=C sort -z \
      | cpio --null -o -H newc --reproducible --owner=0:0 \
      | gzip -n -9) > "$out/initramfs.cpio.gz"
    (cd root; sha256sum init) > "$out/payload-SHA256SUMS"
    (cd "$out"; sha256sum initramfs.cpio.gz) > "$out/SHA256SUMS"
    cp -r root "$out/root"
    cat > "$out/README" <<'EOF'
    Build-only AArch64 USB probe experiment, not an Android boot image.
    Rescue PID 1 guards every block device read-only, binds the fixed ACM
    gadget, writes a bounded status line every two seconds and reboots at a
    fixed deadline. No storage reads, input, acquisition or shell.
    USB descriptors are for private in-house experiments.
    No Titan boot, USB operation or return has been tested.
    EOF
  '';
  vmRamdisk = import ./vm-initramfs.nix {
    inherit pkgs;
    name = "titan-usb-probe-VM-TEST-ONLY-initramfs";
    init = vmInit;
    modules = [ "virtio_pci" "virtio_blk" "dummy_hcd" "libcomposite" "usb_f_acm" "cdc_acm" ];
  };
  vmTests = pkgs.runCommand "titan-usb-probe-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    python3 ${./usb-probe/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${pkgs.linux}/bzImage --kernel-version ${pkgs.linux.modDirVersion} \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$NIX_BUILD_TOP/probe-results"
    cp -r "$NIX_BUILD_TOP/probe-results" "$out"
  '';
  toolTests = pkgs.runCommand "titan-usb-probe-aarch64-refusal-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    mkdir -p "$out"
    python3 - ${pkgs.qemu-user}/bin/qemu-aarch64 ${init}/bin/init > "$out/refusal-tests.txt" <<'PY'
    import subprocess, sys
    emulator, init = sys.argv[1:]
    result = subprocess.run([emulator, init], capture_output=True, timeout=5)
    assert result.returncode == 1 and result.stdout == b""
    assert result.stderr == b"TITAN_RESCUE_REFUSED not-pid-one\n", result
    print("AArch64 probe init: refused non-PID1 execution without arming a reboot")
    PY
  '';
in {
  inherit init ramdisk vmRamdisk vmTests toolTests;
}
