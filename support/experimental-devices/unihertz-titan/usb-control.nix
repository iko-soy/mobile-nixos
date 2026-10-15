{ pkgs, transport }:

# Separate build-only experiment: an offline acquisition of the sixteen control
# and calibration regions, started from the recovery partition. Rescue PID 1
# with the probe and control profiles, the fixed region producer and the TTR1
# sender. This does not replace any other ramdisk or produce a boot image.
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  headers = directory: lib.cleanSourceWith {
    src = directory;
    filter = path: type: type == "regular" && lib.hasSuffix ".h" (baseNameOf path);
  };
  pythonSource = directory: lib.cleanSourceWith {
    src = directory;
    filter = path: type:
      let name = baseNameOf path;
      in (type == "directory" && name != "__pycache__")
        || (type == "regular" && lib.hasSuffix ".py" name);
  };
  mkProducer = staticPkgs: vmTest: staticPkgs.stdenv.mkDerivation {
    pname = "titan-control-produce${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "1";
    src = ./control/producer.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ staticPkgs.openssl ];
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static -DTITAN_USB_MOUNT_PROFILE \
        ${lib.optionalString vmTest "-DTITAN_CONTROL_VM_TEST"} \
        -I ${headers ./rescue} -x c "$src" ${./rescue/mount-policy.c} -x none \
        $(pkg-config --cflags --libs --static libcrypto) -o titan-control-produce
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-control-produce "$out/bin/titan-control-produce"
    '';
    meta = { platforms = lib.platforms.linux; hydraPlatforms = []; };
  };
  producer = mkProducer target false;
  vmProducer = mkProducer pkgs.pkgsStatic true;
  mkInit = staticPkgs: vmTest: staticPkgs.stdenv.mkDerivation {
    pname = "titan-usb-control-init${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "1";
    src = ./control/pipeline.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_USB_PROBE_PROFILE -DTITAN_USB_CONTROL_PROFILE -DTITAN_USB_MOUNT_PROFILE \
        ${lib.optionalString vmTest "-DTITAN_USB_PROBE_VM_TEST -DTITAN_USB_PIPELINE_VM_TEST -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5"} \
        -I ${headers ./rescue} -I ${headers ./usb} -I ${headers ./usb-pipeline} \
        ${./rescue/init.c} ${./usb/owner.c} ${./rescue/mount-policy.c} ${./usb-probe/probe.c} \
        ${lib.optionalString vmTest "${./usb-pipeline/relay.c}"} \
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
  ramdisk = pkgs.runCommand "titan-usb-control-initramfs-aarch64" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.findutils pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    set -o pipefail
    mkdir -p root/{bin,dev,proc,sys,run,tmp} "$out"
    install -m 0555 ${init}/bin/init root/init
    install -m 0555 ${producer}/bin/titan-control-produce root/bin/titan-control-produce
    install -m 0555 ${transport.sender}/bin/titan-rescue-send root/bin/titan-rescue-send
    chmod 1777 root/tmp
    for binary in root/init root/bin/*; do
      readelf -h "$binary" > "$out/$(basename "$binary").elf.txt"
      readelf -l "$binary" > "$out/$(basename "$binary").segments.txt"
      readelf -d "$binary" > "$out/$(basename "$binary").dynamic.txt"
      grep -Eq 'Class:[[:space:]]+ELF64' "$out/$(basename "$binary").elf.txt"
      grep -Eq 'Machine:[[:space:]]+AArch64' "$out/$(basename "$binary").elf.txt"
      if grep -q INTERP "$out/$(basename "$binary").segments.txt" \
          || grep -q '(NEEDED)' "$out/$(basename "$binary").dynamic.txt"; then
        echo "Unexpected dynamic dependency: $binary" >&2
        exit 1
      fi
    done
    # VM-only controllers, bridges, tables and markers must not enter the phone
    # image, and the phone's own disk table must. The VM table names `vda`.
    for binary in root/init root/bin/titan-control-produce; do
      strings -n 3 "$binary" > "$out/$(basename "$binary").strings.txt"
      if grep -E 'dummy_udc|dummy_hcd|ttyACM0|ttyS1|ttyS2|TVM1|TITAN_PROBE_VM_|TITAN_CONTROL_VM_|titan_usb_probe_test=|/dev/vda|TITAN_PROBE_DEADLINE_REBOOT|TITAN_PROBE_BACKSTOP_REBOOT' \
          "$out/$(basename "$binary").strings.txt" \
          || grep -qx vda "$out/$(basename "$binary").strings.txt"; then
        echo "VM fixture strings leaked into $binary" >&2
        exit 1
      fi
      if ! grep -qx mmcblk0 "$out/$(basename "$binary").strings.txt" \
          || ! grep -qx mmcblk0p "$out/$(basename "$binary").strings.txt"; then
        echo "The phone disk table is missing from $binary" >&2
        exit 1
      fi
    done
    find root -exec touch -h -d @1 -- {} +
    (cd root; find . -print0 | LC_ALL=C sort -z \
      | cpio --null -o -H newc --reproducible --owner=0:0 \
      | gzip -n -9) > "$out/initramfs.cpio.gz"
    (cd root; sha256sum init bin/*) > "$out/payload-SHA256SUMS"
    (cd "$out"; sha256sum initramfs.cpio.gz) > "$out/SHA256SUMS"
    cp -r root "$out/root"
    cat > "$out/README" <<'EOF'
    Build-only AArch64 offline control-region acquisition, not a boot image.
    Rescue PID 1 guards every block device read-only, binds the fixed ACM
    gadget, streams sixteen fixed control and calibration regions with two
    hash passes over TTR1 and restarts into the bootloader. No writes, mounts,
    input-selected sources or shell. No Titan run has been tested.
    EOF
  '';
  vmRamdisk = import ./vm-initramfs.nix {
    inherit pkgs;
    name = "titan-usb-control-VM-TEST-ONLY-initramfs";
    init = vmInit;
    programs = {
      titan-control-produce = "${vmProducer}/bin/titan-control-produce";
      titan-rescue-send = "${transport.nativeSender}/bin/titan-rescue-send";
    };
    modules = [ "virtio_pci" "virtio_blk" "dummy_hcd" "libcomposite" "usb_f_acm" "cdc_acm" ];
  };
  vmTests = pkgs.runCommand "titan-usb-control-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.e2fsprogs ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    export TITAN_TRANSPORT_SOURCE=${pythonSource ./transport}
    export TITAN_TOOLS_SOURCE=${pythonSource ./tools}
    export TITAN_CONTROL_SOURCE=${./control/producer.c}
    python3 ${./control/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${pkgs.linux}/bzImage --kernel-version ${pkgs.linux.modDirVersion} \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$NIX_BUILD_TOP/control-results"
    cp -r "$NIX_BUILD_TOP/control-results" "$out"
  '';
  toolTests = pkgs.runCommand "titan-usb-control-aarch64-refusal-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    mkdir -p "$out"
    python3 - ${pkgs.qemu-user}/bin/qemu-aarch64 ${init}/bin/init \
      ${producer}/bin/titan-control-produce > "$out/refusal-tests.txt" <<'PY'
    import os, subprocess, sys
    emulator, init, producer = sys.argv[1:]
    result = subprocess.run([emulator, init], capture_output=True, timeout=5)
    assert result.returncode == 1 and result.stdout == b""
    assert result.stderr == b"TITAN_RESCUE_REFUSED not-pid-one\n", result
    print("AArch64 control init: refused non-PID1 execution")
    data_read, data_write = os.pipe()
    status_read, status_write = os.pipe()
    try:
        result = subprocess.run([emulator, producer, "--output-fd", str(data_write),
                                 "--status-fd", str(status_write), "--max-bytes", "1073741824",
                                 "--timeout-seconds", "5"],
                                pass_fds=(data_write, status_write), capture_output=True, timeout=10)
    finally:
        os.close(data_write)
        os.close(status_write)
    assert os.read(data_read, 32) == b"", "the producer streamed outside the offline environment"
    assert (result.returncode, os.read(status_read, 32)) == (2, b"TPST\0\0\0\2"), result
    print("AArch64 control producer: refused outside the offline environment, nothing streamed")
    PY
  '';
in {
  inherit init producer ramdisk vmRamdisk vmTests toolTests;
}
