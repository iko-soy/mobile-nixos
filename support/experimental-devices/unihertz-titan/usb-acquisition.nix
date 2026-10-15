{ pkgs, rescue, transport }:

# Separate build-only experiment: fixed USB ACM startup plus guarded userdata
# imaging. This does not replace rescue.ramdisk or produce an Android boot image.
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
    pname = "titan-usb-block-produce${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "1";
    src = ./producer/supervisor.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_PRODUCER_BLOCK_SOURCE -DTITAN_USB_MOUNT_PROFILE \
        ${lib.optionalString vmTest "-DTITAN_SOURCE_VM_TEST"} \
        -I ${headers ./source} -I ${headers ./rescue} \
        -x c "$src" ${./source/guard.c} ${./rescue/mount-policy.c} -o titan-block-produce
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-block-produce "$out/bin/titan-block-produce"
    '';
    meta = { platforms = lib.platforms.linux; hydraPlatforms = []; };
  };
  producer = mkProducer target false;
  vmProducer = mkProducer pkgs.pkgsStatic true;
  mkInit = staticPkgs: vmTest: staticPkgs.stdenv.mkDerivation {
    pname = "titan-usb-acquisition-init${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "1";
    src = ./usb-pipeline/init.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_USB_PIPELINE_PROFILE -DTITAN_USB_MOUNT_PROFILE \
        ${lib.optionalString vmTest "-DTITAN_USB_PIPELINE_VM_TEST -DTITAN_SOURCE_VM_TEST -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5"} \
        -I ${headers ./rescue} -I ${headers ./source} \
        -I ${headers ./usb} -I ${headers ./usb-pipeline} \
        ${./rescue/init.c} ${./usb/owner.c} ${./source/guard.c} \
        ${./rescue/mount-policy.c} ${lib.optionalString vmTest "${./usb-pipeline/relay.c}"} \
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
  ramdisk = pkgs.runCommand "titan-usb-acquisition-initramfs-aarch64" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.findutils pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    set -o pipefail
    mkdir -p root/{bin,dev,proc,sys,run,tmp} "$out"
    install -m 0555 ${init}/bin/init root/init
    install -m 0555 ${producer}/bin/titan-block-produce root/bin/titan-block-produce
    install -m 0555 ${transport.sender}/bin/titan-rescue-send root/bin/titan-rescue-send
    install -m 0555 ${rescue.busybox}/bin/busybox root/bin/busybox
    install -m 0555 ${lib.getBin rescue.e2fsprogs}/bin/e2image root/bin/e2image
    install -m 0555 ${lib.getBin rescue.zstd}/bin/zstd root/bin/zstd
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
    # VM-only discovery, control channel and fixture strings must not enter
    # the phone profile. Its controller and userdata identity are compiled in.
    for binary in root/init root/bin/titan-block-produce; do
      strings "$binary" > "$out/$(basename "$binary").strings.txt"
      if grep -E 'dummy_udc|ttyS2|TITAN_USB_PIPELINE_VM_|titan_usb_pipeline_test=|/dev/vda|hold-zstd|/task/[0-9]+/children' \
          "$out/$(basename "$binary").strings.txt"; then
        echo "VM fixture or unsupported children path leaked into $binary" >&2
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
    Build-only AArch64 USB acquisition experiment, not an Android boot image.
    Fixed production USB owner and guarded userdata producer; no shell or
    automatic reboot. USB descriptors are for private in-house experiments.
    Static musl userspace only; no vendor firmware or inherited UBports init.
    No Titan boot, storage consistency, USB transfer or recovery has been tested.
    EOF
  '';
  holdZstd = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "titan-usb-acquisition-VM-TEST-ONLY-compressor-proxy";
    version = "1";
    src = ./block/hold-zstd.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_BLOCK_VM_TEST -x c "$src" -o hold-zstd
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 hold-zstd "$out/bin/hold-zstd"
    '';
    meta.hydraPlatforms = [];
  };
  nativeE2fsprogs = pkgs.pkgsStatic.e2fsprogs.override { withFuse = false; };
  vmRamdisk = import ./vm-initramfs.nix {
    inherit pkgs;
    name = "titan-usb-acquisition-VM-TEST-ONLY-initramfs";
    init = vmInit;
    programs = {
      titan-block-produce = "${vmProducer}/bin/titan-block-produce";
      titan-rescue-send = "${transport.nativeSender}/bin/titan-rescue-send";
      e2image = "${lib.getBin nativeE2fsprogs}/bin/e2image";
      zstd = "${lib.getBin pkgs.pkgsStatic.zstd}/bin/zstd";
      hold-zstd = "${holdZstd}/bin/hold-zstd";
    };
    modules = [ "virtio_pci" "virtio_blk" "dummy_hcd" "libcomposite" "usb_f_acm" "cdc_acm" ];
  };
  vmTests = pkgs.runCommand "titan-usb-acquisition-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.e2fsprogs pkgs.zstd ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    export TITAN_TRANSPORT_SOURCE=${pythonSource ./transport}
    export TITAN_BLOCK_FIXTURE_SOURCE=${pythonSource ./block}
    python3 ${./usb-pipeline/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${pkgs.linux}/bzImage --kernel-version ${pkgs.linux.modDirVersion} \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$NIX_BUILD_TOP/usb-results"
    cp -r "$NIX_BUILD_TOP/usb-results" "$out"
  '';
  toolTests = pkgs.runCommand "titan-usb-acquisition-aarch64-refusal-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    mkdir -p "$out"
    python3 - ${pkgs.qemu-user}/bin/qemu-aarch64 ${init}/bin/init \
      ${producer}/bin/titan-block-produce > "$out/refusal-tests.txt" <<'PY'
    import os, subprocess, sys
    emulator, init, producer = sys.argv[1:]
    result = subprocess.run([emulator, init], capture_output=True, timeout=5)
    assert result.returncode == 1 and result.stdout == b""
    assert result.stderr == b"TITAN_RESCUE_REFUSED not-pid-one\n", result
    print("Integrated AArch64 init: refused non-PID1 execution")
    for override in (None, "--input-fd", "--e2image", "--zstd"):
        data_read, data_write = os.pipe()
        status_read, status_write = os.pipe()
        try:
            command = [emulator, producer, "--output-fd", str(data_write),
                       "--status-fd", str(status_write), "--max-bytes", "4096",
                       "--timeout-seconds", "2"]
            if override:
                command += [override, "0" if override == "--input-fd" else "/bin/" + override[2:]]
            result = subprocess.run(command, pass_fds=(data_write, status_write),
                                    capture_output=True, timeout=5)
        finally:
            os.close(data_write)
            os.close(status_write)
        try:
            assert result.stdout == b"" and os.read(data_read, 32) == b""
            status = os.read(status_read, 32)
            assert (result.returncode, status) == ((1, b"") if override else (2, b"TPST\0\0\0\2"))
        finally:
            os.close(data_read)
            os.close(status_read)
        print((override or "non-rescue source environment") + ": rejected")
    PY
  '';
in {
  inherit init producer ramdisk vmRamdisk vmTests toolTests;
}
