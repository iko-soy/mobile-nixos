{ pkgs }:

let
  inherit (pkgs) lib;
  headers = directory: lib.cleanSourceWith {
    src = directory;
    filter = path: type: type == "regular" && lib.hasSuffix ".h" (baseNameOf path);
  };
  vmInit = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "titan-usb-mount-policy-VM-TEST-ONLY-init";
    version = "1";
    src = ./rescue/mount-vm-test.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5 \
        -DTITAN_SOURCE_VM_TEST -DTITAN_USB_MOUNT_PROFILE -DTITAN_MOUNT_VM_TEST \
        -I ${headers ./rescue} -I ${headers ./source} \
        ${./rescue/init.c} ${./rescue/mount-policy.c} ${./source/guard.c} \
        -x c "$src" -o init
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 init "$out/bin/init"
    '';
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  };
  vmRamdisk = import ./vm-initramfs.nix {
    inherit pkgs;
    name = "titan-usb-mount-policy-VM-TEST-ONLY-initramfs";
    init = vmInit;
    modules = [ "virtio_pci" "virtio_blk" "configfs" ];
  };
  vmTests = pkgs.runCommand "titan-usb-mount-policy-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    python3 ${./rescue/mount-vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${pkgs.linux}/bzImage --kernel-version ${pkgs.linux.modDirVersion} \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$NIX_BUILD_TOP/mount-results"
    cp -r "$NIX_BUILD_TOP/mount-results" "$out"
  '';
  # Host parser fixtures with Linux 4.14 numbering (initramfs rootfs = mount 0),
  # which the disposable 6.18 VMs cannot produce. No mount is performed.
  parserTests = pkgs.runCommandCC "titan-usb-mount-policy-parser-tests" {
    meta = { platforms = lib.platforms.linux; hydraPlatforms = []; };
  } ''
    $CC -std=c11 -O2 -Wall -Wextra -Werror \
      -DTITAN_USB_MOUNT_PROFILE -DTITAN_MOUNT_POLICY_PARSER_TEST \
      -I ${headers ./rescue} ${./rescue/mount-policy.c} ${./rescue/mount-parser-test.c} \
      -o mount-parser-test
    ./mount-parser-test > results || { cat results; exit 1; }
    cat results
    cp results "$out"
  '';
in {
  inherit vmRamdisk vmTests parserTests;
}
