{ pkgs }:

# Software-only USB lifecycle tests. No USB helper, fixture descriptors, test
# callback, modules or poweroff code is added to the AArch64 rescue ramdisk.
let
  vmKernel = pkgs.linux;
  vmInit = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "titan-usb-VM-TEST-ONLY-init";
    version = "1";
    src = pkgs.lib.cleanSourceWith {
      src = ./usb;
      filter = path: type:
        type == "regular" && pkgs.lib.hasSuffix ".c" (baseNameOf path);
    };
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5 \
        -DTITAN_USB_VM_TEST ${./rescue/init.c} vm-test.c -o init
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 init "$out/bin/init"
    '';
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  };
  vmRamdisk = pkgs.runCommand "titan-usb-VM-TEST-ONLY-initramfs" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.xz pkgs.zstd pkgs.kmod ];
    meta.hydraPlatforms = [];
  } ''
    set -o pipefail
    mkdir -p root/{bin,dev,proc,sys,run,tmp,vm-modules} "$out"
    install -m 0555 ${vmInit}/bin/init root/rescue-init
    install -m 0555 ${pkgs.pkgsStatic.busybox}/bin/busybox root/bin/busybox
    # dummy_hcd supplies both sides of the USB bus inside the guest. There is
    # no physical USB device, passthrough or QEMU USB controller in this test.
    for module in virtio_pci virtio_blk dummy_hcd libcomposite usb_f_acm cdc_acm; do
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
    cp modules.list "$out/modules.list"
  '';
  vmTests = pkgs.runCommand "titan-usb-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    python3 ${./usb/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${vmKernel}/bzImage --kernel-version ${vmKernel.modDirVersion} \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$NIX_BUILD_TOP/usb-results"
    # With --keep-failed the complete bounded evidence also survives a failed
    # assertion in the build directory; failed store outputs may be removed.
    cp -r "$NIX_BUILD_TOP/usb-results" "$out"
  '';
in {
  inherit vmRamdisk vmTests;
}
