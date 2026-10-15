{ pkgs, sources, kernel, ramdisk, name ? "titan-native-probe-recovery-image",
  imageName ? "UNTESTED-UNSIGNED-native-probe.img",
  summary ? "and the modern USB probe", extraCmdline ? "",
  title ? "Build-only first native-route recovery image", status ? "Never booted." }:

# Native-route boot images (../native-n0.adoc): the native kernel, the Titan
# board tree and minimal bootloader overlay as Android DT tables, and a modern
# ramdisk (by default the USB probe; the diagnostic image passes its own and a
# larger kernel log buffer), in the recovery-partition layout the bootloader
# has already accepted. Assembled by the pinned mkbootimg with the reviewed
# header fields; no private input is used.
let
  inherit (pkgs) lib;
  # The device tree's /chosen/bootargs carries the three *_ignore_unused flags;
  # repeat them here in case the bootloader does not keep those arguments.
  cmdline = "bootopt=64S3,32N2,64N2 rdinit=/init panic=5 clk_ignore_unused pd_ignore_unused regulator_ignore_unused"
    + lib.optionalString (extraCmdline != "") " ${extraCmdline}";
  tools = lib.cleanSourceWith {
    src = ../tools;
    filter = path: type: type == "regular" && baseNameOf path == "inspect-boot-image.py";
  };
in
pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.python3 ];
  meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = [ ]; };
} ''
  set -o pipefail
  export PYTHONDONTWRITEBYTECODE=1
  mkdir -p "$out"
  python3 -I ${./dt-table.py} ${kernel}/dtbs/mt6771-unihertz-titan.dtb dtb.img
  python3 -I ${./dt-table.py} ${kernel}/dtbs/mt6771-unihertz-titan-minimal-dtbo.dtb dtbo.img
  python3 -B ${sources.mkbootimg}/mkbootimg.py \
    --kernel ${kernel}/Image.gz --ramdisk ${ramdisk}/initramfs.cpio.gz \
    --dtb dtb.img --recovery_dtbo dtbo.img --cmdline ${lib.escapeShellArg cmdline} \
    --header_version 2 --os_version 10 --os_patch_level 2025-08 \
    --base 0x40000000 --kernel_offset 0x80000 --ramdisk_offset 0x15000000 \
    --second_offset 0xf00000 --tags_offset 0x14000000 --pagesize 2048 \
    --dtb_offset 0x14000000 --output "$out/${imageName}"
  size=$(stat -c %s "$out/${imageName}")
  if [ "$size" -gt 33554432 ]; then echo "Image exceeds the recovery partition" >&2; exit 1; fi
  cp "$out/${imageName}" padded.img
  truncate -s 33554432 padded.img
  python3 -I ${tools}/inspect-boot-image.py --json "$out/${imageName}" \
    > "$out/inspection.json"
  cp dtb.img "$out/dtb-table.img"
  cp dtbo.img "$out/recovery-dtbo-table.img"
  {
    printf 'image %s %s\n' "$size" "$(sha256sum < "$out/${imageName}" | cut -d' ' -f1)"
    printf 'padded 33554432 %s\n' "$(sha256sum < padded.img | cut -d' ' -f1)"
    printf 'kernel %s\n' "$(sha256sum < ${kernel}/Image.gz | cut -d' ' -f1)"
    printf 'ramdisk %s\n' "$(sha256sum < ${ramdisk}/initramfs.cpio.gz | cut -d' ' -f1)"
    printf 'dtb-table %s\n' "$(sha256sum < dtb.img | cut -d' ' -f1)"
    printf 'recovery-dtbo-table %s\n' "$(sha256sum < dtbo.img | cut -d' ' -f1)"
    printf 'cmdline %s\n' ${lib.escapeShellArg cmdline}
  } > "$out/manifest.txt"
  cat > "$out/README" <<'EOF'
  ${title} for the original Unihertz Titan:
  the modern kernel, the Titan board tree and its minimal bootloader overlay,
  ${summary}. Unsigned, no AVB metadata. ${status}
  EOF
''
