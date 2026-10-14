{ lib, runCommand, python3, gzip, cpio, findutils, coreutils, openssl
, sources, kernel, fixture ? false
}:

let
  purpose = if fixture then "nonbootable-packaging-fixture" else "ubports-reference";
  imageName = if fixture then "NONBOOTABLE-FIXTURE.img" else "boot.img";
in
runCommand "unihertz-titan-${purpose}-boot-image" {
  nativeBuildInputs = [ python3 gzip cpio findutils coreutils openssl ];
  meta = {
    description = "Build-only Titan ${purpose} Android v2 boot image";
    sourceProvenance = [ lib.sourceTypes.fromSource lib.sourceTypes.binaryNativeCode ];
    # This assembles mixed upstream prebuilts; a complete license inventory has
    # not been established. Do not claim an aggregate license or redistribution
    # permission, and do not schedule publication of these experimental images.
    hydraPlatforms = [];
    # The fixture only packs data with native Python/GNU tools. The real kernel
    # still requires the pinned x86_64 Linux Android compilers.
    platforms = if fixture then lib.platforms.unix else [ "x86_64-linux" ];
  };
} ''
  set -o pipefail
  export PYTHONDONTWRITEBYTECODE=1
  mkdir -p "$out"

  # Pinned and reviewed shell assignments, as consumed by the reference build.
  source ${sources.adaptation}/deviceinfo
  test "$deviceinfo_bootimg_header_version" = 2
  test "$deviceinfo_bootimg_partition_size" = 33554432
  test "$deviceinfo_bootimg_append_vbmeta" = true

  cp ${sources.initramfs} ramdisk.img
  chmod u+w ramdisk.img
  cp -r ${sources.adaptation}/ramdisk-overlay overlay
  chmod -R u+w overlay
  find overlay -exec touch -h -d @1 -- {} +
  # Match UBports' concatenated gzip/cpio overlay semantics. Normalize archive
  # order, ownership and inode numbering instead of preserving builder identity.
  (
    cd overlay
    find . -print0 | LC_ALL=C sort -z \
      | cpio --null -o -H newc --reproducible --owner=0:0 \
      | gzip -n -9
  ) >> ramdisk.img

  python3 ${sources.mkbootimg}/mkbootimg.py \
    --kernel ${kernel}/Image.gz \
    --ramdisk ramdisk.img \
    --cmdline "$deviceinfo_kernel_cmdline" \
    --header_version "$deviceinfo_bootimg_header_version" \
    --os_version "$deviceinfo_bootimg_os_version" \
    --os_patch_level "$deviceinfo_bootimg_os_patch_level" \
    --base "$deviceinfo_flash_offset_base" \
    --kernel_offset "$deviceinfo_flash_offset_kernel" \
    --ramdisk_offset "$deviceinfo_flash_offset_ramdisk" \
    --second_offset "$deviceinfo_flash_offset_second" \
    --tags_offset "$deviceinfo_flash_offset_tags" \
    --pagesize "$deviceinfo_flash_pagesize" \
    --dtb ${sources.adaptation}/unihertz-titan.dtb \
    --dtb_offset "$deviceinfo_flash_offset_dtb" \
    --output "$out/${imageName}"

  # Preserve both steps in make-bootimage.sh. append_vbmeta_image replaces the
  # first footer/vbmeta with Google's supplied GSI metadata; the final descriptor
  # set must not be interpreted as a verified hash of this newly built kernel.
  python3 ${sources.avb}/avbtool.py add_hash_footer \
    --image "$out/${imageName}" --partition_name boot \
    --partition_size "$deviceinfo_bootimg_partition_size"
  # This avbtool opens even its vbmeta input read/write; keep the pinned store
  # source immutable and give it a disposable local copy.
  cp ${sources.vbmeta} vbmeta.img
  chmod u+w vbmeta.img
  python3 ${sources.avb}/avbtool.py append_vbmeta_image \
    --image "$out/${imageName}" --partition_size "$deviceinfo_bootimg_partition_size" \
    --vbmeta_image vbmeta.img

  python3 ${./tools/inspect-boot-image.py} --json --check-titan \
    "$out/${imageName}" > "$out/boot-image.json"
  python3 ${sources.avb}/avbtool.py info_image --image "$out/${imageName}" \
    > "$out/avb-info.txt"
  cp ${sources.adaptation}/deviceinfo "$out/deviceinfo"
  (cd "$out" && sha256sum ${imageName}) > "$out/SHA256SUMS"
  cat > "$out/README" <<'EOF'
  Purpose: ${purpose}
  This is a build/packaging experiment, not a validated installation image.
  It uses the Ubuntu Touch initramfs and Titan ramdisk overlay. There is no
  NixOS root filesystem or NixOS boot handoff in this output.
  ${if fixture then "The kernel payload is an intentionally nonbootable test fixture." else "No hardware boot or recovery test is implied by a successful build."}
  JSON inspection checks layout, not signatures, hashes or bootability.
  Mixed upstream prebuilts: complete license inventory and redistribution
  permissions have not been established.
  EOF
''
