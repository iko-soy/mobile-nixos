{ pkgs, usbDebug ? true, kexec ? false, cpuPowerDown ? false, i2cChannels ? false }:

# Build-only native-route kernel (../native-n0.adoc): Linux v7.3-rc3 with the
# postmarketOS MT6771 patches, the T-PHY software role-switch patch from the
# adomerle/mt6771-next branch (commit 96fe48be, vendored because generated
# patch downloads are not byte-stable) with a local hardening follow-up (0004),
# and the postmarketOS configuration with debug info and BTF switched off.
# Plus the Titan board tree and its minimal bootloader overlay (dts/). No
# hardware boot is implied by a build. With usbDebug = false, the donor's
# CONFIG_USB_MTU3_DEBUG is turned off: it logs every USB transfer, flooding
# the kernel log and slowing USB networking (../native-ram-trial.adoc). With
# kexec = true, CONFIG_KEXEC adds the kexec_load call, which takes a device
# tree from userspace; the donor's kexec_file_load always reuses the
# bootloader's tree. With cpuPowerDown = true, patch 0005 adds a driver that
# asks MediaTek's firmware to power down each core that CPU hotplug or kexec
# has turned off, as MediaTek's kernel does; without it such a core never
# starts again (../native-kexec-trial.adoc). With i2cChannels = true, patch
# 0006 lets an I2C controller shared with a coprocessor be driven through
# one of its channels, as MediaTek's kernel does, for a node with
# mediatek,channel-offset; without that property nothing changes
# (../native-i2c-input-scan-trial.adoc).
let
  inherit (pkgs) lib fetchurl;
  cross = pkgs.pkgsCross.aarch64-multiplatform;
  pmaportsRev = "0e458a2417d6f5ed61c7b70621d5632e30136091";
  pmFile = name: sha256: fetchurl {
    url = "https://gitlab.postmarketos.org/postmarketOS/pmaports/-/raw/${pmaportsRev}/device/testing/linux-postmarketos-mediatek-mt6771/${name}";
    inherit sha256;
  };
  config = pmFile "config-postmarketos-mediatek-mt6771.aarch64"
    "11d1edeb4207642eedfce634f2de2ab4c6a279799466f1777446f22c9004f7e4";
  makeFlags = [
    "ARCH=arm64"
    "CROSS_COMPILE=${cross.stdenv.cc.targetPrefix}"
    "HOSTCC=${cross.buildPackages.stdenv.cc}/bin/cc"
    "KBUILD_BUILD_USER=nix"
    "KBUILD_BUILD_HOST=titan-build"
    "KBUILD_BUILD_TIMESTAMP=Thu Jan 1 00:00:00 UTC 1970"
    "KBUILD_BUILD_VERSION=1"
  ];
in
cross.stdenv.mkDerivation {
  pname = "titan-native-kernel${lib.optionalString (!usbDebug) "-quiet-usb"}${lib.optionalString kexec "-kexec"}${lib.optionalString cpuPowerDown "-cpu-power"}${lib.optionalString i2cChannels "-i2c-channel"}";
  version = "7.3.0-rc3";
  src = fetchurl {
    url = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/snapshot/linux-7.3-rc3.tar.gz";
    sha256 = "49b24119d7b92da75bba0daf5da4f7735c8cb948757a282e849092dcc681d8dd";
  };
  patches = [
    (pmFile "0001-hx83112a_touchscreen.patch"
      "19d4596e4038242ea1d0b0208c2a444073ab7d58ed4797c7334a8a3ec0c5618d")
    (pmFile "0002-add-mt6771-gigaset-gs4.patch"
      "e11f14be74f56bce72f78799880ecff2bc284d95a3e06c51c9c189c383c0f9a3")
    ./patches/0003-phy-mediatek-tphy-add-software-role-switching.patch
    ./patches/0004-phy-mediatek-tphy-keep-the-forced-role-without-a-role-switch.patch
  ] ++ lib.optional cpuPowerDown
    ./patches/0005-soc-mediatek-power-down-mt6771-cores-after-cpu-hotplug.patch
  ++ lib.optional i2cChannels
    ./patches/0006-i2c-mt65xx-drive-a-channel-of-a-shared-controller.patch;
  postPatch = ''
    patchShebangs scripts
    cp ${./dts/mt6771-unihertz-titan.dts} arch/arm64/boot/dts/mediatek/mt6771-unihertz-titan.dts
    cp ${./dts/mt6771-unihertz-titan-minimal-dtbo.dts} \
      arch/arm64/boot/dts/mediatek/mt6771-unihertz-titan-minimal-dtbo.dts
    printf '%s\n' 'dtb-$(CONFIG_ARCH_MEDIATEK) += mt6771-unihertz-titan.dtb' \
      'dtb-$(CONFIG_ARCH_MEDIATEK) += mt6771-unihertz-titan-minimal-dtbo.dtb' \
      >> arch/arm64/boot/dts/mediatek/Makefile
  '';
  strictDeps = true;
  depsBuildBuild = [ cross.buildPackages.stdenv.cc ];
  nativeBuildInputs = with pkgs; [ bc bison flex perl python3 openssl kmod ];
  enableParallelBuilding = true;
  dontStrip = true;
  configurePhase = ''
    runHook preConfigure
    cp ${config} .config
    chmod u+w .config
    scripts/config --file .config \
      --disable DEBUG_INFO_BTF --disable DEBUG_INFO_BTF_MODULES \
      --disable DEBUG_INFO_DWARF5 --disable DEBUG_INFO_COMPRESSED_ZSTD \
      --disable DEBUG_INFO --enable DEBUG_INFO_NONE${lib.optionalString (!usbDebug) " --disable USB_MTU3_DEBUG"}${lib.optionalString kexec " --enable KEXEC"}${lib.optionalString cpuPowerDown " --enable MTK_MT6771_CPU_POWER"}
    make ${lib.escapeShellArgs makeFlags} olddefconfig
    ${lib.optionalString cpuPowerDown "grep -qx CONFIG_MTK_MT6771_CPU_POWER=y .config"}
    runHook postConfigure
  '';
  buildPhase = ''
    runHook preBuild
    make ${lib.escapeShellArgs makeFlags} -j"$NIX_BUILD_CORES" Image.gz dtbs
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/dtbs" "$out/share/build-info"
    cp arch/arm64/boot/Image arch/arm64/boot/Image.gz .config System.map "$out/"
    cp arch/arm64/boot/dts/mediatek/mt6771-*.dtb "$out/dtbs/" 2>/dev/null || true
    cp arch/arm64/boot/dts/mediatek/mt8183-*.dtb "$out/dtbs/" 2>/dev/null || true
    make ${lib.escapeShellArgs makeFlags} -s kernelrelease > "$out/share/build-info/kernel.release"
    ${cross.stdenv.cc.targetPrefix}gcc --version | head -1 > "$out/share/build-info/compiler.txt"
    (cd "$out" && sha256sum Image Image.gz .config) > "$out/share/build-info/SHA256SUMS"
    runHook postInstall
  '';
  meta = {
    description = "Build-only native-route kernel for the original Unihertz Titan (not booted)";
    license = lib.licenses.gpl2Only;
    platforms = [ "aarch64-linux" ];
    hydraPlatforms = [ ];
  };
}
