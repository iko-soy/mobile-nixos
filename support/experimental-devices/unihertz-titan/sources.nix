{ fetchurl, fetchzip, runCommand, gnutar, gzip }:

let
  adaptationRev = "811aaa59fa3f21748c7b4142412633d9734d4928";
  buildToolsRev = "7dd99e0de224931a7af1ffcc8d41f3c4c51f5316";
  mkbootimgRev = "40a19c4c5ffe8b86c6c61318c8aa4ffe35d6e7ad";

  unpack = name: archive: runCommand name {
    nativeBuildInputs = [ gnutar gzip ];
  } ''
    mkdir -p "$out"
    tar -xzf ${archive} --strip-components=1 -C "$out"
  '';

  adaptationArchive = fetchurl {
    url = "https://gitlab.com/ubports/porting/community-ports/android10/unihertz-titan/unihertz-titan/-/archive/${adaptationRev}/unihertz-titan-${adaptationRev}.tar.gz";
    hash = "sha256-fjjoyHbjl+qWNdjPqAeuudhFU/HOy6y/FA/kaYKCT8I=";
  };
in
{
  # Select the inputs needed for boot-image reproduction. The adaptation also
  # contains Android userspace binaries that are not part of this boot image.
  adaptation = runCommand "unihertz-titan-boot-inputs-${adaptationRev}" {
    nativeBuildInputs = [ gnutar gzip ];
  } ''
    mkdir extracted "$out"
    tar -xzf ${adaptationArchive} --strip-components=1 -C extracted
    cp -r extracted/deviceinfo extracted/unihertz-titan.dtb \
      extracted/ramdisk-overlay "$out/"
  '';

  # Reference implementation for provenance; its network-fetching build.sh is
  # deliberately not executed by any of the Nix builds.
  adaptationBuildTools = unpack "titan-adaptation-build-tools-${buildToolsRev}" (fetchurl {
    url = "https://gitlab.com/ubports/porting/community-ports/halium-generic-adaptation-build-tools/-/archive/${buildToolsRev}/halium-generic-adaptation-build-tools-${buildToolsRev}.tar.gz";
    hash = "sha256-b85+c8n6PKr9op4fdiXijrqq0cx1S7gpxv8C4xOXO8s=";
  });

  mkbootimg = unpack "titan-mkbootimg-${mkbootimgRev}" (fetchurl {
    url = "https://github.com/LineageOS/android_system_tools_mkbootimg/archive/${mkbootimgRev}.tar.gz";
    hash = "sha256-5nCtYO+WO4XqCwvBy16gtlknCuFCSjWpBG2H1vLrSbw=";
  });

  # Gitiles can regenerate different gzip bytes for the same tree. Pin its
  # extracted contents, including executable bits, rather than the gzip stream.
  avb = fetchzip {
    name = "titan-avb-342b0af8402a12b4c8cce6af5b54653beab1b05c";
    url = "https://android.googlesource.com/platform/external/avb/+archive/342b0af8402a12b4c8cce6af5b54653beab1b05c.tar.gz";
    stripRoot = false;
    hash = "sha256-pmj+IkcEF8zN/vcXCNh78ZKIglJHExm3Zu+hNF59P9w=";
  };

  # These URLs are mutable release/download locations; the content hashes are
  # the pins. An upstream replacement must fail the build until reviewed.
  initramfs = fetchurl {
    url = "https://github.com/halium/initramfs-tools-halium/releases/download/dynparts-lvm/initrd.img-touch-arm64-lvm";
    hash = "sha256-QxZw2NMQ33ZA1p9nF4SpYrF8vTKm5MUFhc2Abw925uY=";
  };
  vbmeta = fetchurl {
    url = "https://dl.google.com/developers/android/qt/images/gsi/vbmeta.img";
    hash = "sha256-9tpUif2HfLac9h+nIc/W135TAISu/puWZk+BiUf/YfY=";
  };
}
