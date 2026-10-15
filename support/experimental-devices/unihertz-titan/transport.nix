{ pkgs }:

# Transport sender and host tests. Absent from rescue.ramdisk; only the separate
# build-only usbAcquisition profile starts the sender (usb-pipeline/README.adoc).
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  testSource = lib.cleanSourceWith {
    src = ./transport;
    filter = path: type:
      let name = baseNameOf path;
      in (type == "directory" && name != "__pycache__")
        || (type == "regular" && lib.hasSuffix ".py" name);
  };
  mkSender = staticPkgs: staticPkgs.stdenv.mkDerivation {
    pname = "titan-rescue-transport-sender";
    version = "1";
    src = ./transport/sender.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ staticPkgs.openssl ];
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static -x c "$src" -x none \
        $(pkg-config --cflags --libs --static libcrypto) -o titan-rescue-send
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-rescue-send "$out/bin/titan-rescue-send"
    '';
    meta = {
      description = "Off-device prototype for bounded acknowledged rescue byte transfers";
      license = lib.licenses.mit;
      platforms = lib.platforms.linux;
      hydraPlatforms = [];
    };
  };
  sender = mkSender target;
  nativeSender = mkSender pkgs.pkgsStatic;
  tests = pkgs.runCommand "titan-rescue-transport-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    set -o pipefail
    export PYTHONDONTWRITEBYTECODE=1
    mkdir -p "$out"
    readelf -h ${sender}/bin/titan-rescue-send > "$out/sender.elf.txt"
    readelf -l ${sender}/bin/titan-rescue-send > "$out/sender.segments.txt"
    readelf -d ${sender}/bin/titan-rescue-send > "$out/sender.dynamic.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$out/sender.elf.txt"
    grep -Eq 'Machine:[[:space:]]+AArch64' "$out/sender.elf.txt"
    if grep -q INTERP "$out/sender.segments.txt" \
        || grep -q '(NEEDED)' "$out/sender.dynamic.txt"; then
      echo 'Transport sender unexpectedly depends on a dynamic loader or library' >&2
      exit 1
    fi
    export TITAN_TRANSPORT_SENDER=${nativeSender}/bin/titan-rescue-send
    python3 ${testSource}/test_transport.py > "$out/native-tests.log" 2>&1 \
      || { cat "$out/native-tests.log"; exit 1; }
    export TITAN_TRANSPORT_SENDER=${sender}/bin/titan-rescue-send
    export TITAN_TRANSPORT_EMULATOR=${pkgs.qemu-user}/bin/qemu-aarch64
    python3 ${testSource}/test_transport.py > "$out/aarch64-tests.log" 2>&1 \
      || { cat "$out/aarch64-tests.log"; exit 1; }
    sha256sum ${sender}/bin/titan-rescue-send > "$out/sender-SHA256SUMS"
    printf '%s\n' 'Synthetic socket/PTY/file/pipe tests only; no Titan USB or hardware validation.' \
      > "$out/README"
  '';
in {
  inherit sender nativeSender tests;
}
