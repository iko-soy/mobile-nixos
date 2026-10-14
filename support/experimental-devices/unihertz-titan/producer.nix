{ pkgs, transport }:

# Synthetic-image pipeline supervision only. No phone storage, PID 1 or gadget
# integration is supplied; production paths are fixed inside a future ramdisk.
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  transportSource = lib.cleanSourceWith {
    src = ./transport;
    filter = path: type:
      let name = baseNameOf path;
      in (type == "directory" && name != "__pycache__")
        || (type == "regular" && lib.hasSuffix ".py" name);
  };
  mkSupervisor = staticPkgs: fixture: staticPkgs.stdenv.mkDerivation {
    pname = "titan-rescue-producer${lib.optionalString fixture "-TEST-ONLY"}";
    version = "1";
    src = ./producer/supervisor.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        ${lib.optionalString fixture "-DTITAN_PRODUCER_TEST_ONLY"} \
        -x c "$src" -o titan-rescue-producer
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-rescue-producer "$out/bin/titan-rescue-producer"
    '';
    meta = {
      description = "Off-device ext4 imaging/compression supervisor${lib.optionalString fixture " (test variant)"}";
      license = lib.licenses.mit;
      platforms = lib.platforms.linux;
      hydraPlatforms = [];
    };
  };
  supervisor = mkSupervisor target false;
  nativeFixture = mkSupervisor pkgs.pkgsStatic true;
  emulatedFixture = mkSupervisor target true;
  tests = pkgs.runCommand "titan-rescue-producer-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.e2fsprogs pkgs.zstd pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    set -o pipefail
    export PYTHONDONTWRITEBYTECODE=1
    mkdir -p "$out"
    readelf -h ${supervisor}/bin/titan-rescue-producer > "$out/supervisor.elf.txt"
    readelf -l ${supervisor}/bin/titan-rescue-producer > "$out/supervisor.segments.txt"
    readelf -d ${supervisor}/bin/titan-rescue-producer > "$out/supervisor.dynamic.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$out/supervisor.elf.txt"
    grep -Eq 'Machine:[[:space:]]+AArch64' "$out/supervisor.elf.txt"
    if grep -q INTERP "$out/supervisor.segments.txt" \
        || grep -q '(NEEDED)' "$out/supervisor.dynamic.txt"; then
      echo 'Producer unexpectedly depends on a dynamic loader or library' >&2
      exit 1
    fi
    export TITAN_TRANSPORT_SOURCE=${transportSource}
    export TITAN_E2IMAGE=${lib.getBin pkgs.e2fsprogs}/bin/e2image
    export TITAN_ZSTD=${lib.getBin pkgs.zstd}/bin/zstd
    export TITAN_PRODUCER=${nativeFixture}/bin/titan-rescue-producer
    export TITAN_PRODUCTION_PRODUCER=${supervisor}/bin/titan-rescue-producer
    export TITAN_PRODUCTION_EMULATOR=${pkgs.qemu-user}/bin/qemu-aarch64
    export TITAN_TRANSPORT_SENDER=${transport.nativeSender}/bin/titan-rescue-send
    python3 ${./producer/test_producer.py} > "$out/native-tests.log" 2>&1 \
      || { cat "$out/native-tests.log"; exit 1; }
    export TITAN_PRODUCER=${emulatedFixture}/bin/titan-rescue-producer
    export TITAN_PRODUCER_EMULATOR=${pkgs.qemu-user}/bin/qemu-aarch64
    export TITAN_TRANSPORT_SENDER=${transport.sender}/bin/titan-rescue-send
    export TITAN_TRANSPORT_EMULATOR=${pkgs.qemu-user}/bin/qemu-aarch64
    python3 ${./producer/test_producer.py} > "$out/aarch64-tests.log" 2>&1 \
      || { cat "$out/aarch64-tests.log"; exit 1; }
    sha256sum ${supervisor}/bin/titan-rescue-producer > "$out/supervisor-SHA256SUMS"
    printf '%s\n' 'Synthetic regular ext4 files only; test supervisors permit executable overrides.' \
      'Imaging/compression executables are native Linux tools in both runs.' \
      'No phone storage acquisition or rescue startup was tested.' > "$out/README"
  '';
in {
  inherit supervisor nativeFixture emulatedFixture tests;
}
