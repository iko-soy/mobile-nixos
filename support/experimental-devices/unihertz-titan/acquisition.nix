{ pkgs, transport }:

# Build-only block-source integration. No phone ramdisk, USB startup or boot
# operation is supplied. Only the separate VM profile is executed by vmTests.
let
  inherit (pkgs) lib;
  target = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic;
  headers = lib.cleanSourceWith {
    src = ./source;
    filter = path: type: type == "directory" || baseNameOf path == "guard.h";
  };
  transportSource = lib.cleanSourceWith {
    src = ./transport;
    filter = path: type:
      let name = baseNameOf path;
      in (type == "directory" && name != "__pycache__")
        || (type == "regular" && lib.hasSuffix ".py" name);
  };
  mkProducer = staticPkgs: vmTest: staticPkgs.stdenv.mkDerivation {
    pname = "titan-block-produce${lib.optionalString vmTest "-VM-TEST-ONLY"}";
    version = "1";
    src = ./producer/supervisor.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_PRODUCER_BLOCK_SOURCE ${lib.optionalString vmTest "-DTITAN_SOURCE_VM_TEST"} \
        -I ${headers} -x c "$src" ${./source/guard.c} -o titan-block-produce
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-block-produce "$out/bin/titan-block-produce"
    '';
    meta = {
      description = "Build-only guarded userdata imaging producer${lib.optionalString vmTest " (VM fixture)"}";
      license = lib.licenses.mit;
      platforms = lib.platforms.linux;
      hydraPlatforms = [];
    };
  };
  producer = mkProducer target false;
  vmProducer = mkProducer pkgs.pkgsStatic true;
  vmInit = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "titan-acquisition-VM-TEST-ONLY-init";
    version = "1";
    src = ./block/vm-test.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static \
        -DTITAN_RESCUE_VM_TEST -DTITAN_RESCUE_DISCOVERY_SECONDS=5 \
        -DTITAN_BLOCK_VM_TEST -DTITAN_SOURCE_VM_TEST -I ${headers} \
        ${./rescue/init.c} ${./source/guard.c} -x c "$src" -o init
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 init "$out/bin/init"
    '';
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  };
  holdZstd = pkgs.pkgsStatic.stdenv.mkDerivation {
    pname = "titan-acquisition-VM-TEST-ONLY-compressor-proxy";
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
  vmKernel = pkgs.linux;
  e2fsprogs = pkgs.pkgsStatic.e2fsprogs.override { withFuse = false; };
  vmRamdisk = pkgs.runCommand "titan-acquisition-VM-TEST-ONLY-initramfs" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.xz pkgs.zstd pkgs.kmod pkgs.binutils ];
    meta.hydraPlatforms = [];
  } ''
    set -o pipefail
    mkdir -p root/{bin,dev,proc,sys,run,tmp,vm-modules} "$out"
    install -m 0555 ${vmInit}/bin/init root/rescue-init
    install -m 0555 ${pkgs.pkgsStatic.busybox}/bin/busybox root/bin/busybox
    install -m 0555 ${vmProducer}/bin/titan-block-produce root/bin/titan-block-produce
    install -m 0555 ${transport.nativeSender}/bin/titan-rescue-send root/bin/titan-rescue-send
    install -m 0555 ${lib.getBin e2fsprogs}/bin/e2image root/bin/e2image
    install -m 0555 ${lib.getBin pkgs.pkgsStatic.zstd}/bin/zstd root/bin/zstd
    install -m 0555 ${holdZstd}/bin/hold-zstd root/bin/hold-zstd
    for binary in root/rescue-init root/bin/*; do
      readelf -h "$binary" > "$out/$(basename "$binary").elf.txt"
      readelf -l "$binary" > "$out/$(basename "$binary").segments.txt"
      readelf -d "$binary" > "$out/$(basename "$binary").dynamic.txt"
      grep -Eq 'Class:[[:space:]]+ELF64' "$out/$(basename "$binary").elf.txt"
      grep -Eq 'Machine:.*X86-64' "$out/$(basename "$binary").elf.txt"
      if grep -q INTERP "$out/$(basename "$binary").segments.txt" \
          || grep -q '(NEEDED)' "$out/$(basename "$binary").dynamic.txt"; then
        echo "Unexpected dynamic VM binary: $binary" >&2
        exit 1
      fi
    done
    for module in virtio_pci virtio_blk; do
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
  '';
  vmTests = pkgs.runCommand "titan-acquisition-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.e2fsprogs pkgs.zstd pkgs.binutils ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = []; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    export TITAN_TRANSPORT_SOURCE=${transportSource}
    python3 ${./block/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 \
      --kernel ${vmKernel}/bzImage \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --output "$out"
    readelf -h ${producer}/bin/titan-block-produce > "$out/producer.elf.txt"
    readelf -l ${producer}/bin/titan-block-produce > "$out/producer.segments.txt"
    readelf -d ${producer}/bin/titan-block-produce > "$out/producer.dynamic.txt"
    grep -Eq 'Class:[[:space:]]+ELF64' "$out/producer.elf.txt"
    grep -Eq 'Machine:[[:space:]]+AArch64' "$out/producer.elf.txt"
    if grep -q INTERP "$out/producer.segments.txt" \
        || grep -q '(NEEDED)' "$out/producer.dynamic.txt"; then
      echo 'Block producer unexpectedly has dynamic dependencies' >&2
      exit 1
    fi
    python3 - ${pkgs.qemu-user}/bin/qemu-aarch64 ${producer}/bin/titan-block-produce \
      > "$out/production-cli.log" <<'PY'
    import os, subprocess, sys, tempfile
    emulator, binary = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="titan-block-cli-") as directory:
        path = os.path.join(directory, "regular-source")
        with open(path, "wb") as stream:
            stream.write(bytes(2048))
        for option in (None, "--input-fd", "--e2image", "--zstd"):
            source = os.open(path, os.O_RDONLY)
            data_read, data_write = os.pipe()
            status_read, status_write = os.pipe()
            try:
                command = [emulator, binary, "--output-fd", str(data_write),
                           "--status-fd", str(status_write), "--max-bytes", "4096",
                           "--timeout-seconds", "2"]
                if option is not None:
                    value = str(source) if option == "--input-fd" else "/bin/" + option[2:]
                    command += [option, value]
                result = subprocess.run(command, pass_fds=(source, data_write, status_write),
                                        capture_output=True, timeout=5)
            finally:
                for descriptor in (source, data_write, status_write):
                    os.close(descriptor)
            try:
                data = os.read(data_read, 32)
                status = os.read(status_read, 32)
                assert result.stdout == b"" and data == b""
                if option is None:
                    assert result.returncode == 2 and status == b"TPST\0\0\0\2", result
                else:
                    assert result.returncode == 1 and status == b"", (option, result, status)
            finally:
                os.close(data_read)
                os.close(status_read)
            print((option or "non-rescue environment") + ": rejected as expected")
    PY
    sha256sum ${producer}/bin/titan-block-produce > "$out/producer-SHA256SUMS"
  '';
in {
  inherit producer vmRamdisk vmTests;
}
