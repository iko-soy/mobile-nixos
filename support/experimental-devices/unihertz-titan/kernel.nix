{ lib, stdenv, runCommand, bc, bison, flex, perl, python3, openssl, kmod, which
, sources, toolchains
}:

# This is intentionally a standalone cross-build, not a Mobile NixOS kernel
# module: its Android 4.14 ABI is not supported by the current NixOS userspace.
let
  kernelBuild = stdenv.mkDerivation {
    pname = "unihertz-titan-reference-kernel";
    version = "4.14.141";
    src = sources.kernel;

    nativeBuildInputs = [ bc bison flex perl python3 openssl kmod which ];
    enableParallelBuilding = true;
    hardeningDisable = [ "all" ];
    dontStrip = true;
    dontFixup = true;

    # Stable version information. Same-builder repeats pass, but independent
    # cloud/Linux hashes differ; see README for the unresolved comparison.
    KBUILD_BUILD_USER = "nix";
    KBUILD_BUILD_HOST = "titan-build";
    KBUILD_BUILD_VERSION = "1";
    KBUILD_BUILD_TIMESTAMP = "Sun Sep 13 21:19:17 UTC 2026";
    ARCH = "arm64";
    CLANG_TRIPLE = "aarch64-linux-gnu-";
    CROSS_COMPILE = "aarch64-linux-android-";
    CROSS_COMPILE_ARM32 = "arm-linux-androideabi-";

    postPatch = ''
      patchShebangs scripts
      substituteInPlace Makefile --replace-fail /bin/pwd pwd
    '';

    configurePhase = ''
      runHook preConfigure
      export PATH="${lib.makeBinPath [ toolchains.clang toolchains.gccAarch64 toolchains.gccArm ]}:$PATH"
      makeFlagsArray=(
        O="$PWD/build"
        CC=clang
        HOSTCC=cc
        HOSTCFLAGS="-O2 -std=gnu11 -fcommon"
      )
      mkdir -p build
      make "''${makeFlagsArray[@]}" titan_defconfig halium.config
      runHook postConfigure
    '';

    buildPhase = ''
      runHook preBuild
      make "''${makeFlagsArray[@]}" -j"$NIX_BUILD_CORES"
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p "$out" "$out/share/build-info"
      cp build/arch/arm64/boot/Image build/arch/arm64/boot/Image.gz "$out/"
      cp build/.config "$out/config"
      cp build/System.map build/vmlinux "$out/"
      cp build/include/config/kernel.release "$out/share/build-info/kernel.release"
      if [ -e build/Module.symvers ]; then
        cp build/Module.symvers "$out/share/build-info/"
      fi
      if grep -q '^CONFIG_MODULES=y$' build/.config; then
        make "''${makeFlagsArray[@]}" INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH="$out" modules_install
        find "$out/lib/modules" -type l \( -name build -o -name source \) -delete
      fi
      # The shipped DT table comes from the separately pinned adaptation. Do not
      # silently replace it with any generic MT6771 DTBs compiled by this tree.
      clang --version > "$out/share/build-info/clang.txt"
      aarch64-linux-android-gcc --version > "$out/share/build-info/gcc-aarch64.txt"
      arm-linux-androideabi-gcc --version > "$out/share/build-info/gcc-arm.txt"
      (cd "$out" && sha256sum Image Image.gz config System.map vmlinux) \
        > "$out/share/build-info/SHA256SUMS"
      runHook postInstall
    '';

    meta = {
      description = "Build-only reproduction of the UBports original Titan kernel";
      license = lib.licenses.gpl2Only;
      platforms = [ "x86_64-linux" ];
    };
  };
in
# The old modules_install script hardcodes /sbin/depmod, which does not exist in
# a Nix build. Generate indexes separately with the pinned host kmod; keep this
# packaging step independent of the expensive reference kernel compilation.
runCommand kernelBuild.name {
  nativeBuildInputs = [ kmod ];
  inherit (kernelBuild) meta;
  passthru.unindexed = kernelBuild;
} ''
  mkdir -p "$out"
  for entry in "${kernelBuild}"/*; do
    case "$entry" in
      */lib) ;;
      *) ln -s "$entry" "$out/" ;;
    esac
  done
  if [ -d "${kernelBuild}/lib/modules" ]; then
    mkdir -p "$out/lib"
    cp -r "${kernelBuild}/lib/modules" "$out/lib/"
    chmod -R u+w "$out/lib/modules"
    depmod -b "$out" -F "$out/System.map" \
      "$(cat "$out/share/build-info/kernel.release")"
  fi
''
