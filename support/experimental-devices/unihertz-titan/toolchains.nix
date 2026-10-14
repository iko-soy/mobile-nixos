{ lib, stdenv, stdenvNoCC, autoPatchelfHook, python3, zlib, sources }:

let
  # Preserve the reference compilers and assemblers. Only their host ELF loader,
  # library search paths and Python launchers are adapted to run from /nix/store.
  package = { name, src, compiler, license }:
    stdenvNoCC.mkDerivation {
      pname = "titan-${name}";
      version = "halium-10";
      inherit src;

      nativeBuildInputs = [ autoPatchelfHook python3 ];
      buildInputs = [ stdenv.cc.cc.lib zlib ];
      dontUnpack = true;
      dontStrip = true;
      dontPatchELF = true;
      dontMoveLib64 = true;
      dontAutoPatchelf = compiler == "clang";

      # Clang also ships Android userspace runtimes (including x86_64 ones).
      # They are target libraries, not host executables, and must not acquire
      # Nix host-library dependencies. Only patch its host binaries/libraries.
      postFixup = lib.optionalString (compiler == "clang") ''
        autoPatchelf --no-recurse "$out/bin" "$out/lib64"
      '';

      installPhase = ''
        runHook preInstall
        mkdir -p "$out"
        cp -r "$src/." "$out/"
        chmod -R u+w "$out"

        # Match setup_repositories.sh: bypass Android's Python-2 compiler
        # launchers (which otherwise add no flags) and retain real binaries.
        if [ -e "$out/bin/real-${compiler}" ]; then
          ln -sf "real-${compiler}" "$out/bin/${compiler}"
        else
          ln -sf "${compiler}.real" "$out/bin/${compiler}"
        fi
        patchShebangs "$out"
        runHook postInstall
      '';

      meta = {
        description = "Pinned Android ${name} toolchain for the Titan build experiment";
        platforms = [ "x86_64-linux" ];
        sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
        inherit license;
      };
    };
in
{
  clang = package {
    name = "clang-r353983c";
    src = sources.toolchains.clang;
    compiler = "clang";
    license = [ lib.licenses.asl20 lib.licenses.llvm-exception lib.licenses.ncsa ];
  };
  gccAarch64 = package {
    name = "gcc-aarch64-4.9";
    src = sources.toolchains.gccAarch64;
    compiler = "aarch64-linux-android-gcc";
    license = lib.licenses.gpl3Plus;
  };
  gccArm = package {
    name = "gcc-arm-4.9";
    src = sources.toolchains.gccArm;
    compiler = "arm-linux-androideabi-gcc";
    license = lib.licenses.gpl3Plus;
  };
}
