{ pkgs ? import ../../../pkgs.nix {} }:

# Standalone build experiments, not a device module for the Mobile NixOS
# evaluator. In particular, referenceBootImage contains the UBports initramfs.
let
  sources = pkgs.callPackage ./sources.nix {}
    // pkgs.callPackage ./kernel-sources.nix {};
  toolchains = pkgs.callPackage ./toolchains.nix { inherit sources; };
  kernel = pkgs.callPackage ./kernel.nix { inherit sources toolchains; };
  referenceBootImage = pkgs.callPackage ./boot-image.nix { inherit sources kernel; };
  rescue = import ./rescue.nix { inherit pkgs; };
  transport = import ./transport.nix { inherit pkgs; };
  producer = import ./producer.nix { inherit pkgs transport; };
  storage = import ./storage.nix { inherit pkgs; };
  acquisition = import ./acquisition.nix { inherit pkgs transport; };
  usb = import ./usb.nix { inherit pkgs; };
  # This pin's Darwin libffi trampoline dylib aborts on macOS 27 when ctypes
  # loads. Backport the targeted upstream fix for the host test interpreter:
  # https://github.com/NixOS/nixpkgs/commit/31ac410db37503704af446f2cad40811fabe0b04
  # Keep the kernel, reference image and repository-wide package set unchanged.
  testPython = if pkgs.stdenv.hostPlatform.isDarwin then pkgs.python3.override {
    libffi = if pkgs.lib.hasInfix "-Wl,-no_fixup_chains" (pkgs.libffi.postBuild or "")
      then pkgs.libffi
      else pkgs.libffi.overrideAttrs (old:
        assert pkgs.lib.hasInfix "-Wl,-no_compact_unwind" old.postBuild;
        {
          postBuild = builtins.replaceStrings
            [ "-Wl,-no_compact_unwind" ]
            [ "-Wl,-no_compact_unwind -Wl,-no_fixup_chains" ]
            old.postBuild;
        });
  } else pkgs.python3;
  toolsSource = pkgs.lib.cleanSourceWith {
    src = ./tools;
    filter = path: type:
      let name = baseNameOf path;
      in (type == "directory" && name != "__pycache__")
        || (type == "regular" && pkgs.lib.hasSuffix ".py" name);
  };

  fixtureKernel = pkgs.runCommand "titan-NONBOOTABLE-kernel-fixture" {
    nativeBuildInputs = [ pkgs.gzip ];
  } ''
    mkdir -p "$out"
    printf '%s\n' 'NONBOOTABLE Titan boot-packaging fixture; not a Linux kernel.' \
      | gzip -n > "$out/Image.gz"
  '';
  packagingFixture = pkgs.callPackage ./boot-image.nix {
    inherit sources;
    kernel = fixtureKernel;
    fixture = true;
  };
in
{
  inherit sources toolchains kernel referenceBootImage rescue transport producer storage acquisition usb;

  tests = pkgs.runCommand "titan-tools-and-boot-packaging-tests" {
    nativeBuildInputs = [ testPython ];
  } ''
    export PYTHONDONTWRITEBYTECODE=1
    # The inventory collector intentionally rejects output in Git checkouts.
    # Nix's private build directory also keeps temporary inventory fixtures out
    # of the source tree, even when the caller builds from a checkout.
    export TMPDIR="$NIX_BUILD_TOP"
    python3 -m unittest discover -s ${toolsSource}/tests -v
    mkdir -p "$out"
    cp ${packagingFixture}/boot-image.json "$out/fixture-inspection.json"
    cp ${packagingFixture}/avb-info.txt "$out/fixture-avb-info.txt"
    printf '%s\n' 'Unit tests and packaging fixture passed; no real kernel or hardware boot tested.' \
      > "$out/README"
  '';
}
