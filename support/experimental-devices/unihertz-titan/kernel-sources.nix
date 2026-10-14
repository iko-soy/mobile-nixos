{ fetchurl, fetchzip }:

# Android's compiler branches are resolved here rather than followed at build
# time. These are the Halium 10 defaults in generic-adaptation build tools
# 7dd99e0de224931a7af1ffcc8d41f3c4c51f5316, used by the pinned Titan adaptation.
let
  kernelRev = "fc94895e6dccf5f8f2cc34abc0255e2a3e4edebe";
  prebuilts = "https://android.googlesource.com/platform/prebuilts";
in
{
  kernel = fetchurl {
    url = "https://gitlab.com/ubports/porting/community-ports/android10/unihertz-titan/kernel-alps-mt6771/-/archive/${kernelRev}/kernel-alps-mt6771-${kernelRev}.tar.gz";
    sha256 = "aa035bfb2317dd21839012feebfa1e8c839a624c5d2b5f0bcc68912e713c8a6e";
  };

  toolchains = {
    clang = fetchzip {
      name = "android-clang-r353983c.tar.gz";
      url = "${prebuilts}/clang/host/linux-x86/+archive/3f889f9c9d42bae85728fa89ba5f92a01704fd83/clang-r353983c.tar.gz";
      stripRoot = false;
      hash = "sha256-te+nUU6FahWKmJQOsPZYV2jtU+P6JnBDFtx3h4ZxY6E=";
    };
    gccAarch64 = fetchzip {
      name = "android-gcc-aarch64-961622e.tar.gz";
      url = "${prebuilts}/gcc/linux-x86/aarch64/aarch64-linux-android-4.9/+archive/961622e926a1b21382dba4dd9fe0e5fb3ee5ab7c.tar.gz";
      stripRoot = false;
      hash = "sha256-01/UBMa4S6GCRpi5jy90nig0/1WLqRPmik21ij6imBc=";
    };
    gccArm = fetchzip {
      name = "android-gcc-arm-09518d2.tar.gz";
      url = "${prebuilts}/gcc/linux-x86/arm/arm-linux-androideabi-4.9/+archive/09518d29069cf5993d0ef25c96a09bc851819b54.tar.gz";
      stripRoot = false;
      hash = "sha256-+TSYkgkQEuQomhM3aSzFuBr+Ze+LHRcGVxFn2saOZ/w=";
    };
  };
}
