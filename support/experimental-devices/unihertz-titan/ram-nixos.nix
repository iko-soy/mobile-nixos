{ pkgs, kernel }:

# Build-only RAM NixOS experiment for the native route (ram-nixos/README.adoc):
# a NixOS system whose store is a squashfs pushed from the Mac over the USB
# network into RAM, started by a small busybox stage 0 in the recovery image.
# The phone's board tree has its eMMC controller disabled, so Linux never
# touches storage. The VM build runs the same stage 0 and configuration on
# x86_64 with virtio networking.
let
  inherit (pkgs) lib;
  nixosSystem = { system, interface, authorizedKey, defaultSeconds, hardDeadlineSeconds }:
    (import "${pkgs.path}/nixos/lib/eval-config.nix" {
      system = null;
      modules = [
        (import ./ram-nixos/configuration.nix { inherit interface authorizedKey defaultSeconds hardDeadlineSeconds; })
        { nixpkgs.hostPlatform = system; }
      ];
    }).config.system.build.toplevel;
  snakeOil = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  # Sessions end 20 minutes after boot unless titan-session moves the end,
  # and at the latest at the hard deadline: 75 minutes until hardware has
  # shown a checker-driven restart and the thermal behaviour of a longer run.
  phoneHardDeadline = 4500;
  phoneSystem = nixosSystem {
    system = "aarch64-linux";
    interface = "usb0";
    authorizedKey = lib.fileContents ./ram-nixos/authorized_keys;
    defaultSeconds = 1200;
    hardDeadlineSeconds = phoneHardDeadline;
  };
  # Short enough for the VM cases to observe the restarts.
  vmHardDeadline = 840;
  vmSystem = nixosSystem {
    system = "x86_64-linux";
    interface = "eth0";
    authorizedKey = snakeOil.snakeOilEd25519PublicKey;
    defaultSeconds = 480;
    hardDeadlineSeconds = vmHardDeadline;
  };
  squashfs = name: toplevel: pkgs.callPackage "${pkgs.path}/nixos/lib/make-squashfs.nix" {
    fileName = name;
    storeContents = [ toplevel ];
    # The phone kernel has squashfs xz and zlib support, not zstd.
    comp = "xz -Xdict-size 100%";
  };
  phoneSquashfs = squashfs "titan-ram-nixos-aarch64" phoneSystem;
  vmSquashfs = squashfs "titan-ram-nixos-VM-TEST-ONLY" vmSystem;
  # The phone kernel builds NBD in with 16 devices by default; stage 0 and
  # NixOS accept only loop, RAM and zram devices, so none may be created.
  # systemd reads its crash action here before any configuration. An oops,
  # such as a CPU that fails to go offline for kexec, panics and so restarts
  # after the panic timeout instead of hanging; kexec reuses this line.
  imageCmdline = "nbd.nbds_max=0 systemd.crash_action=reboot panic_on_oops=1";
  mkDeadline = staticPkgs: name: staticPkgs.stdenv.mkDerivation {
    pname = name;
    version = "1";
    src = ./ram-nixos/deadline.c;
    dontUnpack = true;
    dontConfigure = true;
    strictDeps = true;
    buildPhase = ''
      runHook preBuild
      $CC -std=c11 -O2 -Wall -Wextra -Werror -static "$src" -o titan-deadline
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p "$out/bin"
      install -m 0555 titan-deadline "$out/bin/titan-deadline"
    '';
    meta = { platforms = lib.platforms.linux; hydraPlatforms = [ ]; };
  };
  deadline = mkDeadline pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic "titan-ram-deadline";
  vmDeadline = mkDeadline pkgs.pkgsStatic "titan-ram-deadline-VM-TEST-ONLY";
  stage0 = { name, toplevel, image, udc, dataInterface, deadlineSeconds, hardDeadlineSeconds }:
    pkgs.runCommand name { } ''
      bytes=$(stat -c %s ${image})
      hash=$(sha256sum ${image} | cut -d' ' -f1)
      substitute ${./ram-nixos/stage0.sh} "$out" \
        --subst-var-by systemBytes "$bytes" --subst-var-by systemSha256 "$hash" \
        --subst-var-by nixosInit ${toplevel}/init --subst-var-by udc ${udc} \
        --subst-var-by dataInterface "${dataInterface}" \
        --subst-var-by deadlineSeconds ${toString deadlineSeconds} \
        --subst-var-by hardDeadlineSeconds ${toString hardDeadlineSeconds}
      chmod 0555 "$out"
      if grep -q '@[A-Za-z]*@' "$out"; then echo "Unsubstituted value in stage 0" >&2; exit 1; fi
    '';
  phoneStage0 = stage0 {
    name = "titan-ram-stage0";
    toplevel = phoneSystem;
    image = phoneSquashfs;
    udc = "11201000.usb";
    dataInterface = "";
    deadlineSeconds = 600;
    hardDeadlineSeconds = phoneHardDeadline;
  };
  vmStage0 = stage0 {
    name = "titan-ram-stage0-VM-TEST-ONLY";
    toplevel = vmSystem;
    image = vmSquashfs;
    udc = "dummy_udc.0";
    dataInterface = "eth0";
    deadlineSeconds = 150;
    hardDeadlineSeconds = vmHardDeadline;
  };
  applets = [
    "sh" "mount" "mkdir" "cat" "ln" "ip" "udhcpd" "nc" "head" "stat" "sha256sum"
    "rm" "sleep" "reboot" "kill" "switch_root" "env" "timeout" "sync" "insmod" "ls" "tr"
  ];
  mkRamdisk = { name, busybox, deadline, init, machine, modules ? [ ] }:
    pkgs.runCommand name {
      nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.findutils pkgs.binutils ]
        ++ lib.optionals (modules != [ ]) [ pkgs.kmod pkgs.xz pkgs.zstd ];
      meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = [ ]; };
    } ''
      set -o pipefail
      mkdir -p root/{bin,dev,proc,sys,run,sysroot} "$out"
      install -m 0555 ${busybox}/bin/busybox root/bin/busybox
      for applet in ${lib.concatStringsSep " " applets}; do ln -s busybox "root/bin/$applet"; done
      install -m 0555 ${deadline}/bin/titan-deadline root/bin/titan-deadline
      install -m 0555 ${init} root/init
      for binary in busybox titan-deadline; do
        readelf -h "root/bin/$binary" > "$out/$binary.elf.txt"
        readelf -l "root/bin/$binary" > "$out/$binary.segments.txt"
        grep -Eq 'Class:[[:space:]]+ELF64' "$out/$binary.elf.txt"
        grep -Eq 'Machine:[[:space:]]+${machine}' "$out/$binary.elf.txt"
        if grep -q INTERP "$out/$binary.segments.txt"; then echo "$binary is not static" >&2; exit 1; fi
      done
      ${lib.optionalString (modules != [ ]) ''
        mkdir root/vm-modules
        for module in ${lib.concatStringsSep " " modules}; do
          modprobe --set-version ${pkgs.linux.modDirVersion} --dirname ${pkgs.linux.modules} \
            --show-depends "$module" >> depends.txt
        done
        awk '$1 == "insmod" && !seen[$2]++ { print $2 }' depends.txt > modules.list
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
        cp modules.list "$out/modules.list"
      ''}
      find root -exec touch -h -d @1 -- {} +
      (cd root; find . -print0 | LC_ALL=C sort -z \
        | cpio --null -o -H newc --reproducible --owner=0:0 \
        | gzip -n -9) > "$out/initramfs.cpio.gz"
      (cd "$out"; sha256sum initramfs.cpio.gz) > "$out/SHA256SUMS"
      cp root/init "$out/init"
    '';
  ramdisk = mkRamdisk {
    name = "titan-ram-stage0-initramfs-aarch64";
    busybox = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.busybox;
    inherit deadline;
    init = phoneStage0;
    machine = "AArch64";
  };
  vmRamdisk = mkRamdisk {
    name = "titan-ram-stage0-VM-TEST-ONLY-initramfs";
    busybox = pkgs.pkgsStatic.busybox;
    deadline = vmDeadline;
    init = vmStage0;
    machine = "Advanced Micro Devices X86-64";
    modules = [
      "virtio_pci" "virtio_net" "virtio_blk" "configfs" "libcomposite" "dummy_hcd"
      "usb_f_ncm" "usb_f_acm" "loop" "squashfs" "overlay" "zram"
    ];
  };
  # The phone's board tree with only the eMMC host disabled.
  boardDtb = pkgs.runCommand "titan-ram-board-dtb" {
    nativeBuildInputs = [ pkgs.dtc pkgs.python3 ];
  } ''
    mkdir -p "$out"
    base=${kernel}/dtbs/mt6771-unihertz-titan.dtb
    node=/soc/mmc@11230000
    fdtget -t s "$base" "$node" compatible > compatible.txt
    grep -q -- '-mmc' compatible.txt
    cp "$base" ram.dtb
    chmod u+w ram.dtb
    fdtput -t s ram.dtb "$node" status disabled
    dtc -q -I dtb -O dts -o base.dts "$base"
    dtc -q -I dtb -O dts -o ram.dts ram.dtb
    python3 -I - base.dts ram.dts > "$out/difference.txt" <<'PY'
    import difflib, re, sys
    base, ram = (open(path).read().splitlines() for path in sys.argv[1:])
    changed = [line for line in difflib.unified_diff(base, ram, lineterm="", n=0)
               if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    added = [line[1:].strip() for line in changed if line.startswith("+")]
    removed = [line[1:].strip() for line in changed if line.startswith("-")]
    assert added == ['status = "disabled";'] and removed in ([], ['status = "okay";']), changed
    # No MMC host may remain enabled anywhere in the tree.
    hosts = list(re.finditer(r'^(\s*)(mmc@[0-9a-f]+) \{\n(.*?)^\1\};', "\n".join(ram) + "\n", re.M | re.S))
    assert hosts, "no MMC host found"
    for match in hosts:
        assert 'status = "disabled";' in match.group(3), match.group(2)
    print("\n".join(changed))
    PY
    cp ram.dtb "$out/mt6771-unihertz-titan-ram.dtb"
  '';
  vmTests = pkgs.runCommand "titan-ram-nixos-vm-tests" {
    nativeBuildInputs = [ pkgs.python3 ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = [ ]; };
  } ''
    export PYTHONDONTWRITEBYTECODE=1 HOME="$TMPDIR"
    python3 ${./ram-nixos/vm-check.py} \
      --qemu ${pkgs.qemu}/bin/qemu-system-x86_64 --kernel ${pkgs.linux}/bzImage \
      --initrd ${vmRamdisk}/initramfs.cpio.gz --system ${vmSquashfs} \
      --ssh ${pkgs.openssh}/bin/ssh --key ${snakeOil.snakeOilEd25519PrivateKey} \
      --output "$NIX_BUILD_TOP/ram-results"
    cp -r "$NIX_BUILD_TOP/ram-results" "$out"
  '';
  # What titan-kexec loads for a kexec into the same image: the uncompressed
  # kernel (kexec_file_load takes no gzip) and stage 0's initramfs.
  kexecPayload = pkgs.runCommand "titan-ram-kexec-payload" { } ''
    mkdir -p "$out"
    cp ${kernel}/Image "$out/Image"
    cp ${ramdisk}/initramfs.cpio.gz "$out/initramfs.cpio.gz"
    (cd "$out" && sha256sum Image initramfs.cpio.gz) > "$out/SHA256SUMS"
  '';
  # Built-in block drivers that create devices at boot must stay within what
  # stage 0 accepts: loop and zram devices, and NBD only with none created.
  kernelCheck = pkgs.runCommand "titan-ram-kernel-block-check" { } ''
    config=${kernel}/.config
    for option in BLK_DEV_NULL_BLK BLK_DEV_PMEM MTD_BLOCK MTD_UBI_BLOCK BLK_DEV_RNBD_CLIENT; do
      if grep -qx "CONFIG_$option=y" "$config"; then echo "Unexpected built-in block driver: $option" >&2; exit 1; fi
    done
    if grep -qx CONFIG_BLK_DEV_NBD=y "$config"; then
      case " ${imageCmdline} " in *" nbd.nbds_max=0 "*) ;; *) echo "NBD needs nbd.nbds_max=0" >&2; exit 1 ;; esac
    fi
    grep -E '^CONFIG_(BLK_DEV_LOOP|ZRAM|BLK_DEV_NBD|MMC_BLOCK)=' "$config" > "$out"
  '';
  # titan-dtb-check against synthetic trees: what it must accept and refuse.
  dtbCheckTests = pkgs.runCommand "titan-ram-dtb-check-tests" {
    nativeBuildInputs = [ pkgs.dtc ];
  } ''
    check=${pkgs.writeShellApplication {
      name = "titan-dtb-check";
      runtimeInputs = [ pkgs.coreutils pkgs.dtc ];
      text = builtins.readFile ./ram-nixos/dtb-check.sh;
    }}/bin/titan-dtb-check
    cat > base.dts <<'DTS'
    /dts-v1/;
    / {
      #address-cells = <2>;
      #size-cells = <2>;
      memory@40000000 { device_type = "memory"; reg = <0 0x40000000 1 0x80000000>; };
      reserved-memory {
        #address-cells = <2>;
        #size-cells = <2>;
        ranges;
        framebuffer@7e340000 { reg = <0 0x7e340000 0 0x1c80000>; no-map; };
        cma { compatible = "shared-dma-pool"; reusable; size = <0 0x2000000>; alloc-ranges = <0 0x40000000 0 0x80000000>; };
        empty { };
      };
      chosen { bootargs = "console=ttyS0"; };
    };
    DTS
    variant() { sed "$2" base.dts > "$1.dts"; dtc -q -I dts -O dtb -o "$1.dtb" "$1.dts"; }
    dtc -q -I dts -O dtb -o base.dtb base.dts
    variant chosen 's/console=ttyS0/console=ttyS1/'
    variant extra 's|empty { };|empty { }; extra@1 { reg = <0 0x1000 0 0x1000>; };|'
    variant nomap 's/; no-map; };/; };/'
    variant disabled 's/no-map; };/no-map; status = "disabled"; };/'
    variant size 's/size = <0 0x2000000>/size = <0 0x1000000>/'
    variant noempty 's/empty { };//'
    variant memory 's/reg = <0 0x40000000 1 0x80000000>;/reg = <0 0x40000000 1 0x40000000>;/'
    variant memory2 's|chosen {|memory@200000000 { device_type = "memory"; reg = <2 0 0 0x1000>; }; chosen {|'
    variant cells 's/#size-cells = <2>;/#size-cells = <1>;/'
    for accepted in base chosen extra; do
      "$check" base.dtb "$accepted.dtb" || { echo "refused $accepted" >&2; exit 1; }
    done
    for refused in nomap disabled size noempty memory memory2 cells; do
      if "$check" base.dtb "$refused.dtb" 2> "$refused.err"; then echo "accepted $refused" >&2; exit 1; fi
    done
    if "$check" missing.dtb base.dtb 2> missing.err; then echo "accepted a missing running tree" >&2; exit 1; fi
    mkdir -p "$out"
    cat *.err > "$out/refusals.txt"
  '';
  # The phone ramdisk as built: static AArch64 busybox with every applet stage
  # 0 uses, no VM modules, and stage 0's pinned values matching the system.
  phoneChecks = pkgs.runCommand "titan-ram-phone-checks" {
    nativeBuildInputs = [ pkgs.cpio pkgs.gzip ];
    meta = { platforms = [ "x86_64-linux" ]; hydraPlatforms = [ ]; };
  } ''
    mkdir -p "$out" root
    cp ${kernelCheck} "$out/kernel-block.txt"
    (cd root && gzip -dc ${ramdisk}/initramfs.cpio.gz | cpio -id --quiet)
    test ! -e root/vm-modules
    ${pkgs.qemu-user}/bin/qemu-aarch64 root/bin/busybox --list > "$out/applets.txt"
    for applet in ${lib.concatStringsSep " " applets}; do
      grep -qx "$applet" "$out/applets.txt" || { echo "Missing applet: $applet" >&2; exit 1; }
    done
    ${pkgs.qemu-user}/bin/qemu-aarch64 root/bin/busybox sh -n root/init
    grep -qx "SYSTEM_SHA256=$(sha256sum ${phoneSquashfs} | cut -d' ' -f1)" root/init
    grep -qx "SYSTEM_BYTES=$(stat -c %s ${phoneSquashfs})" root/init
    grep -qx "NIXOS_INIT=${phoneSystem}/init" root/init
    grep -qx "UDC=11201000.usb" root/init
    grep -qx "DATA_INTERFACE=" root/init
    grep -qx "DEADLINE_SECONDS=600" root/init
    grep -qx "HARD_DEADLINE_SECONDS=${toString phoneHardDeadline}" root/init
    # The phone's busybox, not the VM's, checks the pinned values.
    emulate() { ${pkgs.qemu-user}/bin/qemu-aarch64 root/bin/busybox "$@"; }
    test "$(emulate stat -c %s ${phoneSquashfs})" = "$(stat -c %s ${phoneSquashfs})"
    echo "$(sha256sum ${phoneSquashfs} | cut -d' ' -f1)  ${phoneSquashfs}" | emulate sha256sum -c -s
    emulate head -c 4096 ${phoneSquashfs} > head.bin
    test "$(stat -c %s head.bin)" = 4096
    cp ${phoneSquashfs} flipped.img
    chmod u+w flipped.img
    printf '\x01' | dd of=flipped.img bs=1 seek=4096 conv=notrunc status=none
    if echo "$(sha256sum ${phoneSquashfs} | cut -d' ' -f1)  flipped.img" | emulate sha256sum -c -s; then
      echo "The phone busybox accepted a changed squashfs" >&2; exit 1
    fi
    rm flipped.img
    printf '%s %s\n' "$(stat -c %s ${phoneSquashfs})" "$(sha256sum ${phoneSquashfs} | cut -d' ' -f1)" > "$out/system"
  '';
in {
  inherit phoneSystem vmSystem phoneSquashfs vmSquashfs phoneStage0 vmStage0 ramdisk vmRamdisk boardDtb
    vmTests phoneChecks kernelCheck imageCmdline kexecPayload dtbCheckTests;
}
