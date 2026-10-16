# The RAM-only NixOS system (README.adoc in this directory). Stage 0 starts it
# with switch_root after verifying its store squashfs, so it has no kernel,
# initrd or boot loader of its own. Root is a tmpfs and the store an overlay
# on that squashfs; nothing here mounts storage, and the only way in is SSH
# with one key over the USB network.
{ interface, authorizedKey, defaultSeconds, hardDeadlineSeconds }:
{ lib, pkgs, modulesPath, ... }:
let
  # The session restarts the phone at a deadline counted in seconds of uptime:
  # by default defaultSeconds, or as set with titan-session, never later than
  # five minutes before stage 0's hard deadline (deadline.c), which restarts
  # the phone regardless at hardDeadlineSeconds.
  deadlineFile = "/run/titan-session/deadline";
  cap = hardDeadlineSeconds - 300;
  # A missing or malformed deadline means the default; any value is held to
  # the cap, so nothing written to the file can outlast it.
  readDeadline = ''
    deadline=$(cat ${deadlineFile} 2>/dev/null || true)
    case "$deadline" in "" | *[!0-9]*) deadline=${toString defaultSeconds} ;; esac
    if [ "''${#deadline}" -gt 6 ] || [ "$((10#$deadline))" -gt ${toString cap} ]; then deadline=${toString cap}; fi
    deadline=$((10#$deadline))
  '';
  titanSession = pkgs.writeShellApplication {
    name = "titan-session";
    runtimeInputs = [ pkgs.coreutils pkgs.systemd ];
    text = ''
      now=$(cut -d. -f1 /proc/uptime)
      ${readDeadline}
      usage() { echo "titan-session [status | end-in MINUTES (1 to 240) | end]" >&2; exit 2; }
      case "''${1:-status}" in
        status)
          check=$(systemctl is-active titan-deadline.timer || true)
          helper=$( (grep -lx titan-deadline /proc/[0-9]*/comm 2>/dev/null || true) | wc -l)
          echo "uptime ''${now}s; restart at ''${deadline}s of uptime, in $(( (deadline - now) / 60 )) min (check ''${check}); hard limit ${toString hardDeadlineSeconds}s (helper running: ''${helper})"
          ;;
        end-in)
          minutes=''${2:-}
          case "$minutes" in "" | *[!0-9]*) usage ;; esac
          if [ "''${#minutes}" -gt 3 ]; then usage; fi
          minutes=$((10#$minutes))
          if [ "$minutes" -lt 1 ] || [ "$minutes" -gt 240 ]; then usage; fi
          new=$(( now + minutes * 60 ))
          if [ "$new" -gt ${toString cap} ]; then new=${toString cap}; fi
          directory=$(dirname ${deadlineFile})
          mkdir -p "$directory"
          temporary=$(mktemp "$directory/deadline.XXXXXX")
          echo "$new" > "$temporary"
          mv "$temporary" ${deadlineFile}
          echo "restart at ''${new}s of uptime"
          ;;
        end) systemctl reboot ;;
        *) usage ;;
      esac
    '';
  };
  # Refuses a replacement device tree unless it keeps the running tree's
  # reserved regions, memory nodes and cell sizes unchanged (dtb-check.sh).
  titanDtbCheck = pkgs.writeShellApplication {
    name = "titan-dtb-check";
    runtimeInputs = [ pkgs.coreutils pkgs.dtc ];
    text = builtins.readFile ./dtb-check.sh;
  };
  # Loads a kernel and initramfs for kexec only when both match the SHA-256
  # given; `systemctl kexec` then starts them after a clean shutdown. Without
  # --dtb, kexec_file_load reuses the device tree the bootloader passed, with
  # its reserved memory and boot data, and updates only /chosen. With --dtb,
  # kexec_load takes the given tree, which must match its SHA-256 and pass
  # titan-dtb-check against the running tree. APPEND adds only titan_*
  # markers, so it cannot override the command line's safety settings.
  titanKexec = pkgs.writeShellApplication {
    name = "titan-kexec";
    runtimeInputs = [ pkgs.coreutils pkgs.kexec-tools titanDtbCheck ];
    text = ''
      usage() {
        echo "titan-kexec [--dtb DTB DTB_SHA256] KERNEL KERNEL_SHA256 INITRD INITRD_SHA256 [titan_MARKER[=VALUE]]" >&2
        exit 2
      }
      dtb="" dtb_sha256=""
      if [ "''${1:-}" = "--dtb" ]; then
        if [ "$#" -lt 3 ] || [ -z "$2" ]; then usage; fi
        dtb=$2 dtb_sha256=$3
        shift 3
      fi
      if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then usage; fi
      kernel=$1 kernel_sha256=$2 initrd=$3 initrd_sha256=$4 append=''${5:-}
      hashes=("$kernel_sha256" "$initrd_sha256")
      if [ -n "$dtb" ]; then hashes+=("$dtb_sha256"); fi
      for hash in "''${hashes[@]}"; do
        case "$hash" in *[!0-9a-f]*) usage ;; esac
        if [ "''${#hash}" -ne 64 ]; then usage; fi
      done
      if [ -n "$append" ] && ! [[ "$append" =~ ^titan_[a-z0-9_]+(=[A-Za-z0-9_.,-]*)?$ ]]; then usage; fi
      echo "$kernel_sha256  $kernel" | sha256sum --check --quiet
      echo "$initrd_sha256  $initrd" | sha256sum --check --quiet
      arguments=(--initrd="$initrd" --reuse-cmdline)
      if [ -n "$append" ]; then arguments+=(--append="$append"); fi
      if [ -z "$dtb" ]; then
        kexec --kexec-file-syscall --load "$kernel" "''${arguments[@]}"
      else
        echo "$dtb_sha256  $dtb" | sha256sum --check --quiet
        titan-dtb-check /sys/firmware/fdt "$dtb"
        # kexec_load, not the default that tries kexec_file_load first and
        # would ignore the tree.
        kexec --kexec-syscall --load "$kernel" --dtb="$dtb" "''${arguments[@]}"
      fi
      echo "loaded; systemctl kexec starts it"
    '';
  };
in
{
  imports = [ "${modulesPath}/profiles/minimal.nix" ];

  boot.kernel.enable = false;
  boot.initrd.enable = false;
  boot.loader.grub.enable = false;
  fileSystems."/" = { device = "none"; fsType = "tmpfs"; options = [ "mode=0755" ]; };
  swapDevices = [ ];
  # Stage 0 refuses to hand over while any disk is present. Should one appear
  # anyway, at boot (udev replays existing devices) or later, restart at once,
  # and never mount partitions found by GPT type.
  services.udev.extraRules = ''
    ACTION=="add", SUBSYSTEM=="block", KERNEL!="loop*|ram*|zram*", RUN+="${pkgs.systemd}/bin/systemctl --no-block reboot"
  '';
  systemd.generators.systemd-gpt-auto-generator = "/dev/null";

  networking.hostName = "titan";
  networking.useNetworkd = true;
  networking.useDHCP = false;
  # A point-to-point USB link to the owner's Mac; sshd accepts one key only.
  networking.firewall.enable = false;
  systemd.network.wait-online.enable = false;
  # Stage 0 has already brought the link up; keep its kernel name.
  systemd.network.links."10-${interface}" = {
    matchConfig.OriginalName = interface;
    linkConfig.Name = interface;
  };
  systemd.network.networks."10-${interface}" = {
    matchConfig.Name = interface;
    address = [ "172.16.42.1/24" ];
    networkConfig = {
      DHCPServer = true;
      KeepConfiguration = "static";
      ConfigureWithoutCarrier = true;
      LinkLocalAddressing = "ipv6";
    };
    # One lease for the Mac, with no router or name servers, so its traffic
    # never routes through the phone.
    dhcpServerConfig = {
      PoolOffset = 2;
      PoolSize = 1;
      EmitDNS = false;
      EmitNTP = false;
      EmitRouter = false;
    };
    linkConfig.RequiredForOnline = "no";
  };
  services.resolved.enable = false;
  services.timesyncd.enable = false;

  services.openssh = {
    enable = true;
    openFirewall = false;
    hostKeys = [ { path = "/etc/ssh/ssh_host_ed25519_key"; type = "ed25519"; } ];
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
    };
  };
  users.mutableUsers = false;
  users.users.root = {
    hashedPassword = "!";
    openssh.authorizedKeys.keys = [ authorizedKey ];
  };

  services.journald.storage = "volatile";
  nix.enable = false;
  # Nothing to trim without storage.
  services.fstrim.enable = false;
  # Read-only inspection tools for bring-up work over SSH; nothing here
  # drives GPIOs or writes device registers.
  environment.systemPackages = [ titanSession titanKexec titanDtbCheck ] ++ (with pkgs; [
    dtc file less strace htop tmux ethtool iperf3 lsof pv kexec-tools
  ]);
  # The USB controller has no shutdown hook; detach the gadget before a kexec
  # so that no transfer is left running into memory the next kernel reuses.
  systemd.services.titan-gadget-detach = {
    description = "Detach the USB gadget before kexec";
    unitConfig.DefaultDependencies = false;
    wantedBy = [ "kexec.target" ];
    before = [ "systemd-kexec.service" ];
    serviceConfig.Type = "oneshot";
    script = ''
      udc=/sys/kernel/config/usb_gadget/titan-ram/UDC
      if [ -e "$udc" ]; then echo > "$udc" || true; fi
    '';
  };
  users.motd = "RAM NixOS session: titan-session status | end-in MINUTES | end";
  # No console is reachable, so a failed unit must not stop the boot at an
  # emergency shell, and a crash of the service manager restarts instead of
  # freezing (the command line says so too, for crashes before this is read).
  systemd.enableEmergencyMode = false;
  # The hardware watchdog stays untouched, including systemd's default arming
  # at reboot: how the bootloader treats a watchdog reset is unknown.
  systemd.settings.Manager = {
    CrashAction = "reboot";
    RuntimeWatchdogSec = "off";
    RebootWatchdogSec = "off";
  };

  # Restart into the phone's normal boot once the session deadline passes.
  # Checked every 30 seconds from early boot and kept across isolation, so a
  # boot that never reaches its targets still restarts; a missing or
  # malformed deadline means the default.
  systemd.timers.titan-deadline = {
    wantedBy = [ "sysinit.target" ];
    unitConfig = { DefaultDependencies = false; IgnoreOnIsolate = true; };
    timerConfig = { OnBootSec = "30s"; OnUnitActiveSec = "30s"; AccuracySec = "1s"; };
  };
  systemd.services.titan-deadline = {
    description = "Restart at the RAM session deadline";
    unitConfig = { DefaultDependencies = false; IgnoreOnIsolate = true; };
    serviceConfig.Type = "oneshot";
    path = [ pkgs.coreutils pkgs.systemd ];
    script = ''
      ${readDeadline}
      if [ "$(cut -d. -f1 /proc/uptime)" -ge "$deadline" ]; then systemctl reboot; fi
    '';
  };

  system.stateVersion = "26.05";
}
