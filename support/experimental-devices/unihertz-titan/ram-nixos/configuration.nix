# The RAM-only NixOS system (README.adoc in this directory). Stage 0 starts it
# with switch_root after verifying its store squashfs, so it has no kernel,
# initrd or boot loader of its own. Root is a tmpfs and the store an overlay
# on that squashfs; nothing here mounts storage, and the only way in is SSH
# with one key over the USB network.
{ interface, authorizedKey, deadline }:
{ lib, pkgs, modulesPath, ... }:
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

  # Restart into the phone's normal boot at the deadline, counted from the
  # kernel's start. Armed in early boot and kept across isolation, so a boot
  # that never reaches its targets still restarts; stopping the timer over
  # SSH is a deliberate choice to keep the session.
  systemd.timers.titan-deadline = {
    wantedBy = [ "sysinit.target" ];
    unitConfig = { DefaultDependencies = false; IgnoreOnIsolate = true; };
    timerConfig = { OnBootSec = deadline; AccuracySec = "1s"; };
  };
  systemd.services.titan-deadline = {
    description = "Restart at the RAM session deadline";
    unitConfig = { DefaultDependencies = false; IgnoreOnIsolate = true; };
    serviceConfig = { Type = "oneshot"; ExecStart = "${pkgs.systemd}/bin/systemctl reboot"; };
  };

  system.stateVersion = "26.05";
}
