{
  pkgs,
  lib,
  modulesPath,
  ...
}: {
  imports = [
    "${toString modulesPath}/profiles/minimal.nix"
    "${toString modulesPath}/profiles/qemu-guest.nix"
  ];

  system.image = {
    id = lib.mkDefault "nixos-tee";
    version = "1";
  };

  boot.enableContainers = lib.mkDefault false;
  boot.initrd.systemd.enable = lib.mkDefault true;

  documentation.info.enable = lib.mkDefault false;

  networking.useNetworkd = lib.mkDefault true;
  networking.firewall.enable = lib.mkDefault true;

  nix.enable = false;

  programs.command-not-found.enable = lib.mkDefault false;
  programs.less.lessopen = lib.mkDefault null;

    # Secure network defaults
  systemd.network = {
    enable = lib.mkDefault true;
    networks."10-secure" = {
      matchConfig.Name = lib.mkDefault "*";
      networkConfig = {
        DHCP = lib.mkDefault "ipv4";
        IPv6AcceptRA = lib.mkDefault false;
        LinkLocalAddressing = lib.mkDefault "no";
        LLMNR = lib.mkDefault false;
        MulticastDNS = lib.mkDefault false;
        DNSOverTLS = lib.mkDefault "opportunistic";
        DNSSEC = lib.mkDefault "allow-downgrade";
      };
    };
  };

  # Disable auto-login
  services.getty.autologinUser = lib.mkForce null;
  services.sshd.enable = lib.mkForce false;
  services.udisks2.enable = false; # udisks has become too bloated to have in a headless system

  system.disableInstallerTools = lib.mkDefault true;
  system.switch.enable = lib.mkDefault false;

  users.mutableUsers = false;
  # Remove root password
  users.users.root.hashedPassword = lib.mkForce null;
  # Disable checking that at least the `root` user or a user in the `wheel` group can log in using a password or an SSH key
  users.allowNoPasswordLogin = lib.mkForce true;
}
