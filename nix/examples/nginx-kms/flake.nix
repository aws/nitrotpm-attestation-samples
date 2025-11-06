{
  description = "Example of TEE running HTTP server decrypting cipher requests";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nitro-tee.url = "path:../..";
  };
  outputs = { self, nixpkgs, flake-utils, nitro-tee, ... }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";
          fcgiScript = pkgs.callPackage ./fcgi-script.nix { };
          kmsInitScript = pkgs.callPackage ./kms-init.nix { inherit nitro-tee; };
          secureBootData = pkgs.callPackage ./secure-boot-data.nix { };

          # Common configuration shared between production and debug builds
          commonUserConfig = { config, pkgs, lib, ... }: {
            users.groups.tpm = {};
            users.groups.kms-init = {};

            users.users.kms-init = {
              isSystemUser = true;
              group = "kms-init";
              extraGroups = [ "tpm" ];
            };
            users.users.nginx.extraGroups = [ "kms-init" ];

            services.udev.extraRules = ''
              KERNEL=="tpm0", OWNER="root", GROUP="tpm", MODE="0660"
            '';

            # systemd service for system initialization
            systemd.services.kms-init = {
              description = "Initialize KMS and decrypt symmetric key";
              wantedBy = [ "multi-user.target" ];
              requires = [ "network-online.target" ];
              after = [ "network-online.target" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = kmsInitScript;
                RemainAfterExit = true;

                User = "kms-init";
                RuntimeDirectory = "kms-init";
                RuntimeDirectoryMode = "0750";
                UMask = "0027";

                ProtectSystem = "strict";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectHome = true;
                ProtectHostname = true;
                ProtectProc = "invisible";
                ProcSubset = "pid";

                PrivateTmp = true;
                PrivateUsers = true;

                DevicePolicy = "closed";
                DeviceAllow = [ "/dev/tpm0 rw" ];

                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RestrictNamespaces = true;

                NoNewPrivileges = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RemoveIPC = true;

                CapabilityBoundingSet = "";
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources"];
                SystemCallErrorNumber = "EPERM";
              };
            };

            services = {
              # nginx service
              nginx = {
                enable = true;

                virtualHosts."mytest.com" = {
                  locations."/" = {
                    fastcgiParams = {
                      SCRIPT_FILENAME = "${fcgiScript}";
                    };
                    extraConfig = ''
                      fastcgi_pass unix:/run/fcgiwrap/fcgiwrap.sock;
                    '';
                  };
                };
              };

              # fcgiwrap to handle FastCGI requests
              fcgiwrap.instances.nginx = {
                socket = {
                  inherit (config.services.nginx) user group;
                  mode = "0660";
                  address = "/run/fcgiwrap/fcgiwrap.sock";
                };
                process = {
                  inherit (config.services.nginx) user group;
                };
              };
            };

            # App-specific firewall configuration
            networking.firewall = {
              # Open port 80 for nginx HTTP service
              allowedTCPPorts = [ 80 ];
              # IMDS access control - specific to AWS KMS integration
              extraCommands = "
                # Allow kms-init service to access IMDS for KMS operations
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner kms-init -j ACCEPT
                # Allow nginx service to access IMDS for KMS operations
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner nginx -j ACCEPT
                # Block all other IMDS access for security
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -j DROP
              ";
            };
          };
        in
        {
          packages = {
            # Production build (default)

            raw-image = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = false;
            };

            raw-image-secure-boot = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = false;
              secureBootData = secureBootData;
            };

            # Debug build with console access enabled
            # WARNING: This enables operator access and bypasses security!

            raw-image-debug = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = true;
            };

            raw-image-secure-boot-debug = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = true;
              secureBootData = secureBootData;
            };
          };

          # Expose the apps from nitro-tee
          apps = {
            boot-uefi-qemu = nitro-tee.apps.${system}.boot-uefi-qemu;
            create-ami = nitro-tee.apps.${system}.create-ami;
            create-ami-secure-boot = {
              type = "app";
              program = "${pkgs.writeShellScript "create-ami-secure-boot" ''
                ${nitro-tee.apps.${system}.create-ami.program} "$1" "${secureBootData.uefiVarStore}/uefi_data.aws"
              ''}";
            };
          };
        }
      );
}
