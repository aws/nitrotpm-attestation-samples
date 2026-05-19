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
            # Production build (default). Produces an unsigned image; secure
            # boot signing is a post-build step (see sign-efi-image).

            raw-image = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = false;
            };

            # Debug build with console access enabled
            # WARNING: This enables operator access and bypasses security!

            raw-image-debug = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = true;
            };
          };

          apps = {
            boot-uefi-qemu = nitro-tee.apps.${system}.boot-uefi-qemu;
            create-ami = nitro-tee.apps.${system}.create-ami;
            sign-efi-image = nitro-tee.apps.${system}.sign-efi-image;
            compute-pcrs = nitro-tee.apps.${system}.compute-pcrs;

            generate-uefi-vars = let
              python-uefivars = pkgs.fetchFromGitHub {
                owner = "awslabs";
                repo = "python-uefivars";
                rev = "main";
                sha256 = "sha256-HzaKFyKMqEADPvydCdD29P9nC7Qwq/UYvgZYCx4oEhw=";
              };
              pythonEnv = pkgs.python3.withPackages (ps: with ps; [ google-crc32c ]);
            in {
              type = "app";
              program = "${pkgs.writeShellScript "generate-uefi-vars" ''
                if [ "$#" -lt 4 ]; then
                  echo "Usage: generate-uefi-vars -P <PK.esl> -K <KEK.esl> --db <db.esl> -O <output.aws>"
                  exit 1
                fi
                ${pythonEnv}/bin/python3 ${python-uefivars}/uefivars -i none -o aws "$@"
              ''}";
            };
          };
        }
      );
}
