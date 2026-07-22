{
  description = "Example of TEE with LUKS-encrypted PostgreSQL data volume";
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
          kmsInitScript = pkgs.callPackage ./kms-init.nix { inherit nitro-tee; };
          luksInitScript = pkgs.callPackage ./luks-init.nix { };
          certInitScript = pkgs.callPackage ./cert-init.nix { };
          imdsCredentialsScript = pkgs.callPackage ./imds-credentials.nix { };

          commonUserConfig = { config, pkgs, lib, ... }: {
            users.groups.tpm = {};
            users.groups.kms-init = {};

            users.users.kms-init = {
              isSystemUser = true;
              group = "kms-init";
              extraGroups = [ "tpm" ];
            };

            # postgres needs no kms-init group access: cert-init chowns the cert files to it.

            system.stateVersion = "24.11";

            services.udev.extraRules = ''
              KERNEL=="tpm0", OWNER="root", GROUP="tpm", MODE="0660"
            '';

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

            systemd.services.luks-unlock = {
              description = "Unlock LUKS-encrypted data volume";
              wantedBy = [ "multi-user.target" ];
              requires = [ "kms-init.service" ];
              after = [ "kms-init.service" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = luksInitScript;
                RemainAfterExit = true;
                # luks-init.sh waits in-process (up to 120s) for the hot-attached EBS device
                TimeoutStartSec = "180s";
                # Runs as root (needs block device access)
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
              };
            };

            systemd.mounts = [{
              what = "/dev/mapper/data";
              where = "/data";
              type = "ext4";
              wantedBy = [ "multi-user.target" ];
              requires = [ "luks-unlock.service" ];
              after = [ "luks-unlock.service" ];
              options = "defaults";
              unitConfig = {
                # Keep out of local-fs.target to avoid a dependency cycle:
                # data.mount → luks-unlock → kms-init → basic.target → local-fs.target → data.mount
                DefaultDependencies = false;
              };
            }];

            systemd.services.cert-init = {
              description = "Decrypt server certificate bundle for PostgreSQL mTLS";
              wantedBy = [ "multi-user.target" ];
              requires = [ "kms-init.service" ];
              after = [ "kms-init.service" ];
              before = [ "postgresql.service" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = certInitScript;
                RemainAfterExit = true;
                RuntimeDirectory = "postgresql-certs";
                RuntimeDirectoryMode = "0750";

                ReadOnlyPaths = [ "/run/kms-init" ];

                ProtectSystem = "strict";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectHome = true;
                ProtectHostname = true;

                PrivateTmp = true;

                NoNewPrivileges = true;
                RestrictSUIDSGID = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
              };
            };

            # systemd's mount namespacing requires the data directory to exist before postgresql starts
            systemd.services.postgresql-datadir-init = {
              description = "Create PostgreSQL data directory on encrypted volume";
              wantedBy = [ "multi-user.target" ];
              requires = [ "data.mount" ];
              after = [ "data.mount" ];
              before = [ "postgresql.service" ];
              unitConfig.DefaultDependencies = false;
              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                ExecStart = "${pkgs.coreutils}/bin/install -d -o postgres -g postgres -m 0700 /data/postgresql";
              };
            };

            # PostgreSQL configuration on the encrypted volume
            services.postgresql = {
              enable = true;
              dataDir = "/data/postgresql";
              # Create the postgres-client role so mTLS clients with CN=postgres-client can authenticate
              initialScript = pkgs.writeText "init-postgres-client.sql" ''
                CREATE ROLE "postgres-client" WITH LOGIN;
                GRANT ALL ON SCHEMA public TO "postgres-client";
              '';
              settings = {
                ssl = "on";
                ssl_cert_file = "/run/postgresql-certs/server.crt";
                ssl_key_file = "/run/postgresql-certs/server.key";
                ssl_ca_file = "/run/postgresql-certs/ca.crt";
                listen_addresses = lib.mkForce "*";
              };
              authentication = lib.mkForce ''
                # Local unix socket connections (peer auth)
                local all all peer
                # Remote SSL connections requiring client cert
                hostssl all all 0.0.0.0/0 cert clientcert=verify-full
                hostssl all all ::/0 cert clientcert=verify-full
              '';
            };

            # Ensure postgresql starts after the data volume is mounted, dir is created, and certs are ready
            systemd.services.postgresql = {
              requires = [ "data.mount" "postgresql-datadir-init.service" "cert-init.service" ];
              after = [ "data.mount" "postgresql-datadir-init.service" "cert-init.service" ];
              serviceConfig = {
                # Allow PostgreSQL to read the certificate files under ProtectSystem=strict
                ReadOnlyPaths = [ "/run/postgresql-certs" ];
              };
            };

            # Firewall and IMDS access control
            networking.firewall = {
              # Allow inbound PostgreSQL connections over mTLS
              allowedTCPPorts = [ 5432 ];
              # IMDS access control - only the kms-init user can reach IMDS
              extraCommands = "
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner kms-init -j ACCEPT
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -j DROP
              ";
            };
          };

          # Debug-only configuration: adds IMDS credential helper and SSM agent
          debugUserConfig = { config, pkgs, lib, ... }: {
            environment.systemPackages = [
              (pkgs.runCommand "imds-credentials" {} ''
                mkdir -p $out/bin
                cp ${imdsCredentialsScript} $out/bin/imds-credentials.sh
              '')
            ];

            # Enable SSM agent for remote shell access (replaces SSH).
            services.amazon-ssm-agent.enable = true;

            # SSM agent runs as root and needs IMDS; insert the ACCEPT before the DROP (debug only)
            networking.firewall.extraCommands = lib.mkAfter "
              ${pkgs.iptables}/bin/iptables -I OUTPUT -d 169.254.169.254 -m owner --uid-owner root -j ACCEPT
            ";
          };
        in
        {
          packages = {
            # Production build (default); secure boot signing is a post-build step (see sign-efi-image)
            raw-image = nitro-tee.lib.${system}.tee-image {
              userConfig = commonUserConfig;
              isDebug = false;
            };

            # WARNING: debug build enables console/operator access and bypasses security!
            raw-image-debug = nitro-tee.lib.${system}.tee-image {
              userConfig = { imports = [ commonUserConfig debugUserConfig ]; };
              isDebug = true;
            };
          };

          # Expose the apps from nitro-tee
          apps = {
            boot-uefi-qemu = nitro-tee.apps.${system}.boot-uefi-qemu;
            create-ami = nitro-tee.apps.${system}.create-ami;
            sign-efi-image = nitro-tee.apps.${system}.sign-efi-image;
            compute-pcrs = nitro-tee.apps.${system}.compute-pcrs;
            generate-uefi-vars = nitro-tee.apps.${system}.generate-uefi-vars;
          };
        }
      );
}
