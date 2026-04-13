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

            # The NixOS postgresql module creates the "postgres" user/group automatically.
            # We just need to add it to the kms-init group so it can read the symmetric key dir.
            users.users.postgres = {
              extraGroups = [ "kms-init" ];
            };

            system.stateVersion = "24.11";

            services.udev.extraRules = ''
              KERNEL=="tpm0", OWNER="root", GROUP="tpm", MODE="0660"
            '';

            # systemd service for KMS initialization and symmetric key decryption
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

            # systemd service for LUKS volume unlock
            systemd.services.luks-unlock = {
              description = "Unlock LUKS-encrypted data volume";
              wantedBy = [ "multi-user.target" ];
              requires = [ "kms-init.service" ];
              after = [ "kms-init.service" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = luksInitScript;
                RemainAfterExit = true;
                # Runs as root (needs block device access)
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
              };
            };

            # systemd mount unit for the unlocked LUKS volume
            systemd.mounts = [{
              what = "/dev/mapper/data";
              where = "/data";
              type = "ext4";
              wantedBy = [ "multi-user.target" ];
              requires = [ "luks-unlock.service" ];
              after = [ "luks-unlock.service" ];
              options = "defaults";
              unitConfig = {
                # Prevent systemd from adding this mount to local-fs.target,
                # which would create a dependency cycle:
                # data.mount → luks-unlock → kms-init → basic.target → local-fs.target → data.mount
                DefaultDependencies = false;
              };
            }];

            # systemd service for decrypting server certificate bundle for PostgreSQL mTLS
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
              };
            };

            # Ensure PostgreSQL data directory exists on the encrypted volume.
            # systemd's mount namespacing requires the path to exist before the service starts.
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
                CREATE ROLE "postgres-client" WITH LOGIN SUPERUSER;
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
              # IMDS access control - only kms-init user can reach IMDS
              extraCommands = "
                # Allow kms-init service to access IMDS for KMS operations
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner kms-init -j ACCEPT
                # Allow cert-init service (runs as root) to access IMDS for fetching user data
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner root -j ACCEPT
                # Block all other IMDS access for security
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

            # Enable SSM agent for remote shell access (replaces SSH)
            services.amazon-ssm-agent.enable = true;

            # SSM agent needs IMDS access to register with Systems Manager
            networking.firewall.extraCommands = lib.mkAfter "
              # Allow SSM agent (runs as root) to access IMDS — already covered by root ACCEPT rule
            ";
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
              userConfig = { imports = [ commonUserConfig debugUserConfig ]; };
              isDebug = true;
            };

            raw-image-secure-boot-debug = nitro-tee.lib.${system}.tee-image {
              userConfig = { imports = [ commonUserConfig debugUserConfig ]; };
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
