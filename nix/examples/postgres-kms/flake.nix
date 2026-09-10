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
          lib = nixpkgs.lib;

          # Pinned at build time: a key change requires a rebuild (new PCR4, rejected by policy); must be git-tracked.
          kmsKeyArn =
            if !builtins.pathExists ./kms-key-arn.txt then
              throw ("kms-key-arn.txt is missing from the flake source. It must be git-tracked: "
                + "a git+file:// flake ref only sees tracked paths. "
                + "Run: git add nix/examples/postgres-kms/kms-key-arn.txt")
            else
              let
                raw = lib.removeSuffix "\n" (builtins.readFile ./kms-key-arn.txt);
                pattern = "arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}";
              in
              if raw == "" || builtins.match pattern raw != null then raw
              else
                throw ("kms-key-arn.txt must hold one full KMS key ARN with no surrounding "
                  + "whitespace, or be empty to build unpinned. Got: '" + raw + "'");

          kmsInitScript = pkgs.callPackage ./kms-init.nix { inherit nitro-tee kmsKeyArn; };
          luksInitScript = pkgs.callPackage ./luks-init.nix { };
          certInitScript = pkgs.callPackage ./cert-init.nix { };
          imdsCredentialsScript = pkgs.callPackage ./imds-credentials.nix { };

          # Shared cluster bootstrap SQL. Prod appends NOLOGIN (below); debug
          # omits it so an operator can still `sudo -u postgres psql`.
          basePgInitSql = ''
            CREATE ROLE "postgres-client" WITH LOGIN;
            GRANT ALL ON SCHEMA public TO "postgres-client";
          '';

          commonUserConfig = { config, pkgs, lib, ... }: {
            users.groups.tpm = {};
            users.groups.kms-init = {};
            users.groups.cert-init = {};

            users.users.kms-init = {
              isSystemUser = true;
              group = "kms-init";
              extraGroups = [ "tpm" ];
            };

            # Dedicated uid for the cert-decrypt parser; kms-init group grants read of /run/kms-init without running as root.
            users.users.cert-init = {
              isSystemUser = true;
              group = "cert-init";
              extraGroups = [ "kms-init" ];
            };


            system.stateVersion = "24.11";

            services.udev.extraRules = ''
              KERNEL=="tpm0", OWNER="root", GROUP="tpm", MODE="0660"
            '';

            # Symlinks NVMe EBS disks to their attach-time BDM name (/dev/xvdf); see luks-init.nix.
            services.udev.packages = [ pkgs.amazon-ec2-utils ];

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

            boot.kernelModules = [ "dm-integrity" ];

            # First-boot integrity-tag wipe (~90s/10 GiB) outlasts the 90s default device job timeout, discarding data.mount before luks-unlock finishes; scoped to this device only.
            systemd.units."dev-mapper-data.device" = {
              overrideStrategy = "asDropin";
              text = ''
                [Unit]
                JobRunningTimeoutSec=1800s
              '';
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
                TimeoutStartSec = "1800s";
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
              # Operator-attachable volume; noexec/nosuid safe because PostgreSQL extensions load from the read-only store, not $PGDATA.
              options = "defaults,nodev,nosuid,noexec";
              unitConfig = {
                # Avoid cycle: data.mount → luks-unlock → kms-init → basic.target → local-fs.target → data.mount
                DefaultDependencies = false;
              };
            }];

            systemd.services.cert-init = {
              description = "Decrypt server certificate bundle for PostgreSQL mTLS";
              wantedBy = [ "multi-user.target" ];
              requires = [ "kms-init.service" ];
              after = [ "kms-init.service" ];
              before = [ "postgresql.service" ];
              # Parses operator-controlled bytes with the disk key beside it — confine like kms-init so a parser RCE can't escalate or exfil; CAP_CHOWN split into cert-init-perms.service.
              serviceConfig = {
                Type = "oneshot";
                ExecStart = certInitScript;
                RemainAfterExit = true;
                RuntimeDirectory = "postgresql-certs";
                RuntimeDirectoryMode = "0750";

                User = "cert-init";
                UMask = "0077";   # extracted files start 0600; perms unit widens for postgres

                ReadOnlyPaths = [ "/run/kms-init" ];

                # No network: kms-init already persisted the user-data.
                PrivateNetwork = true;
                RestrictAddressFamilies = [ "AF_UNIX" ];

                ProtectSystem = "strict";
                ProtectKernelTunables = true;
                ProtectControlGroups = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectHome = true;
                ProtectHostname = true;
                ProtectProc = "invisible";
                ProcSubset = "pid";

                PrivateTmp = true;
                PrivateUsers = true;

                DevicePolicy = "closed";

                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RestrictNamespaces = true;

                NoNewPrivileges = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RemoveIPC = true;

                CapabilityBoundingSet = "";
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
                SystemCallErrorNumber = "EPERM";
              };
            };

            # Privileged ownership fixup split from parsing unit: fixed paths only, no operator bytes, holds only chown/chmod caps.
            systemd.services.cert-init-perms = {
              description = "Set postgres ownership on decrypted PostgreSQL certs";
              wantedBy = [ "multi-user.target" ];
              requires = [ "cert-init.service" ];
              after = [ "cert-init.service" ];
              before = [ "postgresql.service" ];
              script = ''
                ${pkgs.coreutils}/bin/chown root:postgres /run/postgresql-certs
                ${pkgs.coreutils}/bin/chown postgres:postgres /run/postgresql-certs/ca.crt /run/postgresql-certs/server.crt /run/postgresql-certs/server.key
                ${pkgs.coreutils}/bin/chmod 0640 /run/postgresql-certs/ca.crt /run/postgresql-certs/server.crt
                ${pkgs.coreutils}/bin/chmod 0600 /run/postgresql-certs/server.key
              '';
              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                ReadWritePaths = [ "/run/postgresql-certs" ];

                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectProc = "invisible";
                ProcSubset = "pid";
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectKernelLogs = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectHostname = true;

                PrivateTmp = true;
                PrivateNetwork = true;
                RestrictAddressFamilies = [ "AF_UNIX" ];
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RestrictNamespaces = true;

                NoNewPrivileges = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RemoveIPC = true;

                # chown needs CAP_CHOWN; chmod on non-self-owned files needs CAP_FOWNER;
                # traversing the parser-owned dir needs CAP_DAC_OVERRIDE.
                CapabilityBoundingSet = [ "CAP_CHOWN" "CAP_FOWNER" "CAP_DAC_OVERRIDE" ];
                SystemCallArchitectures = "native";
                # @chown is privileged, so re-add it after subtracting @privileged.
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" "@chown" ];
                SystemCallErrorNumber = "EPERM";
              };
            };

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

            services.postgresql = {
              enable = true;
              dataDir = "/data/postgresql";
              # Defense in depth: per-page checksums catch torn/spliced pages that slip past dm-integrity.
              initdbArgs = [ "--data-checksums" ];
              # Prod: NOLOGIN blocks a postgres-uid RCE from opening a local superuser session; debug drops it.
              initialScript = pkgs.writeText "init-postgres-client.sql" (basePgInitSql + ''
                ALTER ROLE postgres NOLOGIN;
              '');
              settings = {
                ssl = "on";
                ssl_cert_file = "/run/postgresql-certs/server.crt";
                ssl_key_file = "/run/postgresql-certs/server.key";
                ssl_ca_file = "/run/postgresql-certs/ca.crt";
                listen_addresses = lib.mkForce "*";
              };
              # CN=postgres-client only; superuser rejected over TCP. Deployer holds the CA — see README.
              identMap = ''
                mtls /^postgres-client$ postgres-client
              '';
              # Scope local peer to the postgres uid: with the operator-forged /data catalog,
              # `local all all peer` let any local uid log in as a forged same-named SUPERUSER
              # (COPY FROM PROGRAM shell). postgres-client only connects over mTLS/TCP.
              authentication = lib.mkForce ''
                local all postgres peer
                hostssl all postgres        0.0.0.0/0 reject
                hostssl all postgres        ::/0      reject
                hostssl all postgres-client 0.0.0.0/0 cert clientcert=verify-full map=mtls
                hostssl all postgres-client ::/0      cert clientcert=verify-full map=mtls
              '';
            };

            # Block a planted /data/postgresql/.psqlrc from running \! shell escapes as postgres:
            # PSQLRC=/dev/null, HOME off the untrusted volume, and sandbox to contain any shell.
            users.users.postgres.home = lib.mkForce "/var/empty";

            systemd.services.postgresql-setup = {
              environment.PSQLRC = "/dev/null";
              serviceConfig = {
                # initdb writes PGDATA on the volume; strict rootfs must allow it.
                ReadWritePaths = [ "/data" ];

                ProtectSystem = "strict";
                ProtectHome = true;
                ProtectProc = "invisible";
                ProcSubset = "pid";
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectKernelLogs = true;
                ProtectControlGroups = true;
                ProtectClock = true;
                ProtectHostname = true;

                PrivateTmp = true;

                # Local psql connects over the /run/postgresql unix socket — no INET needed.
                RestrictAddressFamilies = [ "AF_UNIX" ];
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RestrictNamespaces = true;

                NoNewPrivileges = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RemoveIPC = true;

                CapabilityBoundingSet = "";
                SystemCallArchitectures = "native";
                SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
                SystemCallErrorNumber = "EPERM";
              };
            };

            systemd.services.postgresql = {
              requires = [ "data.mount" "postgresql-datadir-init.service" "cert-init-perms.service" ];
              after = [ "data.mount" "postgresql-datadir-init.service" "cert-init-perms.service" ];
              serviceConfig = {
                ReadOnlyPaths = [ "/run/postgresql-certs" ];
                # noexec: certs are read only as TLS data, so block dlopen of a
                # polyglot ca.crt planted via session_preload_libraries (outranks -c pins).
                # /run/postgresql is postgres-writable, so it needs the same treatment.
                NoExecPaths = [ "/run/postgresql-certs" "/run/postgresql" ];

                # Contains a backend compromised via the forged /data catalog. Fork/exec
                # cannot be filtered (fork-per-connection), so deny everything else and
                # rely on /data + /run noexec to leave no write+execute path.
                CapabilityBoundingSet = "";
                NoNewPrivileges = true;
                LockPersonality = true;
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                ProtectClock = true;
                ProtectControlGroups = true;
                ProtectHostname = true;
                ProtectKernelLogs = true;
                ProtectKernelModules = true;
                ProtectKernelTunables = true;
                ProtectProc = "invisible";
              };
            };

            networking.firewall = {
              allowedTCPPorts = [ 5432 ];
              # Only kms-init may reach IMDS; all other users dropped. IPv6 IMDS dropped outright (unused).
              extraCommands = "
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner kms-init -j ACCEPT
                ${pkgs.iptables}/bin/iptables -A OUTPUT -d 169.254.169.254 -j DROP
                ${pkgs.iptables}/bin/ip6tables -A OUTPUT -d fd00:ec2::254 -j DROP
              ";
            };
          };

          debugUserConfig = { config, pkgs, lib, ... }: {
            environment.systemPackages = [
              (pkgs.runCommand "imds-credentials" {} ''
                mkdir -p $out/bin
                cp ${imdsCredentialsScript} $out/bin/imds-credentials.sh
              '')
            ];

            services.amazon-ssm-agent.enable = true;

            # Keep superuser LOGIN-able for operator psql (prod hardens to NOLOGIN).
            services.postgresql.initialScript =
              lib.mkForce (pkgs.writeText "init-postgres-client-debug.sql" basePgInitSql);

            # SSM runs as root and needs IMDS; insert ACCEPT before the production DROP.
            networking.firewall.extraCommands = lib.mkAfter "
              ${pkgs.iptables}/bin/iptables -I OUTPUT -d 169.254.169.254 -m owner --uid-owner root -j ACCEPT
            ";
          };
        in
        {
          packages = {
            # Secure boot signing is a post-build step (see sign-efi-image).
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
