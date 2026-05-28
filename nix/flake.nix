{
  description = "Reproducible and Immutable NixOS Images for EC2";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { self, nixpkgs, flake-utils, nixos-generators, ... }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              # GHSA-xrv8-2pf5-f3q7: nitrotpm-tools < 1.1.0 omits PCR12
              # (kernel command line) from the measurement output, allowing an
              # operator with UefiData modify rights to inject cmdline overrides
              # while keeping PCR4 unchanged.
              (final: prev: {
                nitrotpm-tools =
                  assert prev.lib.assertMsg
                    (prev.lib.versionAtLeast prev.nitrotpm-tools.version "1.1.0")
                    "nitrotpm-tools must be >= 1.1.0 for GHSA-xrv8-2pf5-f3q7 (PCR12); nixpkgs provides ${prev.nitrotpm-tools.version}";
                  prev.nitrotpm-tools;
              })
            ];
          };
        in
          rec {
            # All the packages used inside of TEE
            packages = pkgs.callPackage ./tee/packages.nix { };

            lib = {
              # Lib function to build a raw TEE image. Produces an unsigned
              # image; secure boot signing is a separate post-build step
              # (see nix/utils/sign-efi-image.nix) so private keys never
              # enter the nix store.
              tee-image = { userConfig ? { }, isDebug ? false } :
                pkgs.callPackage ./image/lib.nix {
                  inherit nixos-generators userConfig isDebug;
                  tee-pkgs = packages;
                };
            };

            apps = {
              # Utilities
              # Boot an image with QEMU
              boot-uefi-qemu = pkgs.callPackage ./utils/boot-uefi-qemu.nix { };
              # Create an AMI from the raw image input
              create-ami = pkgs.callPackage ./utils/create-ami.nix { };
              # Sign an unsigned EFI binary with secure boot keys
              sign-efi-image = pkgs.callPackage ./utils/sign-efi-image.nix { };
              # Compute TPM PCR values from an EFI image
              compute-pcrs = pkgs.callPackage ./utils/compute-pcrs.nix { };
            };
          }
      );
}
