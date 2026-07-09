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
              # Require nitrotpm-tools >= 1.1.0 so PCR12 is emitted (versions
              # below omit it). See the GHSA-xrv8-2pf5-f3q7 security note in
              # nix/README.md for why PCR12 matters.
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
              # Boot an image with QEMU
              boot-uefi-qemu = pkgs.callPackage ./utils/boot-uefi-qemu.nix { };
              # Create an AMI from the raw image input
              create-ami = pkgs.callPackage ./utils/create-ami.nix { };
              # Sign an unsigned EFI binary with secure boot keys. For the
              # producer flow it also computes the full PCR set (PCR4 + PCR7)
              # and prints the JSON to stdout, so no extra step is needed.
              sign-efi-image = pkgs.callPackage ./utils/sign-efi-image.nix { };
              # Upstream nitro-tpm-pcr-compute, exposed directly for verifiers
              # who have a signed image + public ESLs but not the signing key.
              compute-pcrs = {
                type = "app";
                program = "${pkgs.nitrotpm-tools}/bin/nitro-tpm-pcr-compute";
              };
              # Generate an AWS UEFI variable store from secure boot ESL files
              generate-uefi-vars = pkgs.callPackage ./utils/generate-uefi-vars.nix { };
            };
          }
      );
}
