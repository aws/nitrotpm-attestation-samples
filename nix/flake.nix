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
          };
        in
          rec {
            # All the packages used inside of TEE
            packages = pkgs.callPackage ./tee/packages.nix { };

            lib = {
              # Lib function to build a raw TEE image
              tee-image = { userConfig ? { }, isDebug ? false, secureBootData ? null } :
                pkgs.callPackage ./image/lib.nix {
                  inherit nixos-generators userConfig isDebug secureBootData;
                  tee-pkgs = packages;
                };
            };

            apps = {
              # Utilities
              # Boot an image with QEMU
              boot-uefi-qemu = pkgs.callPackage ./utils/boot-uefi-qemu.nix { };
              # Create an AMI from the raw image input
              create-ami = pkgs.callPackage ./utils/create-ami.nix { };
            };
          }
      );
}
