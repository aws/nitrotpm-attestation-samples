{
  description = "Reproducible and Immutable NixOS Images for EC2";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = { self, nixpkgs, flake-utils, nixos-generators, crane, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain pkgs.rust-bin.stable.latest.default;
        in
          rec {
            # All the packages used inside of TEE
            packages = pkgs.callPackage ./tee/packages.nix {
              inherit craneLib;
            };

            lib = {
              # Lib function to build a raw TEE image
              tee-image = { userConfig ? { }, isDebug ? false } :
                pkgs.callPackage ./image/lib.nix {
                  inherit craneLib nixos-generators userConfig isDebug;
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
