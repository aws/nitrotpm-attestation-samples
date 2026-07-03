# Nix Attestable AMI Builder

The Nix Attestable AMI Builder helps creating [Attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html) which are confidential, attestable, and reproducible EC2 AMI images. It's designed for workloads that require enhanced security, where the initial state of the EC2 instance needs to be cryptographically measured and verified before any confidential data is bootstrapped on the system.

It provides the Nix framework to build read-only, bit-by-bit reproducible, and measurable EC2 AMIs. These AMIs contain all required attestation logic and helper tools for boilerplate actions, such as extracting TPM attestation reports or decrypting secrets from KMS using such attestation reports.

## How it works

![image](docs/overview.png)

1. Owner of the payload generates an Attestable AMI with the help of this NIX tooling. The tooling helps to harden the image and ensures any instance launched from it does not provide operator access.
2. The generation flow measures the image contents the same way as an instance's UEFI firmware would do during boot. The builds are fully reproducible. The same locked source always builds into an identical AMI which produces the same hash.
3. The Attestable AMI owner creates a KMS secret locked to measurements of newly created AMI.
4. The Attestable AMI owner passes the AMI to a 3rd party
5. The 3rd party runs an instance based on the Attestable AMI on Nitro.
6. During boot, UEFI measures the AMI and securely stores the measurements in [Nitro TPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html)
7. The user application inside the instance fetches the NitroTPM attestation report which contains boot measurements and is signed by a trusted AWS certificate.
8. The User application requests a KMS secret providing the attestation reports with all the boot measurements. If they match the golden reference measurements specified in KMS key policy user application receives required secret in the environment that matches the expectations of AMI creator.

### What is an Attestable AMI

![image](docs/uki.png)

An Attestable AMI is an Amazon Machine Image with a corresponding cryptographic hash that represents all of its contents. The hash is generated during the AMI creation process, and it is calculated based on the contents of that AMI, including the applications, code, and boot process.

You can build an Attestable AMI based on different Operating Systems. A NixOS based Attestable AMI builds a read-only, bit-by-bit reproducible, and measurable Attestable AMI.

The NixOS package store (`/usr/nix/store`) resides on a separate read-only [erofs](https://en.wikipedia.org/wiki/EROFS) partition, containing essential binaries like Attestation Document and KMS Decrypt applications. Users can extend their NixOS with desired configurations and packages, providing flexibility while maintaining security.

To ensure integrity, the Nix store is verified using [`dm-verity`](https://docs.kernel.org/admin-guide/device-mapper/verity.html), with its hash tree stored on a separate read-only partition. The EFI System Partition (ESP) contains a single [Unified Kernel Image (UKI)](https://github.com/uapi-group/specifications/blob/main/specs/unified_kernel_image.md) binary, which includes the kernel, command line (with `dm-verity` root-hash), and initrd.

The UKI binary is measured by the UEFI stage, with the measurement stored in TPM PCR4. This measurement is key to the integrity of the entire AMI and can be used in KMS key policies for decrypting secrets. Any change to system components (sample apps or NixOS config) will alter the `dm-verity` root-hash, which is passed in the UKI command line and ultimately reflected in the TPM PCR4 measurement.

> **Security note (GHSA-xrv8-2pf5-f3q7):** When secure boot is disabled, systemd-boot may append externally-provided kernel command line data on top of the UKI's embedded cmdline. PCR4 does not cover that overlay — PCR12 does. KMS policies that protect attestable AMIs **must** bind `kms:RecipientAttestation:NitroTPMPCR12` (the unmodified-cmdline measurement is the all-zero SHA-384), or alternatively enable secure boot and bind PCR7. The `nginx-kms` example does this automatically. The flake also asserts that `nitrotpm-tools >= 1.1.0` (the version that emits PCR12 in `nitro-tpm-pcr-compute` output).

### Getting started

To build Nix based Attestable AMIs, we provide a [Nix Flake](flake.nix). This flake exposes several [binary packages](tee/packages.nix) that can be used within your own NixOS configuration:

* `nitro-tpm-attest` - Application to fetch TPM attestation document.
* `nitro-tpm-kms-decrypt` - Call KMS Decrypt with attestation document attached.

Please note that in order to ensure reproducibility one needs to save and commit the lock file (`flake.lock`).

To build a complete measured image in RAW format, use the `tee-image` library function. This function packs a preconfigured NixOS with `nitro-tpm-attest` and `nitro-tpm-kms-decrypt` binaries, configures `dm-verity`, and packages the boot chain in a UKI image. The resulting artifacts include precalculated PCR4 measurements for TPM, which can be used as golden records for KMS key policies.

Users can extend the NixOS configuration within `tee-image`. Here's an example:
```nix
{
  description = "Test Attestable AMI";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nitro-tee.url = "path:./";
  };
  outputs = { self, nixpkgs, flake-utils, nitro-tee, ... }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";
        in
        {
          packages.raw-image = nitro-tee.lib.${system}.tee-image {
            userConfig = { config, pkgs, ... }: {
                # NixOS user extension
                systemd.services.hello-world = {
                    description = "Hello World Service";
                    wantedBy = [ "multi-user.target" ];
                    serviceConfig = {
                        Type = "oneshot";
                        ExecStart = "${pkgs.bash}/bin/bash -c 'echo Hello World'";
                    };
                };
                # ...
            };
          };
        }
      );
}
```
Then the image can be built with:
```bash
nix build .#raw-image
```

The `tee-image` function produces an unsigned image with baseline TPM PCR4 measurements and an exported `unsigned.efi` UKI binary. Secure boot signing is an optional post-build step that keeps private keys out of the nix store.

We also provide additional tools to streamline the AMI creation and signing process:

* `create-ami`: A Nix Flake app for uploading the RAW image as an EC2 AMI. It uses the [EBS direct API](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-accessing-snapshot.html) to create an EBS snapshot and then generates a new AMI without launching an instance. Usage:
```bash
nix run .#create-ami -- result/nixos-tee_1.raw
```
* `sign-efi-image`: Signs the unsigned UKI with secure boot keys provided as file paths (not in the nix store), patches the signed UKI into the ESP partition of the writable raw image, and emits a `uefi_data.aws` UEFI variable store for AMI registration. After signing it computes the full TPM PCR set (PCR4 + PCR7) for the signed image and prints the JSON to stdout, so redirect it to capture the golden PCR values. Use this after building to add secure boot signatures without exposing `db.key` in the nix cache. `<image-dir>` is the output of `nix build .#raw-image` (containing `unsigned.efi`, the `*.raw` image, and `repart-output.json`) copied to a writable location; `<keys-dir>` contains `db.crt`, `PK.esl`, `KEK.esl`, and `db.esl` (plus `db.key` unless `--db-key-arn` is used). Pass `--db-key-arn <ARN>` to fetch the db signing key from AWS Secrets Manager and stream it into `sbsign` in memory — the private key is then never written to disk (no `db.key` file is read from `<keys-dir>`). Usage:
```bash
nix run .#sign-efi-image -- <image-dir> <keys-dir> [--db-key-arn <ARN>] > tpm_pcr.json
```
* `compute-pcrs`: Computes TPM PCR values for an EFI image (the upstream `nitro-tpm-pcr-compute` tool exposed directly). The producer flow does not need this — `sign-efi-image` already emits the PCRs — but it lets a verifier or relying party who has a signed image plus the public ESLs (and no signing key) independently compute the golden PCR values. When secure boot ESL files are provided, PCR7 is included alongside PCR4. Output goes to stdout; redirect to a file. Usage:
```bash
nix run .#compute-pcrs -- --image signed.efi --PK PK.esl --KEK KEK.esl --db db.esl > tpm_pcr.json
```
* `generate-uefi-vars`: Generates an AWS UEFI variable store (`uefi_data.aws`) from secure boot ESL files for AMI registration. Usage:
```bash
nix run .#generate-uefi-vars -- -P PK.esl -K KEK.esl --db db.esl -O uefi_data.aws
```
* `boot-uefi-qemu`: A debugging tool that uses QEMU to load the RAW image with a software-emulated TPM. Note that this environment cannot start the full attestation flow. Usage:
```bash
nix run .#boot-uefi-qemu -- result/nixos-tee_1.raw
```

### Secure Boot Workflow

For workloads requiring secure boot, the signing pipeline runs outside of nix:

```bash
# 1. Build unsigned image (produces result/unsigned.efi and result/tpm_pcr.json
#    with PCR4 only — PCR7 is added by sign-efi-image once keys are supplied)
nix build .#raw-image

# 2. Sign the UKI (in a secure environment). This also computes the full PCR
#    set (PCR4 + PCR7) and prints it to stdout — redirect to capture it.
nix run .#sign-efi-image -- <image-dir> <keys-dir> > tpm_pcr.json

# 3. Create AMI with UEFI secure boot variable store
nix run .#create-ami -- result/nixos-tee_1.raw result/uefi_data.aws
```

This separation ensures private signing keys never enter the nix store or cache, while builds remain fully reproducible (same source always produces the same unsigned image and PCR4 values).

**Reproducible PCR7 requires a stable enrolled key set.** PCR4 (UKI content) is reproducible from the source alone, but PCR7 measures the PK/KEK/db EFI Signature Lists — including the owner GUID and every certificate. It is reproducible only if the *same* GUID and PK/KEK/db certs are reused across signings; regenerating any of them changes PCR7. The `nginx-kms` example persists this golden identity in AWS Secrets Manager (see its README) so PCR7 stays stable across deployments, and treats regenerating it as a deliberate PCR7 roll (the revocation model).

## Nix Web Server Example

For an example for how you can use the builder flake to create your own Attestable AMIs, you can look at the [Nix Web Server Example](examples/nginx-kms/). This example demonstrates how to build a minimalistic [Attestable AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html) with NGINX serving incoming decryption requests. The decryption is performed using a symmetric key, which is itself decrypted using AWS KMS based on attestation policy with AMI measurements.

You can use it as a starting point to create your own [Attestable AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html).
