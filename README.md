# NitroTPM Attestation Samples

This repository contains configurations and examples for creating [Attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html). At the moment, this includes:

- [Nix Attestable AMI Builder](nix/) - a flake for the Nix package manager that provides the foundation for building [Attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html) with Nix
- [Nix Web Server Example](nix/examples/nginx-kms) - an example Attestable AMI based on the Nix Attestable AMI Builder that runs an attested decryption web server

## Nix Attestable AMI Builder

The Nix Attestable AMI Builder helps creating [Attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html) which are confidential, attestable, and reproducible EC2 AMI images. It's designed for workloads that require enhanced security, where the initial state of the EC2 instance needs to be cryptographically measured and verified before any confidential data is bootstrapped on the system. It provides the Nix framework to build read-only, bit-by-bit reproducible, and measurable EC2 AMIs. These AMIs contain attestation logic and helper tools to extract NitroTPM attestation documents and decrypt secrets from KMS with the help of NitroTPM Attestation Documents.

## Nix Web Server Example

For an example for how you can use the builder flake to create your own Attestable AMIs, you can look at the [Nix Web Server Example](nix/examples/nginx-kms/). This example demonstrates how to build a minimalistic [Attestable AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html) with NGINX serving incoming decryption requests. The decryption is performed using a symmetric key, which is itself decrypted using AWS KMS based on attestation policy with AMI measurements.

You can use it as a starting point to create your own [Attestable AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html).

## Amazon Linux 2023 example

You can also create [Attestable AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestable-ami.html) based on [Amazon Linux](https://aws.amazon.com/linux/amazon-linux-2023/) using [kiwi-ng](https://osinside.github.io/kiwi/). For templates and examples, see the [kiwi-image-descriptions-examples](https://github.com/amazonlinux/kiwi-image-descriptions-examples) repository as well as the [EC2 Instance Attestation documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html).
