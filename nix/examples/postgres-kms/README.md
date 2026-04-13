# Nix PostgreSQL + LUKS Example

This example demonstrates how to build an Attestable AMI with a LUKS-encrypted PostgreSQL data volume, unlocked via AWS KMS-attested decryption. The instance boots, measures itself using NitroTPM, decrypts a symmetric key from AWS KMS based on TPM attestation policy, and uses that key to manage a LUKS-encrypted EBS volume. PostgreSQL runs with its data directory on the encrypted volume.

On first boot, the raw EBS volume is automatically LUKS-formatted and an ext4 filesystem is created. On subsequent boots, the volume is simply unlocked and mounted — data persists across instance terminations as long as the same EBS volume and symmetric key are used.

[Full details on the Nix Attestable AMI Builder](../../README.md)

## Architecture / Decrypt Flow

The following sequence describes the boot-time data flow from encrypted symmetric key through to a running PostgreSQL instance:

1. **Instance boots** — NitroTPM measures the Unified Kernel Image (UKI) into PCR registers (PCR4 for the UKI, PCR7 for secure boot if enabled).
2. **`kms-init.service` starts** after `network-online.target` is reached.
3. **Fetches IMDSv2 token** and reads EC2 user data containing the KMS `key_id` and the base64-encoded encrypted `ciphertext`.
4. **Calls `nitro-tpm-kms-decrypt`** which presents the TPM attestation document (including PCR measurements) to AWS KMS.
5. **KMS validates PCR measurements** against the key policy conditions. If the measurements match the golden reference, KMS decrypts the ciphertext.
6. **Decrypted symmetric key** is written to `/run/kms-init/symmetric_key` (tmpfs, mode 0750, kms-init group).
7. **`luks-unlock.service` starts** and reads the symmetric key.
8. **LUKS volume management:**
   - *First boot:* `cryptsetup luksFormat` + `luksOpen` + `mkfs.ext4` on `/dev/mapper/data`
   - *Subsequent boot:* `cryptsetup luksOpen` only
9. **`data.mount`** mounts `/dev/mapper/data` to `/data` as ext4.
10. **`postgresql.service` starts** with its data directory at `/data/postgresql`.

```
network-online.target
        │
        ▼
  kms-init.service
        │  Fetches user data → KMS decrypt with TPM attestation
        │  Writes /run/kms-init/symmetric_key
        ▼
  luks-unlock.service
        │  Reads symmetric key → cryptsetup luksFormat/luksOpen
        ▼
  data.mount (/dev/mapper/data → /data)
        │
        ▼
  postgresql.service (dataDir = /data/postgresql)
```

## Prerequisites

Before you begin, ensure you have the following:

- AWS CLI configured with appropriate permissions (see [Minimal IAM Privileges](#minimal-iam-privileges) below)
- Nix package manager installed
- `jq` command-line JSON processor
- AWS account with sufficient permissions for EC2, EBS, KMS, IAM, and STS operations

## Minimal IAM Privileges

The following IAM permissions are required for the full end-to-end deployment flow. You can scope these to specific resources for tighter security.

**EC2 Instance Management:**
- `ec2:RunInstances`
- `ec2:DescribeInstances`
- `ec2:TerminateInstances`
- `ec2:CreateSecurityGroup`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:DeleteSecurityGroup`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeAvailabilityZones`

**AMI Management:**
- `ec2:RegisterImage`
- `ec2:DeregisterImage`
- `ec2:DescribeImages`

**EBS Volume Management:**
- `ec2:CreateVolume`
- `ec2:DeleteVolume`
- `ec2:AttachVolume`
- `ec2:DescribeVolumes`
- `ec2:CreateTags`

**Snapshot (coldsnap):**
- `ebs:PutSnapshotBlock`
- `ebs:StartSnapshot`
- `ebs:CompleteSnapshot`
- `ec2:CreateSnapshot`
- `ec2:DescribeSnapshots`

**KMS:**
- `kms:CreateKey`
- `kms:Encrypt`
- `kms:ScheduleKeyDeletion`
- `kms:PutKeyPolicy`

**IAM:**
- `iam:CreateRole`
- `iam:DeleteRole`
- `iam:GetRole`
- `iam:CreateInstanceProfile`
- `iam:DeleteInstanceProfile`
- `iam:AddRoleToInstanceProfile`
- `iam:RemoveRoleFromInstanceProfile`
- `iam:GetInstanceProfile`
- `iam:PassRole`
- `iam:ListAttachedRolePolicies`
- `iam:ListRolePolicies`
- `iam:DetachRolePolicy`
- `iam:DeleteRolePolicy`

**STS:**
- `sts:GetCallerIdentity`

<details>
<summary>Full IAM Policy JSON (click to expand)</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2InstanceManagement",
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:TerminateInstances",
        "ec2:CreateSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AMIManagement",
      "Effect": "Allow",
      "Action": [
        "ec2:RegisterImage",
        "ec2:DeregisterImage",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EBSVolumeManagement",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateVolume",
        "ec2:DeleteVolume",
        "ec2:AttachVolume",
        "ec2:DescribeVolumes",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SnapshotColdsnap",
      "Effect": "Allow",
      "Action": [
        "ebs:PutSnapshotBlock",
        "ebs:StartSnapshot",
        "ebs:CompleteSnapshot",
        "ec2:CreateSnapshot",
        "ec2:DescribeSnapshots"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KMSKeyManagement",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:Encrypt",
        "kms:ScheduleKeyDeletion",
        "kms:PutKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMManagement",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:PassRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:DetachRolePolicy",
        "iam:DeleteRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

## Getting Started

Follow these steps to set up and test the Attestable AMI with PostgreSQL and LUKS encryption:

### 1. Configure AWS Credentials

You can configure AWS credentials using one of the following methods:

**Method A: Using AWS CLI Configure (Recommended)**

Configure your AWS credentials using the AWS CLI:

```sh
# For default profile
aws configure

# For a specific profile (useful for multiple accounts)
aws configure --profile myprofile
```

This will prompt you for:
- AWS Access Key ID
- AWS Secret Access Key
- Default region name (e.g., `us-east-2`)
- Default output format (e.g., `json`)

More information can be found on the [official documentation page](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

**Method B: Export Environment Variables**

Alternatively, you can export the required AWS credentials and default region to your current shell:

```sh
export AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
export AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
export AWS_SESSION_TOKEN=<AWS_SESSION_TOKEN>
export AWS_DEFAULT_REGION=us-east-2
```

**Using Profiles**

If you configured a specific profile, you can use it by setting the AWS_PROFILE environment variable:

```sh
export AWS_PROFILE=myprofile
```

The `start.sh` script will automatically detect credentials from either environment variables or your AWS configuration.

### 2. Create Test Setup

Run the following script to build the Attestable image and set up the necessary AWS resources:

```sh
./scripts/start.sh
```

This script performs the following actions:

* Builds an image with NixOS containing:
    * [KMS decrypt application](https://github.com/aws/NitroTPM-Tools/blob/main/nitro-tpm-attest/examples/kms_decrypt.rs) for fetching attestation documents and decrypting ciphertexts
    * [Systemd service](./kms-init.nix) to decrypt and store the symmetric key on system boot
    * [LUKS unlock service](./luks-init.nix) to format (first boot) or unlock (subsequent boots) the encrypted EBS volume
    * PostgreSQL service configured to use the encrypted volume for data storage
* Creates an AMI from the image using EBS direct API
* Sets up AWS resources including an instance role, KMS key with image measurements, encrypted symmetric key, and a blank EBS volume
* Launches an EC2 instance using the new AMI with the EBS volume attached as `/dev/xvdf`. The instance's user data includes the ciphertext of the symmetric key and the KMS key ID needed for decryption.

Optional flags:
- `--secure-boot` — build with secure boot enabled (note: not reproducible)
- `--debug` — build with debug console access and SSH enabled

**Note:** Make sure to copy the public address of the launched instance, as you'll need it for the next step.

### 3. Test PostgreSQL

Use the public IP address of the launched instance to verify PostgreSQL is running:

```sh
./scripts/test.sh -s <INSTANCE_IP>
```

This test connects to PostgreSQL on port 5432 and executes `SELECT 1` to verify the database is accessible. Note that the instance must have been launched with `--debug` for SSH-based testing access.

### 4. Clean Up Resources

To remove all created resources, run:

```sh
./scripts/clean.sh
```

## Important Note on Secure Boot and Reproducibility

When using secure boot enabled builds (e.g., `raw-image-secure-boot`), the builds are **NOT reproducible** because this example generates cryptographic keys at build time. Each build will produce different keys and therefore different measurements for PCR7.

In production scenarios, you should use consistent key material across builds to maintain reproducible measurements.

The non-secure-boot builds (`raw-image`, `raw-image-debug`) remain fully reproducible — building from the same locked `flake.lock` will produce bit-for-bit identical images with identical TPM PCR4 measurements. This ensures that golden reference values used in KMS key policies are predictable and trustworthy.

## First Boot vs Subsequent Boot

This example uses a blank (unformatted) EBS volume that is initialized on-instance at first boot:

- **First boot:** The `luks-unlock.service` detects that `/dev/xvdf` is not LUKS-formatted (via `cryptsetup isLuks`). It runs `cryptsetup luksFormat` to encrypt the volume, `cryptsetup luksOpen` to unlock it, and `mkfs.ext4` to create a filesystem. PostgreSQL then initializes its data directory at `/data/postgresql`.

- **Subsequent boots:** The service detects that `/dev/xvdf` is already LUKS-formatted and simply runs `cryptsetup luksOpen` to unlock it. The existing filesystem and PostgreSQL data directory are preserved.

Data persists across instance terminations as long as:
1. The same EBS volume is reattached to the new instance
2. The same symmetric key (same KMS key and encrypted ciphertext in user data) is used

This design ensures the symmetric key never leaves the attested instance in plaintext — LUKS formatting happens entirely on-instance, not during deployment.

## Cleanup

To tear down all AWS resources created by this example, run:

```sh
./scripts/clean.sh
```

This script reads resource IDs from `artifacts/resources.json` and removes: the EC2 instance, security group, AMI, EBS volume, IAM instance profile and role, and schedules the KMS key for deletion. It continues on individual failures and preserves `resources.json` if any operation fails, so you can re-run it or clean up manually.

## End-to-End Testing

For full lifecycle validation — including data persistence across instance termination — use the end-to-end test script:

```sh
./scripts/e2e-test.sh
```

This script provisions all resources, validates PostgreSQL on first boot, writes test data, terminates the instance, launches a new instance with the same EBS volume, verifies the data persists, and then cleans up all resources. It supports `--secure-boot`, `--debug`, and `--timeout` (default: 600s) flags.
