# Nix PostgreSQL + LUKS + mTLS Example

This example demonstrates how to build an Attestable AMI with a LUKS-encrypted PostgreSQL data volume, unlocked via AWS KMS-attested decryption, and secured with mutual TLS (mTLS) authentication. The instance boots, measures itself using NitroTPM, decrypts a symmetric key from AWS KMS based on TPM attestation policy, and uses that key to manage a LUKS-encrypted EBS volume and decrypt server TLS certificates. PostgreSQL runs with its data directory on the encrypted volume and requires client certificate verification for all remote connections.

On first boot, the raw EBS volume is automatically LUKS-formatted and an ext4 filesystem is created. On subsequent boots, the volume is simply unlocked and mounted — data persists across instance terminations as long as the same EBS volume and symmetric key are used.

[Full details on the Nix Attestable AMI Builder](../../README.md)

## Architecture / Decrypt Flow

The following sequence describes the boot-time data flow from encrypted symmetric key through to a running PostgreSQL instance with mTLS:

1. **Instance boots** — NitroTPM measures the Unified Kernel Image (UKI) into PCR registers (PCR4 for the UKI, PCR7 for secure boot if enabled).
2. **`kms-init.service` starts** after `network-online.target` is reached.
3. **Fetches IMDSv2 token** and reads EC2 user data containing the KMS `key_id`, the base64-encoded encrypted `ciphertext`, and the encrypted `server_cert_bundle`.
4. **Calls `nitro-tpm-kms-decrypt`** which presents the TPM attestation document (including PCR measurements) to AWS KMS.
5. **KMS validates PCR measurements** against the key policy conditions. If the measurements match the golden reference, KMS decrypts the ciphertext.
6. **Decrypted symmetric key** is written to `/run/kms-init/symmetric_key` (tmpfs, mode 0750, kms-init group).
7. **`luks-unlock.service` starts** and reads the symmetric key.
8. **LUKS volume management:**
   - *First boot:* `cryptsetup luksFormat` + `luksOpen` + `mkfs.ext4` on `/dev/mapper/data`
   - *Subsequent boot:* `cryptsetup luksOpen` only
9. **`cert-init.service` starts** — fetches the encrypted server certificate bundle from user data via IMDS, decrypts it using the symmetric key, and writes the CA cert, server cert, and server key to `/run/postgresql-certs/` with correct ownership and permissions.
10. **`data.mount`** mounts `/dev/mapper/data` to `/data` as ext4.
11. **`postgresql.service` starts** with its data directory at `/data/postgresql`, SSL enabled, and `clientcert=verify-full` enforced for all remote connections.

```
network-online.target
        │
        ▼
  kms-init.service
        │  Fetches user data → KMS decrypt with TPM attestation
        │  Writes /run/kms-init/symmetric_key
        ├──────────────────────────┐
        ▼                          ▼
  luks-unlock.service        cert-init.service
        │  cryptsetup               │  Decrypts server cert bundle
        ▼                          │  Writes /run/postgresql-certs/
  data.mount (/data)               │
        │                          │
        └──────────┬───────────────┘
                   ▼
         postgresql.service
           dataDir = /data/postgresql
           SSL + mTLS (clientcert=verify-full)
```

## Prerequisites

Before you begin, ensure you have the following:

- AWS CLI configured with appropriate permissions (see [Minimal IAM Privileges](#minimal-iam-privileges) below)
- Nix package manager installed
- `jq` command-line JSON processor
- AWS account with sufficient permissions for EC2, EBS, KMS, IAM, Secrets Manager, and STS operations

## Minimal IAM Privileges

The following IAM permissions are required for the full end-to-end deployment flow. You can scope these to specific resources for tighter security.

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
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets"
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
        "iam:DeleteRolePolicy",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecretsManagerAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMDebugAccess",
      "Effect": "Allow",
      "Action": [
        "ssm:DescribeInstanceInformation",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:StartSession"
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
    * [Certificate init service](./cert-init.nix) to decrypt the server TLS certificate bundle at boot
    * PostgreSQL service configured with SSL and mTLS (`clientcert=verify-full`) on the encrypted volume
* Creates an AMI from the image using EBS direct API
* Sets up AWS resources including an instance role, KMS key with image measurements, encrypted symmetric key, and a blank EBS volume
* Generates a CA and TLS certificates, encrypts the server bundle into user data, and stores the client bundle in AWS Secrets Manager
* Launches an EC2 instance using the new AMI with the EBS volume attached as `/dev/xvdf`. The instance's user data includes the ciphertext of the symmetric key, the KMS key ID, and the encrypted server certificate bundle.

Optional flags:
- `--secure-boot` — build with secure boot enabled (note: not reproducible)
- `--debug` — build with debug console access and SSM (Systems Manager) remote shell enabled

**Note:** Make sure to copy the public address of the launched instance, as you'll need it for the next step.

### 3. Test PostgreSQL

PostgreSQL is accessible over mTLS on port 5432. To connect, retrieve the client certificate bundle from AWS Secrets Manager (the `SECRET_ARN` is stored in `artifacts/resources.json`) and use `psql` with the client certificates:

```sh
# Retrieve client certs from Secrets Manager
SECRET_ARN=$(jq -r '.SECRET_ARN' artifacts/resources.json)
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query 'SecretString' --output text)
echo "$SECRET_JSON" | jq -r '.ca_cert' | base64 -d > /tmp/ca.crt
echo "$SECRET_JSON" | jq -r '.client_cert' | base64 -d > /tmp/client.crt
echo "$SECRET_JSON" | jq -r '.client_key' | base64 -d > /tmp/client.key
chmod 600 /tmp/client.key

# Connect via mTLS
psql "sslmode=verify-ca sslcert=/tmp/client.crt sslkey=/tmp/client.key sslrootcert=/tmp/ca.crt host=<INSTANCE_PRIVATE_IP> port=5432 dbname=postgres user=postgres-client"
```

In debug mode (`--debug`), SSM Session Manager access with local peer authentication is also available. Connect via:

```sh
aws ssm start-session --target <INSTANCE_ID>
```

### 4. Clean Up Resources

To remove all created resources, run:

```sh
./scripts/clean.sh
```

## Build Variants

The flake produces four image variants from two independent axes: operator access (debug vs production) and boot integrity (secure boot vs standard).

**Debug vs Production** controls operator access:

- Production builds have zero operator access — no console login, no SSH, no SSM agent, no root password. Security assertions are enforced. The only way to interact with the instance is via mTLS to PostgreSQL on port 5432.
- Debug builds enable console auto-login as root, SSM agent for remote shell access, and bypass security assertions. Use for development and troubleshooting only.

**Secure Boot** controls boot integrity verification:

- Without secure boot, the TPM measures the Unified Kernel Image (UKI) into PCR4. Builds are fully reproducible — same source produces identical images with identical PCR4 values.
- With secure boot, the TPM additionally measures the secure boot key hierarchy into PCR7, and the UKI is signed with the db key. This prevents unauthorized bootloaders from running.

| | Standard | Secure Boot |
|---|---|---|
| Production | `raw-image` | `raw-image-secure-boot` |
| Debug | `raw-image-debug` | `raw-image-secure-boot-debug` |

| Variant | Operator Access | TPM PCRs | Reproducible |
|---|---|---|---|
| `raw-image` | None | PCR4 | Yes |
| `raw-image-secure-boot` | None | PCR4 + PCR7 | No* |
| `raw-image-debug` | Console + SSM | PCR4 | Yes |
| `raw-image-secure-boot-debug` | Console + SSM | PCR4 + PCR7 | No* |

*\*Secure boot builds are not reproducible in this example because `secure-boot-data.nix` generates fresh cryptographic keys at build time. Each build produces different keys, different UKI signatures, and therefore different PCR7 measurements.*

**Making secure boot reproducible:** To achieve reproducible secure boot builds, pre-generate the key hierarchy (PK, KEK, db) once and provide them as fixed inputs instead of generating them at build time. Store the keys in a hardware security module or secrets manager and inject them during the build. With consistent key material, the signed UKI and PCR7 measurements become deterministic across builds.

## First Boot vs Subsequent Boot

This example uses a blank (unformatted) EBS volume that is initialized on-instance at first boot:

- **First boot:** The `luks-unlock.service` detects that `/dev/xvdf` is not LUKS-formatted (via `cryptsetup isLuks`). It runs `cryptsetup luksFormat` to encrypt the volume, `cryptsetup luksOpen` to unlock it, and `mkfs.ext4` to create a filesystem. PostgreSQL then initializes its data directory at `/data/postgresql`.

- **Subsequent boots:** The service detects that `/dev/xvdf` is already LUKS-formatted and simply runs `cryptsetup luksOpen` to unlock it. The existing filesystem and PostgreSQL data directory are preserved.

Data persists across instance terminations as long as:
1. The same EBS volume is reattached to the new instance
2. The same symmetric key (same KMS key and encrypted ciphertext in user data) is used

This design ensures the symmetric key never leaves the attested instance in plaintext — LUKS formatting happens entirely on-instance, not during deployment.

## mTLS Authentication

PostgreSQL is configured with mutual TLS (mTLS) for all remote connections. This means both the server and client must present valid certificates signed by the same CA.

**How it works:**

- At provisioning time, a self-signed CA is generated along with server and client certificates. The server certificate bundle is encrypted with the KMS symmetric key and embedded in the instance's user data. The client certificate bundle is stored in AWS Secrets Manager.
- At boot time, the `cert-init.service` decrypts the server certificate bundle inside the TEE and writes the plaintext certificates to `/run/postgresql-certs/` (tmpfs). The server private key never exists in plaintext outside the TEE.
- PostgreSQL is configured with `hostssl all all 0.0.0.0/0 cert clientcert=verify-full`, requiring all remote clients to present a valid certificate signed by the CA.
- Local unix socket connections continue to use peer authentication, preserving debug-mode SSH access.

**Connecting as a client:**

Clients retrieve their certificate bundle from Secrets Manager and connect using `psql` with the client certificate files. The client certificate has CN=`postgres-client`, which maps to the `postgres-client` PostgreSQL role created automatically on first boot.

This example uses `sslmode=verify-ca`, which validates the server certificate is signed by the trusted CA but does not check hostname matching. This is appropriate when connecting by private IP address within a VPC.

For production deployments where hostname verification is required, use `sslmode=verify-full` and generate the server certificate with a Subject Alternative Name (SAN) matching the hostname or IP clients will connect to. For example, when generating the server cert in `05a_create_certificates.sh`, add a SAN extension:

```sh
# Example: add SAN for a DNS name or IP
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:postgres.internal.example.com,IP:10.0.1.50")
```

Then connect with full verification:

```sh
psql "sslmode=verify-full sslcert=/tmp/client.crt sslkey=/tmp/client.key sslrootcert=/tmp/ca.crt host=postgres.internal.example.com port=5432 dbname=postgres user=postgres-client"
```

## Cleanup

To tear down all AWS resources created by this example, run:

```sh
./scripts/clean.sh
```

This script reads resource IDs from `artifacts/resources.json` and removes: the Secrets Manager secret, EC2 instance, security group, AMI, EBS volume, IAM instance profile and role (including inline policies), and schedules the KMS key for deletion. It continues on individual failures and preserves `resources.json` if any operation fails, so you can re-run it or clean up manually.

## End-to-End Testing

For full lifecycle validation — including mTLS connectivity and data persistence across instance termination — use the end-to-end test script:

```sh
./scripts/e2e-test.sh
```

This script provisions all resources (including certificate generation and Secrets Manager storage), validates PostgreSQL connectivity over mTLS on first boot, writes test data, terminates the instance, launches a new instance with the same EBS volume, verifies the data persists over mTLS, and then cleans up all resources including the Secrets Manager secret and IAM inline policies.

By default, the E2E test runs in production mode (no SSH). It supports `--secure-boot`, `--debug` (adds SSM-based checks alongside mTLS), `--timeout` (default: 600s), `--no-cleanup` (skip resource teardown on failure for debugging), and `--admin-role-arn <ARN>` (override the KMS key admin principal) flags.

## Troubleshooting

For step-by-step debugging of the boot chain, LUKS, cert-init, and PostgreSQL setup via SSM, see [TROUBLESHOOT.md](./TROUBLESHOOT.md).
