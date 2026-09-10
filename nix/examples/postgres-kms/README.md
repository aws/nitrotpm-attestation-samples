# Nix PostgreSQL + LUKS + mTLS Example

This example demonstrates how to build an Attestable AMI with a LUKS-encrypted PostgreSQL data volume, unlocked via AWS KMS-attested decryption, and secured with mutual TLS (mTLS) authentication. The instance boots, measures itself using NitroTPM, decrypts a symmetric key from AWS KMS based on TPM attestation policy, and uses that key to manage a LUKS-encrypted EBS volume and decrypt server TLS certificates. PostgreSQL runs with its data directory on the encrypted volume and requires client certificate verification for all remote connections.

On first boot, the raw EBS volume is automatically LUKS-formatted and an ext4 filesystem is created. On subsequent boots, the volume is simply unlocked and mounted — data persists across instance terminations as long as the same EBS volume and symmetric key are used.

[Full details on the Nix Attestable AMI Builder](../../README.md)

## Architecture / Decrypt Flow

The following sequence describes the boot-time data flow from encrypted symmetric key through to a running PostgreSQL instance with mTLS:

1. **Instance boots** — NitroTPM measures the Unified Kernel Image (UKI) into PCR registers (PCR4 for the UKI, PCR7 for secure boot if enabled).
2. **`kms-init.service` starts** after `network-online.target` is reached.
3. **Fetches IMDSv2 token** and reads EC2 user data containing the KMS `key_id`, the base64-encoded encrypted `ciphertext`, and the encrypted `server_cert_bundle`.
4. **Checks `key_id` against the KMS key ARN pinned into the image** and refuses to continue on any mismatch — user data is not measured into any PCR, so it cannot be trusted to name the key (see [KMS key pinning](#kms-key-pinning)).
5. **Calls `nitro-tpm-kms-decrypt`** with the *pinned* ARN, which presents the TPM attestation document (including PCR measurements) to AWS KMS.
6. **KMS validates PCR measurements** against the key policy conditions. If the measurements match the golden reference, KMS decrypts the ciphertext.
7. **Decrypted symmetric key** is written to `/run/kms-init/symmetric_key` (tmpfs, mode 0750, kms-init group).
8. **`luks-unlock.service` starts** and reads the symmetric key.
9. **LUKS volume management:**
   - *First boot:* `cryptsetup luksFormat` + `luksOpen` + `mkfs.ext4` on `/dev/mapper/data`
   - *Subsequent boot:* `cryptsetup luksOpen` only
10. **`cert-init.service` starts** — fetches the encrypted server certificate bundle from user data via IMDS, decrypts it using the symmetric key, and writes the CA cert, server cert, and server key to `/run/postgresql-certs/` with correct ownership and permissions.
11. **`data.mount`** mounts `/dev/mapper/data` to `/data` as ext4.
12. **`postgresql.service` starts** with its data directory at `/data/postgresql`, SSL enabled, and `clientcert=verify-full` enforced for all remote connections.

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
        │  cryptsetup              │  Decrypts server cert bundle
        ▼                          │  Writes /run/postgresql-certs/
  data.mount (/data)               │
        │                          │
        └──────────┬───────────────┘
                   ▼
         postgresql.service
           dataDir = /data/postgresql
           SSL + mTLS (clientcert=verify-full)
```

## KMS key pinning

EC2 user data is **not** measured into any PCR. If `kms-init` took `key_id` from user data on trust, the account operator could launch this genuine, correctly-measured AMI against a KMS key whose policy *they* control, feed it a ciphertext they made, and get an instance that unlocks an attacker-chosen LUKS volume and serves attacker-chosen mTLS certs — while presenting valid PCR4/PCR7 to a third-party verifier. The attestation would be sound; it just never said anything about *which key* was consulted.

So the expected key ARN is a build input. It lives in [`kms-key-arn.txt`](./kms-key-arn.txt), ends up in the measured store closure, and [`kms-verify.sh`](./kms-verify.sh) compares user data against it by exact string equality before any decrypt. Substituting the key now requires editing the image, which changes PCR4, which the key policy refuses to decrypt for.

This makes key provisioning two-phase, because pinning otherwise makes the dependency graph circular — the ARN must be known *before* the build, but the PCR-gated key policy can only be written *after* it:

| Step | Script | What it does |
|---|---|---|
| 1 | [`02a_create_kms_key.sh`](./scripts/steps/02a_create_kms_key.sh) | Creates the key under a bootstrap policy granting the provisioning principal `kms:PutKeyPolicy` + `kms:Encrypt` + `kms:ScheduleKeyDeletion` — no `Decrypt`, no attestation conditions — and emits the ARN on stdout. `build.sh` (stage 3) writes and git-tracks the ARN pin. |
| 2 | `00_create_ami.sh` | Builds and measures the image, with the ARN inside it. |
| 3 | [`03_create_symmetric_key.sh`](./scripts/steps/03_create_symmetric_key.sh) | Wraps the symmetric key under the pinned key, using the bootstrap `kms:Encrypt` grant — **before** finalize revokes it. |
| 4 | [`02b_finalize_kms_policy.sh`](./scripts/steps/02b_finalize_kms_policy.sh) | Installs the real PCR-gated policy and **drops `kms:PutKeyPolicy` and `kms:Encrypt` in the same call**, leaving the provisioning principal only `kms:ScheduleKeyDeletion` + `kms:ListGrants`/`kms:RevokeGrant` (for grant audit — see [Production Considerations](#production-considerations)). |

Step 4 is a one-way ratchet: by revoking `kms:Encrypt` and `kms:PutKeyPolicy` in the same call that installs the PCR-gated policy, it leaves no principal — including the account admin — able to widen the policy or wrap a new ciphertext that bypasses the NitroTPM conditions. Nothing is exposed before finalize either: the only ciphertext is the deployer's own DEK (wrapped in step 3 under the still-present `Encrypt` grant), and `Decrypt` is PCR-gated from the outset.

Three consequences worth knowing before you build:

- **`kms-key-arn.txt` must stay git-tracked.** When the flake ref resolves to `git+file://`, Nix only sees git-tracked paths, so an untracked file is invisible to the build. Edits to an already-tracked file *are* picked up from the dirty worktree, which is what makes the rewrite work. `build.sh` (stage 3) refuses to proceed if the pinned ARN file is untracked, so you find out before an orphan key exists.
- **An empty file means unpinned.** That keeps a fresh clone and CI buildable without AWS. The resulting image fails closed at boot rather than falling back to trusting user data. `clean.sh` truncates the file back to empty.
- **The AMI is bound to one account, region and key.** A new key means a rebuild, a new PCR4 and a new policy, so `clean.sh` followed by a full new ceremony can no longer reuse an image. That is inherent to pinning, not a limitation of this implementation — it turns the AMI from a reusable artifact into a per-deployment build.

**Scope.** Pinning fixes *which key* is consulted, not *which ciphertext*. Because finalize revokes `kms:Encrypt`, no principal can wrap a fresh symmetric key under the pinned key after deployment, so the ciphertext-substitution vector is closed for the standing policy — the only wrap happens during provisioning (step 3), before the ratchet. The deployer necessarily sees that one plaintext DEK, since `05a_create_certificates.sh` needs it; trusting the deployer at provisioning time is inherent. Pinning a KMS *alias* ARN would sidestep the circularity but give up the property: `UpdateAlias` is mutable and would re-point the trust root without touching the image.

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
        "kms:PutKeyPolicy",
        "kms:Encrypt",
        "kms:ScheduleKeyDeletion"
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

The finalized KMS key policy grants the provisioning principal
`kms:ScheduleKeyDeletion` plus `kms:ListGrants`/`kms:RevokeGrant` (so grants
stay auditable and revocable — see [Production Considerations](#production-considerations)).
`kms:Encrypt` is used during provisioning under the bootstrap policy and dropped
at finalize; the final policy grants no `kms:PutKeyPolicy` or `kms:Encrypt` and
explicitly denies `kms:CreateGrant` to everyone. After installing the policy —
which closes the window in which a grant could be planted — finalize verifies no
grant exists and fails closed if one does, so the attestation condition remains
the only path for decrypting the wrapped symmetric key.

## Roles & Responsibilities

The governing principle: **no single party may both control what code runs (the
measurements) and hold the plaintext secrets.** A party holding both could sign a
rogue image *and* gate the key to that image's PCRs, which makes the attestation
guarantee worthless against an insider.

| Role | Responsibility | Must not hold |
|---|---|---|
| **Deployer** | Build + sign the image, register the AMI, write the pinned `kms-key-arn.txt` | KMS policy control, `kms:Decrypt`, DEK, CA key |
| **Key Custodian** | Create the KMS key, finalize the PCR-gated policy, audit grants, schedule deletion | `kms:Encrypt`, `kms:Decrypt`, signing key |
| **Secrets / PKI Provisioner** | Mint + wrap the DEK, issue CA/server/client certs, upload bundles | `kms:PutKeyPolicy`, `kms:Decrypt`, signing key |
| **Platform Operator** | IAM role/profile, EBS, launch, SG, SSM, teardown | `kms:Decrypt`, any bundle read, signing key |
| **Application / Test Client** | Connect over mTLS as `postgres-client`, read the client bundle | KMS, server bundle, any provisioning write |
| **Instance role** (machine) | Boot-time PCR-gated `kms:Decrypt` | everything else — it needs no identity policy at all |

The JSON policy above is the **single-identity** policy: one principal running the
whole flow. The per-role split is defined in
[`scripts/lib/role-policies.sh`](scripts/lib/role-policies.sh), which is the source
of truth, and provisioned by `scripts/steps/00_create_roles.sh --create-roles`.
Supply no role ARNs and everything runs as the caller exactly as before.

**What the automated test does and does not prove:** a single runner able to assume
all five roles transitively holds all five, and on one host the workspace and
`artifacts/` are a shared filesystem regardless of which credentials are active — the
`AssumeRole` boundary is credential scope, not OS isolation. What it buys is
*boundary-sufficiency validation*: each stage runs with only its role's permissions,
so the run fails if a role lacks one it needs. True separation of duties needs
distinct principals per role in a real pipeline.

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

Each stage script automatically detects credentials from either environment variables or your AWS configuration.

### 2. Run the Deployment Ceremony

The deployment splits across six role-scoped stages. Pass the value each stage emits
directly to the next stage.

**Automated (single runner, CI-friendly):**

```sh
./scripts/e2e-test.sh --create-roles --authorize-my-ip
```

This drives all six stages under assumed roles, validates mTLS connectivity, and
confirms data persistence across instance termination. See
[End-to-End Testing](#end-to-end-testing) for the full flag reference.

**Manual (six stages, one role each):**

```sh
# Stage 1 — Operator: create the instance role and profile
./scripts/prepare-role.sh
# → emits INSTANCE_ROLE_ARN and INSTANCE_PROFILE_NAME

# Stage 2 — Key Custodian: create the KMS key under a bootstrap policy
./scripts/create-key.sh
# → copy the KMS key ARN from the 'KMS key created with ARN:' line

# Stage 3 — Deployer: pin the ARN into the image, build, sign, register the AMI
./scripts/build.sh --key-id <KMS_KEY_ARN>
# → emits AMI_ID and PCR_DIR; the Deployer holds no kms:PutKeyPolicy so it stops here

# Stage 4 — Provisioner: wrap the DEK and issue mTLS certificates
./scripts/provision-secrets.sh --key-id <KMS_KEY_ARN>

# Stage 5 — Key Custodian: install the PCR-gated policy, revoke Encrypt, audit grants
./scripts/finalize-key.sh --key-id <KMS_KEY_ARN> \
  --instance-role-arn <INSTANCE_ROLE_ARN> --pcr-dir <PCR_DIR>

# Stage 6 — Operator: create the data volume and launch the instance
./scripts/deploy.sh --ami-id <AMI_ID> --instance-profile <INSTANCE_PROFILE_NAME>
```

Each stage resolves AWS credentials from the environment or `~/.aws/config`, and all
resource IDs are accumulated in `artifacts/resources.json`. Omit the optional
`*-role-arn` flags and every stage runs under the ambient credentials — the same
single-identity behaviour as before. See
[Roles & Responsibilities](#roles--responsibilities) for a summary of what each
role may and may not do.

**User-data format.** The artifacts are passed to the instance as a single JSON object on EC2 user data (read at boot via IMDSv2). All binary values are single-line base64:

```json
{
  "key_id": "arn:aws:kms:<region>:<account>:key/<uuid>",
  "ciphertext": "<base64(KMS-encrypted symmetric key)>",
  "server_cert_bundle": "<base64(AES-256-CBC(tar of ca.crt + server.crt + server.key))>"
}
```

- `key_id` — the **full key ARN**, not a bare key id. `kms-init` compares it against the ARN pinned into the image by exact string equality and refuses to boot on a mismatch, so a bare id fails every boot. `aws kms encrypt --key-id` accepts either form, which is why `03_create_symmetric_key.sh` validates it up front.
- `ciphertext` — the symmetric key, encrypted with KMS; `kms-init` decrypts it only if the instance's PCRs satisfy the KMS key policy.
- `server_cert_bundle` — a tarball of the server certs encrypted with that symmetric key (not KMS), so `cert-init` must run after `kms-init`.

The **client** certs (`ca.crt`, `client.crt`, `client.key`) are not in user data — they are stored separately in AWS Secrets Manager (base64 fields in a JSON secret) and used by the connecting client.

Optional flags for `build.sh`:
- `--secure-boot` — sign the UKI for secure boot as a post-build step (ephemeral local keys; PCR7 changes each run)
- `--secure-boot --secrets-manager [ARN]` — persist/reuse a secure boot golden identity in AWS Secrets Manager for reproducible PCR7 (keeps `db.key` off disk)
- `--debug` — build with debug console access and SSM (Systems Manager) remote shell enabled

**Note:** Make sure to copy the public address of the launched instance, as you'll need it for the next step.

### 3. Test PostgreSQL

The instance is launched with a **public IP** and PostgreSQL is accessible over mTLS on port 5432 at that address. The security group only allows the VPC CIDR by default, so `deploy.sh` prints an **ACTION REQUIRED** notice at the end with the security group ID and your detected public IP. Authorize your host before connecting:

```sh
# Find your public IP:
curl -s https://checkip.amazonaws.com

# Authorize it on the security group deploy.sh printed (also in artifacts/resources.json):
aws ec2 authorize-security-group-ingress \
  --group-id <SG_ID_FROM_OUTPUT> --protocol tcp --port 5432 \
  --cidr <YOUR_PUBLIC_IP>/32
```

Then retrieve the client certificate bundle from AWS Secrets Manager (the `SECRET_ARN` is stored in `artifacts/resources.json`) and connect with `psql` using the client certificates and the instance's **public IP**:

```sh
# Retrieve client certs from Secrets Manager
SECRET_ARN=$(jq -r '.SECRET_ARN' artifacts/resources.json)
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query 'SecretString' --output text)
echo "$SECRET_JSON" | jq -r '.ca_cert' | base64 -d > /tmp/ca.crt
echo "$SECRET_JSON" | jq -r '.client_cert' | base64 -d > /tmp/client.crt
echo "$SECRET_JSON" | jq -r '.client_key' | base64 -d > /tmp/client.key
chmod 600 /tmp/client.key

# Connect via mTLS (use the EC2 Public IP from the deploy.sh summary)
psql "sslmode=verify-ca sslcert=/tmp/client.crt sslkey=/tmp/client.key sslrootcert=/tmp/ca.crt host=<INSTANCE_PUBLIC_IP> port=5432 dbname=postgres user=postgres-client"
```

In debug mode (`--debug`), SSM Session Manager access with local peer authentication is also available. Connect via:

```sh
aws ssm start-session --region <region> --target <INSTANCE_ID>
```

### 4. Clean Up Resources

To remove all created resources, run:

```sh
./scripts/clean.sh
```

## Build Variants

The flake produces two image variants along the operator-access axis (debug vs
production). Secure boot is **not** a separate package — it is applied as a
post-build signing step (see below).

**Debug vs Production** controls operator access:

- Production builds have zero operator access — no console login, no SSH, no SSM agent, no root password. Security assertions are enforced. The only way to interact with the instance is via mTLS to PostgreSQL on port 5432.
- Debug builds enable console auto-login as root, SSM agent for remote shell access, and bypass security assertions. Use for development and troubleshooting only.

| Package | Operator Access | Baseline PCRs |
|---|---|---|
| `raw-image` | None | PCR4 |
| `raw-image-debug` | Console + SSM | PCR4 |

**Secure Boot** controls boot integrity verification and is applied as a
post-build step, not as a distinct image package:

- Without secure boot, the TPM measures the Unified Kernel Image (UKI) into PCR4. Builds are fully reproducible — same source produces identical images with identical PCR4 values.
- With secure boot, the unsigned UKI is signed with the `db` key by the `sign-efi-image` app (run outside the nix derivation, so `db.key` never enters the nix store); the signed UKI is patched into the ESP, the UEFI variable store is built from the PK/KEK/db ESLs, and PCR4 + PCR7 are computed against the signed image. This prevents unauthorized bootloaders from running.

`build.sh --secure-boot` generates an **ephemeral** local key hierarchy for a
one-off signed build; PCR7 changes on every run because the keys (and their
GUID) are freshly generated. For **reproducible** PCR7, add `--secrets-manager`:
the whole secure boot golden identity (fixed GUID + PK/KEK/db certs, plus the
private `db.key`) is persisted as a single JSON secret and reused across
deployments, so both PCR4 and PCR7 stay stable. `sign-efi-image` fetches
`db.key` from the secret in memory (`--identity-arn`), so the private key never
touches the local filesystem. Regenerating the identity is a deliberate PCR7
roll (the AWS revocation model). See the root
[Secure Boot Workflow](../../README.md#secure-boot-workflow) for the shared
build → sign → create-ami sequence.

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

## Production Considerations

This example is a demonstrator. A production deployment additionally requires:

- **Distinct principals per role, and a Custodian trusted for the bootstrap window.**
  The five-role split ([Roles & Responsibilities](#roles--responsibilities)) is
  implemented, but omitting the `*-role-arn` flags collapses every stage onto the
  caller — which then holds `kms:PutKeyPolicy` and `kms:Encrypt` together, the exact
  pair the split exists to break (`create-key.sh` warns when it does). Even with
  separate ARNs the Custodian holds `kms:PutKeyPolicy` for the whole bootstrap
  window, so it can self-escalate to `kms:CreateGrant` and plant a grant that is
  exempt from the PCR conditions and survives finalize. `02b`'s post-swap grant audit
  (see [Minimal IAM Privileges](#minimal-iam-privileges)) catches accidental grants,
  third-party principals and compromised tooling under an *honest* Custodian; no
  in-script check binds a principal who can edit or single-step the script. The
  window itself is unavoidable — PCR4 measures the pinned key ARN, so the key must
  exist before the image.
- **The symmetric key is generated in the provisioning pipeline, not inside the TEE.** This is a deliberate recoverability-vs-custody tradeoff — see [DEK custody: pipeline vs. TEE generation](#dek-custody-pipeline-vs-tee-generation) below.
- **Private (no public IP) deployment needs a KMS interface VPC endpoint.** This example launches with a public IP so mTLS is reachable and `kms-init` can reach the public KMS endpoint. A production instance in a private subnet has no route to public KMS (the default VPC has an Internet Gateway but no NAT), so `kms-init` fails at boot unless the subnet has a KMS interface VPC endpoint (PrivateLink) — or a NAT gateway — reachable from the instance.
- **Move CA issuance off the Provisioner's host.** mTLS auth is scoped so only a `CN=postgres-client` cert maps to the `postgres-client` role and the `postgres` superuser is rejected over TCP (`ALTER ROLE postgres NOLOGIN` makes that permanent) — this closes the network-superuser/shell path. But the **Provisioner** still generates the CA key locally (`05a_create_certificates.sh`), so it can mint a valid `postgres-client` cert and reach the data. mTLS here protects against superuser escalation, not against the Provisioner reading data — and the role split cannot fix it, because the CA key and the DEK are deliberately co-located in one stage. Longer term, move CA issuance off the provisioning host entirely (e.g. AWS Private CA with an enforced subject-name policy) so CA custody belongs to no provisioning role by construction.
- **Snapshot rollback is not prevented — dm-integrity authenticates each sector, not the volume's freshness.** The data volume is LUKS2 with `--integrity hmac-sha256`, authenticating each sector as `HMAC(key, data‖sector)` with no counter or hash tree, so any `(ciphertext, tag)` pair ever valid for a sector verifies forever. An operator with EBS snapshot access can snapshot the volume at two times, splice authentic old sectors (with their tags) into the newer image, and reboot: attestation, KMS release, LUKS unlock, and the per-page checksums all pass, and PostgreSQL serves a mixed-epoch state — e.g. a revoked credential restored to its former value. This is replay of *authentic* data, not chosen-plaintext forgery; confidentiality is unaffected and authenticated encryption alone cannot stop it. Closing it needs freshness the operator cannot snapshot-and-splice: archive WAL to an external TEE-authenticated sink and check LSN/timeline monotonicity at startup, or — coarser — seal a high-water-mark checkpoint LSN under the KMS/NitroTPM key and refuse to start if the on-disk volume is older.

### DEK custody: pipeline vs. TEE generation

The LUKS DEK (and the mTLS bundle password, the same key) is minted **in the pipeline**: the Provisioner generates the plaintext, wraps it with `kms:Encrypt`, and ships the ciphertext in user data. The alternative is minting it **inside the TEE** on first boot — `luks-init` generates the key in tmpfs, `luksFormat`s, wraps it over the attested path, and stores the ciphertext as a LUKS2 token in the volume header.

| | Pipeline (current) | TEE first-boot |
|---|---|---|
| **Custody** | Provisioner sees the plaintext; can `luksOpen` on any machine | Plaintext never leaves the enclave; every unlock goes through attestation |
| **Recovery** | Out-of-band with the held plaintext | Relaunch the *same measured AMI* (PCR4/PCR7 must match) + attach the volume |
| **Durability** | Ciphertext lives in the launch template | Only copy is the volume header → needs an off-volume `luksHeaderBackup` |
| **Boot logic** | `kms-init` decrypts a user-data blob | Extra first-boot generate/format/wrap (idempotent via the header check) |

The TEE model shifts the discipline from "guard the plaintext key file" to "guard the KMS key and the AMI": never `ScheduleKeyDeletion` while data is needed, retain the exact AMI + secure-boot identity, keep a `luksHeaderBackup` (it is ciphertext — useless without KMS and a matching-PCR attestation).

Adopting it touches four places: `luks-init.nix` gains first-boot keygen/wrap and later-boot unwrap; `03_create_symmetric_key.sh` drops keygen; the KMS policy grants PCR-gated `kms:Encrypt` to the **instance role** rather than the Provisioner (so Encrypt can only be pinned to the attested role, not revoked outright); `05a_create_certificates.sh` wraps the server bundle the same way. A lighter interim step — a mandatory first-boot re-key (`luksAddKey` a TEE key, `luksKillSlot` the provisioned slot) — shrinks but does not remove custody, since the plaintext still existed on the Provisioner's host at provisioning. Adopting the TEE model would also delete the Provisioner's DEK duty outright, shrinking the five-role split by one custody point.

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

Like the full ceremony, the E2E test launches the instance with a **public IP** so it can validate mTLS from a host outside the VPC — e.g. a laptop or a remote dev box.

> **Prerequisite — allowlist your host on the security group.** The instance's security group only permits inbound 5432 from the VPC CIDR, so your host's public IP must be added before the mTLS checks can connect. The script prints an **ACTION REQUIRED** notice with the security group ID and your detected public IP, then (when run interactively) pauses so you can add the rule:
>
> ```sh
> # Find your public IP:
> curl -s https://checkip.amazonaws.com
>
> # Authorize it on the security group the script printed:
> aws ec2 authorize-security-group-ingress \
>   --group-id <SG_ID_FROM_OUTPUT> --protocol tcp --port 5432 \
>   --cidr <YOUR_PUBLIC_IP>/32
> ```
>
> The script never modifies the security group for host access itself. In non-interactive/CI runs (no TTY) it does not pause — pre-authorize the source range beforehand.

By default, the E2E test runs the **simplest path** (unsigned image, PCR4-only KMS policy) so developers can iterate quickly with minimal prerequisites. For the full production-representative integration, pass `--secure-boot --secrets-manager`:

```sh
# Full integration: secure boot + Secrets Manager golden identity (recommended for CI)
./scripts/e2e-test.sh --secure-boot --secrets-manager
```

Flags:

- `--secure-boot` — sign the UKI for secure boot (ephemeral local keys; PCR7 changes each run)
- `--secure-boot --secrets-manager [ARN]` — sign against a reproducible golden identity in Secrets Manager. With no ARN, the test generates and uploads a fresh identity and deletes it on teardown; with an ARN, it reuses that identity and leaves it in place. Requires `--secure-boot`.
- `--debug` — adds SSM-based checks alongside mTLS
- `--timeout` — validation timeout in seconds (default: 600)
- `--no-cleanup` — skip resource teardown on failure for debugging
- `--admin-role-arn <ARN>` — *(deprecated; use `--custodian-role-arn`)* aliases to the Custodian role: the principal that creates the key, installs the final policy, and audits grants
- `--vpc-id <ID>` — launch into a specific VPC (default VPC otherwise)
- `--start-phase <1|2|3>` — resume a prior `--no-cleanup` run at a later phase (2 = first-boot validation, 3 = persistence). Provisioning is skipped and resource IDs are read from `artifacts/resources.json` (the instance's public IP is re-derived from the recorded `INSTANCE_ID`, and the SG-authorization notice is re-printed). Requires that a previous run left `resources.json` in place. Pair with `--no-cleanup` to keep iterating.

Example — a full run failed at Phase 2 and left resources up; retry just the validation without re-provisioning:

```sh
./scripts/e2e-test.sh --no-cleanup            # full run; leaves resources on failure
./scripts/e2e-test.sh --start-phase 2 --no-cleanup   # re-run validation against the same instance
```

## Troubleshooting

For step-by-step debugging of the boot chain, LUKS, cert-init, and PostgreSQL setup via SSM, see [TROUBLESHOOT.md](./TROUBLESHOOT.md).
