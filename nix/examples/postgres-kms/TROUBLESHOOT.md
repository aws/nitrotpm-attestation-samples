# Troubleshooting Guide

This guide walks through debugging the boot chain and PostgreSQL setup via SSM Session Manager.

## Prerequisites

- Instance launched with `--debug` flag (SSM agent enabled)
- SSM session: `aws ssm start-session --region <region> --target <INSTANCE_ID>`

## Boot chain

```
network-online → kms-init → {luks-unlock, cert-init} → data.mount → postgresql
```

## Step 0: Find the unit that actually failed

`data.mount` and `postgresql.service` have no independent failure mode: if something
upstream fails they can only ever report `result 'dependency'`, with no detail. Start
by finding the real failure rather than reading their status:

```sh
systemctl --failed
systemctl list-dependencies --all data.mount
```

A useful shortcut: if `cert-init` succeeded, then `kms-init` succeeded too (cert-init
requires it *and* uses the decrypted symmetric key), so attestation, TPM, IMDS, the
KMS decrypt and the key itself are all fine. In that case the fault is isolated to
`luks-unlock`.

Two things `systemctl --failed` will mislead you about:

- **`systemd-boot-random-seed.service` failing is expected.** It writes a random seed
  into the ESP, which is part of the measured, verity-protected disk image. The write
  cannot succeed, and should not: mutating the ESP would defeat the build's PCR4
  reproducibility. It has no bearing on the boot chain above.
- **A unit absent from `--failed` may still be the problem.** A job that was cancelled
  by a timeout, or discarded because a dependency failed, leaves the unit `inactive
  (dead)` rather than `failed`. `luks-unlock` can even read `active (exited)` while
  `/data` is unmounted -- see Step 3.

## Step 1: Check kms-init (symmetric key decryption)

```sh
systemctl status kms-init
journalctl -u kms-init --no-pager
```

Verify the key file exists and has content:

```sh
ls -la /run/kms-init/symmetric_key
wc -c /run/kms-init/symmetric_key
```

If kms-init failed, check IMDS reachability and TPM:

```sh
iptables -L OUTPUT -n -v | grep 169.254
ls -la /dev/tpm0
```

### The KMS key ARN is pinned into the image

Before decrypting anything, `kms-init` compares the `key_id` in user data against
the key ARN baked into the image at build time. **A rejection here is the check
working.** User data is not measured into any PCR, so it cannot be trusted to
name the key — see [KMS key pinning](./README.md#kms-key-pinning).

| Journal message | Meaning |
|---|---|
| `built without a pinned KMS key ARN` | The image was built from a checkout whose `kms-key-arn.txt` was empty. That builds on purpose (fresh clone, CI) but cannot boot. Rebuild after `02a_create_kms_key.sh` has written the ARN. |
| `user-data key_id '…' does not match the pinned key …` | Different key, region or account than the image is bound to. Either the wrong AMI was launched for this key, or the key was substituted. |
| `user-data key_id '…' is not a full ARN` | `user_data.json` carries a bare key id. The comparison is exact and a bare id names neither account nor region. Regenerate user data with `03_create_symmetric_key.sh`, which now rejects a non-ARN up front. |
| `user-data carries no key_id` | `user_data.json` is missing the field entirely. |
| `FATAL: refusing to decrypt against an unpinned or substituted KMS key` | The wrapper line that follows any of the above. |

The pinned value and the supplied one are both visible on the instance:

```sh
# What the image is bound to (derive it from the unit, not from a store glob):
KMS_INIT=$(systemctl cat kms-init | awk -F= '/^ExecStart=/{print $2; exit}')
grep -m1 '^PINNED_KMS_KEY_ARN=' "$KMS_INIT"

# What user data asked for:
jq -r '.key_id' /run/kms-init/user_data.json
```

This cannot be fixed on the instance: the pinned ARN lives in the measured image,
so changing it means a rebuild, a new PCR4 and a new KMS key policy.

## Step 2: Check the EBS volume and its LUKS2 format

```sh
lsblk
```

The data volume surfaces as NVMe on Nitro (typically `/dev/nvme1n1`); luks-init
resolves it, falling back to `/dev/xvdf` on non-NVMe instances. A successful unlock
shows a `data` crypt device mounted at `/data`.

`cryptsetup` and `jq` are not on the interactive `PATH` (the service calls them by
absolute store path). The volume is also pinned to one exact format: **LUKS2,
`aes-xts-plain64`, 512-bit encryption key, `hmac(sha256)` data authentication,
4096-byte sectors.**

Derive everything -- binaries *and* pinned constants -- from the `luks-init.sh` that
`luks-unlock` actually runs. Reuse these in every step below:

```sh
LUKS_INIT=$(systemctl cat luks-unlock | awk -F= '/^ExecStart=/{print $2; exit}')

eval "$(grep -E '^(CRYPTSETUP|LUKS_JQ)=' "$LUKS_INIT")"
. "$(grep -o '/nix/store/[a-z0-9]*-luks-verify.sh' "$LUKS_INIT")"

MKFS=$(grep -o '/nix/store/[a-z0-9]*-e2fsprogs-[^/]*/bin/mkfs.ext4' "$LUKS_INIT")
DUMPE2FS="${MKFS%/mkfs.ext4}/dumpe2fs"
DATA_DEV=$([ -e /dev/nvme1n1 ] && echo /dev/nvme1n1 || echo /dev/xvdf)
```

Confirm you loaded the constants the running image enforces. The total must be **768**
(512 encryption + 256 integrity):

```sh
echo "$LUKS_EXPECTED_CIPHER / $LUKS_EXPECTED_INTEGRITY / $LUKS_EXPECTED_SECTOR_SIZE"
echo "total keysize: $((LUKS_EXPECTED_KEYSIZE + LUKS_EXPECTED_INTEGRITY_KEYSIZE))"
```

> **Do not resolve these with a bare glob** such as
> `ls /nix/store/*-luks-verify.sh | head -1` or
> `ls /nix/store/*-cryptsetup-*/bin/cryptsetup | head -1`. A host that has built the
> image more than once has several versions in the store, and `head -1` picks an
> arbitrary one. Sourcing a stale `luks-verify.sh` is especially misleading: an older
> copy has no `LUKS_EXPECTED_INTEGRITY_KEYSIZE`, so the total above silently computes
> as 512 and every manual check disagrees with the service for no visible reason.

Note `--type luks2`: a bare `isLuks` also succeeds on a LUKS1 header, which the
service correctly refuses.

```sh
"$CRYPTSETUP" isLuks --type luks2 "$DATA_DEV" && echo "LUKS2" || echo "not LUKS2 (raw or LUKS1)"
```

If it is LUKS2, inspect the segment. This needs no key:

```sh
"$CRYPTSETUP" luksDump --dump-json-metadata "$DATA_DEV" | "$LUKS_JQ" '.segments["0"]'
```

Expect `encryption: "aes-xts-plain64"`, `sector_size: 4096`, and an `integrity`
object with `type: "hmac(sha256)"`. **A missing `integrity` key means the volume was
formatted by an older image** (before authenticated encryption) or was tampered
with -- either way the service will refuse it on every boot, and it cannot be
migrated in place. Use a fresh EBS volume.

## Step 3: Check luks-unlock

```sh
journalctl -u luks-unlock --no-pager
```

This is where the pinned format is enforced. The volume is encrypted *and*
authenticated, and the header is verified before `luksOpen` while the resulting
mapping is verified after -- because `luksOpen` succeeding proves only that the key
was correct, not how dm-crypt will interpret the data.

**A rejection here is the check working, not a bug.** Do not reformat to make it go
away unless the volume is genuinely disposable.

| Journal message | Meaning |
|---|---|
| `header does not match the pinned format` | Pre-open check failed: wrong cipher, wrong `sector_size`, `integrity` absent, more than one segment, or a non-`crypt` segment. Old-format volume, or a tampered header. |
| `refusing to open ...: header was tampered with` | Wrapper for the above. |
| `active cipher '...' != aes-xts-plain64` | dm-crypt instantiated a different cipher than the header claimed. This is the signature of a `cipher_null` header downgrade. |
| `data authentication is not active on the mapping` | The mapping has no integrity layer. |
| `active keysize '...' != 768 bits` | Wrong combined volume key. Note 768 = 512 encryption + 256 integrity; seeing `512` means the integrity key is absent. |
| `cannot read LUKS2 JSON metadata` | `luksDump` failed -- unreadable or destroyed header. |
| `No data device found ... after 120s` | Volume never attached; check `lsblk` and the EC2 attachment. |

### First boot is slow, not hung

On a raw volume `luksFormat --integrity` initialises the authentication tags before
`mkfs` can run. That writes the tag and journal area rather than the whole device
(about 230 MB for a 10 GiB volume), but it still takes roughly 90 seconds on gp3 and
scales with volume size. `luks-unlock` has `TimeoutStartSec=1800s` for this reason --
a unit sitting in `activating` for a minute or two on first boot is expected.

`/dev/mapper/data` does not exist until that finishes, and `data.mount` gets an
implicit `Requires=` on `dev-mapper-data.device` from its `What=`. A device unit's
`JobRunningTimeoutSec` defaults to `DefaultDeviceTimeoutSec` (90s) and
`systemd.unit(5)` documents it as *independent* of `TimeoutStartSec` on the service,
so the image ships a drop-in raising it to 1800s for this device. If you see

```
dev-mapper-data.device: Job dev-mapper-data.device/start timed out.
Timed out waiting for device /dev/mapper/data.
```

then that drop-in is missing or too small. Note the consequence: once the device job
times out, `data.mount`'s job is **discarded**, and systemd does not re-queue it when
`luks-unlock` later succeeds. `luks-unlock` then shows `active (exited)` while `/data`
stays unmounted and `postgresql` stays dead, with both still showing the original
`Dependency failed` message. Recover with:

```sh
systemctl start data.mount
systemctl start postgresql
```

### Reproducing the checks by hand

Non-destructive. `KEY` comes from kms-init; the constants were loaded in Step 2:

```sh
KEY=$(cat /run/kms-init/symmetric_key)

# Header check (no key needed, no side effects):
luks_verify_header_json "$("$CRYPTSETUP" luksDump --dump-json-metadata "$DATA_DEV")" \
  && echo "header OK"

# Open exactly as the service does, then check the live mapping:
echo "$KEY" | "$CRYPTSETUP" luksOpen --type luks2 "$DATA_DEV" data --key-file=-
luks_verify_status "$("$CRYPTSETUP" status data)" && echo "mapping OK"
```

Both functions print the specific reason to stderr on rejection.

> **WARNING: `luksFormat` DESTROYS ALL DATA on the volume.** Run it only on a volume
> that is genuinely raw (Step 2 reported "not LUKS2") or that you are willing to lose.
>
> It **must** carry the pinned parameters. A plain `luksFormat` produces a volume with
> no data authentication, which this image then rejects on every subsequent boot --
> after having destroyed the data. And `mkfs.ext4` must not be skipped, or `data.mount`
> fails on a missing filesystem.

```sh
echo "$KEY" | "$CRYPTSETUP" luksFormat --type luks2 \
  --cipher "$LUKS_EXPECTED_CIPHER" \
  --key-size "$LUKS_EXPECTED_KEYSIZE" \
  --integrity "$LUKS_EXPECTED_INTEGRITY_ARG" \
  --sector-size "$LUKS_EXPECTED_SECTOR_SIZE" \
  --batch-mode "$DATA_DEV" --key-file=-
echo "$KEY" | "$CRYPTSETUP" luksOpen --type luks2 "$DATA_DEV" data --key-file=-
"$MKFS" /dev/mapper/data
```

### Exit code 4 from cryptsetup

Means wrong key or wrong device. Note that if `cert-init` succeeded, the key is
provably correct (see Step 0), so look at the device instead. Otherwise:

- Volume was formatted with a different symmetric key (reused EBS from a previous deployment)
- The symmetric key has trailing whitespace or newline issues
- Volume isn't attached (neither `/dev/xvdf` nor `/dev/nvme1n1` present)

```sh
cat /run/kms-init/symmetric_key | xxd | head -5
```

## How failures are handled

Knowing what the script cleans up tells you what a given state means.

**On a rejected existing volume, the mapping is closed and the header is left
alone.** So `/dev/mapper/data` being absent after a failure is expected, not a second
problem. The header is deliberately preserved: the volume may hold real data, and a
rejection here may be evidence of tampering worth investigating rather than erasing.

**On a failed first-boot initialisation, the header is rolled back.** Formatting and
`mkfs` are not atomic, and a volume left with a valid LUKS2 header but no filesystem
would be stranded forever, because later boots see the header, take the
existing-volume path, and never `mkfs`. So any failure after `luksFormat` zeroes the
LUKS2 metadata region (primary header, secondary header, keyslots area -- 16 MiB) and
logs `Rolling back partial initialisation`. The next boot sees a raw volume and
retries cleanly. This only runs in the first-boot branch, where by definition there
was no pre-existing data.

If you interrupted the service yourself, or are on an image predating this behaviour,
check for the stranded state directly:

```sh
"$DUMPE2FS" -h /dev/mapper/data >/dev/null 2>&1 && echo "ext4 present" || echo "NO FILESYSTEM"
```

`NO FILESYSTEM` on a verified mapping means exactly that case. Either run
`"$MKFS" /dev/mapper/data` once, or clear the header so first-boot init retries:

```sh
"$CRYPTSETUP" close data
dd if=/dev/zero of="$DATA_DEV" bs=1M count=16 conv=fsync
systemctl restart luks-unlock
```

## Step 4: Check data.mount

Only meaningful once `luks-unlock` has succeeded. If it has not, this reports
`Dependency failed for /data` and nothing more -- go back to Step 3.

```sh
systemctl status data.mount
ls -la /dev/mapper/data
mount | grep /data
```

`/data` is mounted `nodev,nosuid,noexec` because its contents are operator-supplied
and must never be executable. `mount | grep /data` should show those options.

## Step 5: Check cert-init (mTLS certificates)

```sh
systemctl status cert-init
journalctl -u cert-init --no-pager
```

Verify cert files:

```sh
ls -la /run/postgresql-certs/
# Expect: ca.crt (0640), server.crt (0640), server.key (0600)
# All owned by postgresql:postgresql

openssl x509 -in /run/postgresql-certs/server.crt -noout -subject -dates
openssl x509 -in /run/postgresql-certs/ca.crt -noout -subject -dates
```

## Step 6: Check PostgreSQL

Only starts if both `data.mount` and `cert-init` succeeded:

```sh
systemctl status postgresql
journalctl -u postgresql --no-pager
```

Verify config:

```sh
sudo -u postgres psql -c "SHOW ssl;"
sudo -u postgres psql -c "SHOW ssl_cert_file;"
sudo -u postgres psql -c "SHOW ssl_ca_file;"
sudo -u postgres psql -c "SELECT type, database, user_name, address, auth_method FROM pg_hba_file_rules;"
sudo -u postgres psql -c "\du postgres-client"
```

Test local connectivity:

```sh
sudo -u postgres psql -c "SELECT 1;"
```

## Step 7: Check active SSL connections

From another terminal after connecting via mTLS:

```sh
sudo -u postgres psql -c "SELECT pid, ssl, client_addr, ssl_version, ssl_cipher FROM pg_stat_ssl JOIN pg_stat_activity USING (pid);"
```

## Step 8: Check firewall rules

```sh
iptables -L -n -v          # inbound
iptables -L OUTPUT -n -v   # outbound IMDS rules
```

## Step 9: Restart the service chain

If you fixed an issue and need to retry. The service closes its own mapping on
failure, but close any mapping you opened by hand first, or `luks-unlock` fails
immediately with "Device data already exists":

```sh
"$CRYPTSETUP" close data 2>/dev/null

systemctl restart kms-init
# Wait a moment, then:
systemctl restart luks-unlock
systemctl restart cert-init
# data.mount and postgresql should follow automatically
```

Or restart individual services:

```sh
systemctl restart luks-unlock
systemctl restart postgresql
```

Note that a rejected volume cannot be fixed on the instance: the pinned format lives
in the measured image, so changing it means a rebuild, a new PCR4, and a new KMS key
policy.
