# Troubleshooting Guide

This guide walks through debugging the boot chain and PostgreSQL setup via SSM Session Manager.

## Prerequisites

- Instance launched with `--debug` flag (SSM agent enabled)
- SSM session: `aws ssm start-session --target <INSTANCE_ID>`

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

## Step 2: Check the EBS volume

```sh
lsblk
```

The data volume surfaces as NVMe on Nitro (typically `/dev/nvme1n1`); luks-init
resolves it, falling back to `/dev/xvdf` on non-NVMe instances. A successful unlock
shows a `data` crypt device mounted at `/data`.

`cryptsetup` is not on the interactive `PATH` (the service calls it by absolute
store path). Resolve the store binary and the device first -- reuse `$CRYPTSETUP`
and `$DATA_DEV` in the steps below:

```sh
CRYPTSETUP=$(ls /nix/store/*-cryptsetup-*/bin/cryptsetup | head -1)
DATA_DEV=$([ -e /dev/nvme1n1 ] && echo /dev/nvme1n1 || echo /dev/xvdf)
```

Check if the volume is already LUKS-formatted from a previous run (a non-zero
`isLuks` exit means "not LUKS", i.e. raw/unformatted):

```sh
"$CRYPTSETUP" isLuks "$DATA_DEV" && echo "LUKS formatted" || echo "Raw/unformatted"
```

## Step 3: Check luks-unlock

```sh
journalctl -u luks-unlock --no-pager
```

Run these manual commands **only if `luks-unlock` failed** (no `data` crypt device,
`/data` not mounted). If `lsblk` already shows `data` mapped and mounted at `/data`,
the unlock succeeded -- skip this step. Both commands below fail on an already-open
volume ("Device data already exists" / "Device in use").

> **WARNING: `luksFormat` DESTROYS ALL DATA on the volume** -- it writes a new LUKS header
> and the old data becomes unrecoverable. Run it only on a first-boot volume that
> is genuinely raw (Step 2 reported "Raw/unformatted"). Never run it to "fix" an
> unlock failure on a volume that holds data.

Exit code 4 from cryptsetup means wrong key or wrong device. Diagnose without
destroying anything by trying to open first:

```sh
KEY=$(cat /run/kms-init/symmetric_key)
# $CRYPTSETUP and $DATA_DEV resolved in Step 2

# Non-destructive: attempt to open a LUKS-formatted volume (subsequent boot):
echo "$KEY" | "$CRYPTSETUP" luksOpen "$DATA_DEV" data --key-file=- --verbose

# DESTRUCTIVE -- first boot on a raw volume ONLY (wipes the volume):
echo "$KEY" | "$CRYPTSETUP" luksFormat "$DATA_DEV" --key-file=- --verbose
```

Common causes for exit code 4:
- Volume was formatted with a different symmetric key (reused EBS from a previous deployment)
- The symmetric key has trailing whitespace or newline issues
- Volume isn't attached (neither `/dev/xvdf` nor `/dev/nvme1n1` present)

Check for key encoding issues:

```sh
cat /run/kms-init/symmetric_key | xxd | head -5
```

## Step 4: Check data.mount

Only relevant if luks-unlock succeeded:

```sh
systemctl status data.mount
ls -la /dev/mapper/data
mount | grep /data
```

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

If you fixed an issue and need to retry:

```sh
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
