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

Expect to see `xvdf` listed. Then check if it's already LUKS-formatted from a previous run:

```sh
cryptsetup isLuks /dev/xvdf && echo "LUKS formatted" || echo "Raw/unformatted"
```

## Step 3: Check luks-unlock

```sh
journalctl -u luks-unlock --no-pager
```

Exit code 4 from cryptsetup means wrong key or wrong device. Try manually:

```sh
KEY=$(cat /run/kms-init/symmetric_key)

# If volume is LUKS-formatted (subsequent boot), try opening:
echo "$KEY" | cryptsetup luksOpen /dev/xvdf data --key-file=- --verbose

# If volume is raw (first boot), try formatting:
echo "$KEY" | cryptsetup luksFormat /dev/xvdf --key-file=- --verbose
```

Common causes for exit code 4:
- Volume was formatted with a different symmetric key (reused EBS from a previous deployment)
- The symmetric key has trailing whitespace or newline issues
- Volume isn't attached at `/dev/xvdf`

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
