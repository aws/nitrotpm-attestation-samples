#!/bin/bash
set -euo pipefail

usage() {
  echo "Usage: $0 -z AVAILABILITY_ZONE | --availability-zone AVAILABILITY_ZONE [-s SIZE | --size SIZE]"
  echo "  -z, --availability-zone  Specify the availability zone (required)"
  echo "  -s, --size               Specify the volume size in GiB (default: 10)"
  exit 1
}

SIZE=10

while [[ "$#" -gt 0 ]]; do
  case $1 in
    -z|--availability-zone) AVAILABILITY_ZONE="$2"; shift ;;
    -s|--size) SIZE="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ -z "${AVAILABILITY_ZONE:-}" ]; then
  echo "Error: Availability zone is required."
  usage
fi

echo "Creating blank EBS volume (${SIZE} GiB) in ${AVAILABILITY_ZONE}..."

VOLUME_ID=$(aws ec2 create-volume \
  --availability-zone "$AVAILABILITY_ZONE" \
  --size "$SIZE" \
  --volume-type gp3 \
  --query 'VolumeId' \
  --output text)

if [ -z "$VOLUME_ID" ]; then
  echo "Error: Failed to create EBS volume"
  exit 1
fi

aws ec2 create-tags \
  --resources "$VOLUME_ID" \
  --tags Key=Name,Value=PostgresKMS-DataVolume

echo "EBS volume tagged as PostgresKMS-DataVolume."

echo "Waiting for volume to become available..."
aws ec2 wait volume-available --volume-ids "$VOLUME_ID"

echo "Volume ID: $VOLUME_ID"
