{ pkgs, lib, stdenv, system }:

let
  nixArch = builtins.head (builtins.split "-" system);
  arch = if nixArch == "aarch64" then "arm64" else nixArch;

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    boto3
    botocore
  ]);

  # Coldsnap for creating EBS snapshots from raw images
  coldsnap = pkgs.fetchFromGitHub {
    owner = "awslabs";
    repo = "coldsnap";
    rev = "v0.9.0";
    sha256 = "sha256-8+YPKjHi3VURzSOflIa0x4uBkoDMYGFJiFcNJ+8NJ7Q=";
  };

  coldsnapBinary = pkgs.rustPlatform.buildRustPackage {
    pname = "coldsnap";
    version = "0.9.0";
    src = coldsnap;
    cargoHash = "sha256-4w79zZcgIulLIArY2ErOHwaWA8g/mA2cSKCzJx4X9vM=";
    nativeBuildInputs = with pkgs; [ pkg-config ];
    buildInputs = with pkgs; [ openssl ];
  };

  script = pkgs.writeShellApplication {
    name = "create-ami";
    runtimeInputs = with pkgs; [
      awscli2
      coldsnapBinary
    ];

    text = ''
      # Propagate AWS credentials
      export AWS_ACCESS_KEY_ID=''${AWS_ACCESS_KEY_ID:-}
      export AWS_SECRET_ACCESS_KEY=''${AWS_SECRET_ACCESS_KEY:-}
      export AWS_SESSION_TOKEN=''${AWS_SESSION_TOKEN:-}
      export AWS_DEFAULT_REGION=''${AWS_DEFAULT_REGION:-}

      # Check if raw image file is provided
      if [ -z "$1" ]; then
        echo "Error: Raw image file not provided"
        echo "Usage: create-ami <raw-image-file> [uefi-data-file]"
        exit 1
      fi

      # Check if the image file exists
      if [ ! -f "$1" ]; then
        echo "Error: Raw image file '$1' not found"
        exit 1
      fi

      echo "Creating EBS snapshot using coldsnap..."

      # Use coldsnap to upload the raw image and create a snapshot
      SNAPSHOT_ID=$(coldsnap upload "$1" --wait | grep -o 'snap-[a-f0-9]*')

      if [ -z "$SNAPSHOT_ID" ]; then
        echo "Error: Failed to create snapshot with coldsnap"
        exit 1
      fi

      echo "Snapshot created: $SNAPSHOT_ID"
      echo "Waiting for snapshot to complete..."

      aws ec2 wait snapshot-completed \
        --snapshot-ids "$SNAPSHOT_ID"

      echo "Done. Creating an AMI..."

      # Prepare register-image command
      REGISTER_CMD="aws ec2 register-image \
        --name \"''${SNAPSHOT_ID}-tpm\" \
        --boot-mode uefi \
        --architecture \"${arch}\" \
        --virtualization-type hvm \
        --root-device-name /dev/xvda \
        --block-device-mappings DeviceName=/dev/xvda,Ebs=\{SnapshotId=\"''${SNAPSHOT_ID}\"\} \
        --ena-support \
        --tpm-support v2.0"

      # Add UEFI data if provided
      if [ $# -gt 1 ] && [ -n "$2" ]; then
        if [ ! -f "$2" ]; then
          echo "Error: UEFI data file '$2' not found"
          exit 1
        fi
        REGISTER_CMD="$REGISTER_CMD --uefi-data $(cat "$2")"
      fi

      REGISTER_CMD="$REGISTER_CMD --output text"

      # Execute the register-image command
      AMI_ID=$(eval "$REGISTER_CMD")

      echo "Done. AMI ID = ''${AMI_ID}"
    '';
  };
in
{
  type = "app";
  program = "${script}/bin/create-ami";
}
