#!/bin/bash
#
# IAM policy documents for the five provisioning roles. Source of truth for the per-role split.
# Operator IAM: CreateRole+PassRole+RunInstances is an escalation chain; pinning role alone
# still lets
# AttachRolePolicy install AdministratorAccess. Attach/Detach need a separate statement because
# the other actions don't populate iam:PolicyARN (shared condition would deny them).

build_operator_policy() {
  local acct="$1" role_name="$2" profile_name="$3"
  cat <<EOF
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
        "ec2:DescribeSubnets",
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
      "Sid": "TeardownImageAndSnapshots",
      "Effect": "Allow",
      "Action": [
        "ec2:DeregisterImage",
        "ec2:DescribeSnapshots",
        "ec2:DeleteSnapshot"
      ],
      "Resource": "*"
    },
    {
      "Sid": "InstanceRoleLifecycleScopedToTheWorkloadRoleOnly",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:DeleteRolePolicy"
      ],
      "Resource": "arn:aws:iam::${acct}:role/${role_name}"
    },
    {
      "Sid": "AttachOnlyTheSsmManagedPolicyToTheWorkloadRole",
      "Effect": "Allow",
      "Action": [
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "arn:aws:iam::${acct}:role/${role_name}",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyARN": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        }
      }
    },
    {
      "Sid": "InstanceProfileLifecycleScoped",
      "Effect": "Allow",
      "Action": [
        "iam:CreateInstanceProfile",
        "iam:DeleteInstanceProfile",
        "iam:GetInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:RemoveRoleFromInstanceProfile"
      ],
      "Resource": "arn:aws:iam::${acct}:instance-profile/${profile_name}"
    },
    {
      "Sid": "TeardownSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DeleteSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:${acct}:secret:postgres-kms/client-cert-*",
        "arn:aws:secretsmanager:*:${acct}:secret:nitrotpm-sb-identity-*"
      ]
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
EOF
}

# KMS actions can't be resource-scoped here: key ARN doesn't exist at role-creation time. Key
# policy is the binding control.
build_custodian_policy() {
  cat <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KeyLifecycleAndPolicyControl",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:ListGrants",
        "kms:RevokeGrant",
        "kms:GetKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ResolveAssumedRoleSessionToRoleArn",
      "Effect": "Allow",
      "Action": [
        "iam:GetRole"
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
EOF
}

# Scoped to nitrotpm-sb-identity-* only (SM appends a suffix, hence *); Deployer can't read
# client mTLS bundle. Args: <account_id>.
build_deployer_policy() {
  local acct="$1"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AMIRegistration",
      "Effect": "Allow",
      "Action": [
        "ec2:RegisterImage",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SnapshotColdsnap",
      "Effect": "Allow",
      "Action": [
        "ebs:StartSnapshot",
        "ebs:PutSnapshotBlock",
        "ebs:CompleteSnapshot",
        "ec2:DescribeSnapshots",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SigningIdentityCustody",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutResourcePolicy",
        "secretsmanager:GetResourcePolicy"
      ],
      "Resource": "arn:aws:secretsmanager:*:${acct}:secret:nitrotpm-sb-identity-*"
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
EOF
}

# CreateSecret is scoped to postgres-kms/client-cert-* so this role cannot create secrets in
# another namespace — notably not one that shadows the signing identity.
# kms:Encrypt stays on "*" for the same reason ec2:RunInstances is unpinned: the key is a stage-2
# output and does not exist when these roles are created in stage 0. The bootstrap key policy is
# what actually admits this role to the ceremony key. Args: <account_id>.
build_provisioner_policy() {
  local acct="$1"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WrapTheDekDuringTheBootstrapWindow",
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt"
      ],
      "Resource": "*"
    },
    {
      "Sid": "UploadTheClientCertificateBundle",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:${acct}:secret:postgres-kms/client-cert-*"
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
EOF
}

# Scoped to postgres-kms/client-cert-* so this role can't read the signing identity
# (nitrotpm-sb-identity-*). Args: <account_id>.
build_test_client_policy() {
  local acct="$1"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadTheClientCertificateBundleOnly",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:${acct}:secret:postgres-kms/client-cert-*"
    }
  ]
}
EOF
}
