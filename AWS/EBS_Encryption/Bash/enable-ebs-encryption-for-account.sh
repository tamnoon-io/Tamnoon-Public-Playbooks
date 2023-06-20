#!/bin/bash
set -Eeuox pipefail
key_id=$1
profile=${2:-empty}
echo ${profile}
if [ "$profile" == "empty" ]; then
  echo "No AWS profile sent to the script, using the default one"
    aws ec2 enable-ebs-encryption-by-default

    aws ec2 get-ebs-default-kms-key-id

    EBS_CMK_ARN=$(aws kms describe-key --key-id $key_id |jq --raw-output '.KeyMetadata.Arn')

    aws ec2 modify-ebs-default-kms-key-id --kms-key-id "$EBS_CMK_ARN"

    aws ec2 get-ebs-default-kms-key-id
else
    echo "goiung to use AWS profile - ${profile}"
    aws ec2 enable-ebs-encryption-by-default --profile ${profile}

    aws ec2 get-ebs-default-kms-key-id --profile ${profile}

    EBS_CMK_ARN=$(aws kms describe-key --key-id $key_id --profile ${profile}|jq --raw-output '.KeyMetadata.Arn')

    aws ec2 modify-ebs-default-kms-key-id --kms-key-id "$EBS_CMK_ARN" --profile ${profile}

    aws ec2 get-ebs-default-kms-key-id --profile ${profile}
fi