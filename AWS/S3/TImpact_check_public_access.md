
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Impact Playbook: S3 - Check Public Access Configuration.

## Description
This playbook describes how to execute Tamnoon S3 automation to find which s3 buckets have public access.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

This automation investigates policies and ACLs of S3 buckets that can allow public access to the buckets. 
- Buckets are considered public if they have some policy that allows action `s3:ListBucket` or `s3:*` to Principal `*` and having resource as the bucketName. For more details on policies, follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html).  
Similarly, if buckets have similar policy but only with effect `Deny`, then irrespective of other policies, it will be denied access by public.
- It is possible for buckets to be public if they have some ACLs that allows for `READ` or `FULL_CONTROL` permission given to Everyone (`https://acs.amazonaws.com/groups/global/AllUsers`). For more details on ACLs, follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acls.html).  
- Buckets that are public can be blocked for public access by Bucket Level Block Public Access and Account Level Block Public Access. 
    - Block Public Access (BPA) is made of four values, out of which, two values are used for blocking public access of s3 buckets:
        - IgnorePublicAcls - ignores all the ACLs that are defined on the bucket and blocks the public access to the bucket, if it has been allowed via ACLs.
        - RestrictPublicBuckets - ignores all policies that are defined on the bucket and blocks the public access to the bucket, if it has been allowed via policies. It additionally reduces the previous public access - that is if any account could access this bucket previously, it will now allow to the accounts only from same organization as that of bucket owner.   
    Bucket level BPA will take precedence for Account level first, then Bucket level.
- For more details of BlockPublicAccess follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).  

## Prerequisites 
1. AWS credentials defined with following permissions.

    | Permission                     | Required for Operation                        |
    |--------------------------------|-----------------------------------------------|
    | s3:GetBucketPolicy             | GET bucket policy                             |
    | s3:GetBucketAcl                | GET bucket ACL                                |
    | s3:GetBucketPolicyStatus       | GET bucket policy status                      |
    | s3:GetBucketPublicAccessBlock  | GET bucket Block Public Access settings       |
    | s3:GetAccountPublicAccessBlock | GET account Block Public Access settings      |

2. Python v3.9  and above + boto3 package installed ( pip install boto3)

## Impact Investigation steps:
1. Clone the AWS folder from  [Tamnoon-Public-Playbooks](https://github.com/tamnoon-io/Tamnoon-Service)
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      git sparse-checkout set TamnoonPlaybooks/AWS
      git checkout

   ``````  

2. Execute the automation from AWS directory
   1. Using CLI parameters:  
   ```
    python3 -m Automations.S3Actions.S3Helper --profile <aws_profile> --action check_public_access  --bucketNames <comma separated list of bucket name(s) or all>
   ```  
   or  
   ```
    python3 -m Automations.S3Actions.S3Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --action check_public_access --bucketNames <comma separated list of bucket names>
   ```  

    This automation does not require any action params.

