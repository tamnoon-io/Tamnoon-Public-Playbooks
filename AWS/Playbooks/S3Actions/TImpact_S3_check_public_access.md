
[comment]: <> (This is a readonly file, do not edit directly, to change update the s3_check_public_access_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Impact Playbook: S3 - Check Public Access Configuration.
## Description

This playbook describes how to execute Tamnoon S3 automation to find which s3 buckets have public access.
  
This automation investigates policies and ACLs of S3 buckets that can allow public access to the buckets.  

- Buckets are considered public if they have some policy that allows action `s3:ListBucket` or `s3:*` to Principal `*` and having resource as the bucketName. For more details on policies, follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html).  Similarly, if buckets have similar policy but only with effect `Deny`, then irrespective of other policies, it will be denied access by public.

- It is possible for buckets to be public if they have some ACLs that allows for `READ` or `FULL_CONTROL` permission given to Everyone (`https://acs.amazonaws.com/groups/global/AllUsers`). For more details on ACLs, follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acls.html).

- Buckets that are public can be blocked for public access by Bucket Level Block Public Access and Account Level Block Public Access.

	- Block Public Access (BPA) is made of four values, out of which, two values are used for blocking public access of s3 buckets:

		- IgnorePublicAcls - ignores all the ACLs that are defined on the bucket and blocks the public access to the bucket, if it has been allowed via ACLs.

		- RestrictPublicBuckets - ignores all policies that are defined on the bucket and blocks the public access to the bucket, if it has been allowed via policies. It additionally reduces the previous public access - that is if any account could access this bucket previously, it will now allow to the accounts only from same organization as that of bucket owner.
	Bucket level BPA will take precedence for Account level first, then Bucket level.  

- For more details of BlockPublicAccess follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS credentials defined with following permissions.
  
    | Permission                     | Required for Operation                        |
    |--------------------------------|-----------------------------------------------|
    | s3:GetBucketPolicy             | GET bucket policy                             |
    | s3:GetBucketAcl                | GET bucket ACL                                |
    | s3:GetBucketPolicyStatus       | GET bucket policy status                      |
    | s3:GetBucketPublicAccessBlock  | GET bucket Block Public Access settings       |
    | s3:GetAccountPublicAccessBlock | GET account Block Public Access settings      |  
## Impact Investigation steps: 


1. Clone the Repository
	``````
	git clone --branch main --single-branch https://github.com/tamnoon-io/Tamnoon-Public-Playbooks.git
	``````

2. Move to AWS Folder
	``````
	cd TamnoonPlaybooks/AWS
	``````

3. Execute the automation

	1. Using CLI parameters:  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		check_public_access \
		--profile <aws_profile> \
		--bucketNames <comma separated s3 bucket name(s)>
		``````
		or  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		check_public_access \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--bucketNames <comma separated s3 bucket name(s)>
		``````
		or  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		check_public_access \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--bucketNames <comma separated s3 bucket name(s)>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		profile: "<aws-profile>"
		bucketNames:
		    - "<S3-Bucket-Name1>"
		    - "<S3-Bucket-Name2>"
		    - "<S3-Bucket-Name3>"
		logLevel: "<loglevel-type>"
		outputType: "<output-type>"
		outDir: "<output-result-path>"
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.S3Actions \
		s3 \
		check_public_access \
		--file path-to-yml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "profile": "<aws-profile>",
		  "bucketNames": [
		    "<S3-Bucket-Name1>",
		    "<S3-Bucket-Name2>",
		    "<S3-Bucket-Name3>"
		  ],
		  "logLevel": "<loglevel-type>",
		  "outputType": "<output-type>",
		  "outDir": "<output-result-path>"
		}
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.S3Actions \
		s3 \
		check_public_access \
		--file path-to-json-file
		``````
Note: This automation does not require any action params.  
### profile - (Optional)
Use the aws profile for setting up session during automation.
### awsAccessKey - (Optional)
Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.
### awsSecret - (Optional)
Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.
### awsSessionToken - (Optional)
Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey.
### bucketNames - (Required)
Comma separated list of S3 Buckets Name
### regions - (Optional)
List of Regions. If not given then default value is 'all', i.e., remedy will evaluate all the S3 Buckets without checking its regions.
## Sample Output

``````
{
  "region-name": {
    "AccountLevelBPA": {
      "BlockPublicAcls": false,
      "IgnorePublicAcls": false,
      "BlockPublicPolicy": false,
      "RestrictPublicBuckets": false
    },
    "Buckets": {
      "s3-bucket-name": {
        "BlockPublicAccess": {
          "BlockPublicAcls": false,
          "IgnorePublicAcls": false,
          "BlockPublicPolicy": false,
          "RestrictPublicBuckets": false
        },
        "ACL": [
          {
            "Grantee": {
              "DisplayName": "username",
              "ID": "userid",
              "Type": "usertype"
            },
            "Permission": "FULL_CONTROL"
          }
        ],
        "Policy": [
          {
            "Sid": "policy-sid",
            "Effect": "Allow/Deny",
            "Principal": {
              "Service": "logging.s3.amazonaws.com"
            },
            "Action": "s3-action",
            "Resource": "s3-bucket-arn",
            "Condition": {
              "StringEquals": {
                "aws:SourceAccount": "aws-account-id"
              }
            }
          },
          {
            "Sid": "sid",
            "Effect": "Deny/Allow",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
              "resource-arn",
              "resource-arn"
            ],
            "Condition": {
              "Bool": {
                "aws:SecureTransport": "false"
              }
            }
          }
        ],
        "PublicAccessAllowedBy": "NotAllowed",
        "PublicAccessToBucket": "Blocked",
        "PublicAccessToBucketObjects": "Prevented",
        "First3Objects": null
      }
    }
  }
}
``````
