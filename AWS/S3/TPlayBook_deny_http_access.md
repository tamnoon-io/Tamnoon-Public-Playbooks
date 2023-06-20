
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: S3 - Deny HTTP access to bucket.

## Description
This playbook describes how to execute Tamnoon S3 soft configuration automation to add deny policy for HTTP access.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder Automation/S3SoftConfiguration 
2. How to execute the automation:


    python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action block_http  --bucketNames <The S3 bucket name> 
    
    python3 S3_Soft_Configuration_Handler.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --action block_http  --bucketNames <The S3 bucket name> 

   


## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


