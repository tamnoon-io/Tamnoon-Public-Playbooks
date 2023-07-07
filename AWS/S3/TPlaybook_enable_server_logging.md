
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: S3 - Enable Server Logging.

## Description
This playbook describes how to execute Tamnoon S3 soft configuration automation to enable server logging.

The authentication process for this playbook follows the standard AWS set of fallbacks:
1. If an AWS profile or aws access key and secret are given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder Automation/S3SoftConfiguration 
2. How to execute the automation:

       python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action server_logging  --bucketNames <The S3 bucket name> --actionParmas {"target_bucket":<the target buckt to contain the logs>} --revert <true/false if to revert this action>

       python3 S3_Soft_Configuration_Handler.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --action server_logging  --bucketNames <The S3 bucket name> --actionParmas {"target_bucket":<the target buckt to contain the logs>} --revert <true/false if to revert this action>

actionParmas:
1. target_bucket - The target bucket to save the logs to.
      
   


## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


