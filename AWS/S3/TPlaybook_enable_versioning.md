
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: S3 - Enable Server Versioning.

## Description
This playbook describes how to execute Tamnoon S3 soft configuration automation to enable bucket versioning.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder AWS/Automation/S3SoftConfiguration
2. Execute the automation from the /AWS directory


    python3 -m Automations.EC2Actions.S3Helper --profile <aws_profile> --action versioning  --bucketNames <The S3 bucket name> --revert <true/false if to revert this action>
    
    python3 -m Automations.EC2Actions.S3Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --action versioning  --bucketNames <The S3 bucket name> --revert <true/false if to revert this action>

   


## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


