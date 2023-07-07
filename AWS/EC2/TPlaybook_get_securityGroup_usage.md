
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Get Security Group Usage.

## Description
This playbook describes how to execute Tamnoon EC2Helper automation to get security group usage.

The authentication process for this playbook follows the standard AWS set of fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder Automation/EC2Helper
2. Execute the automation 
 
          python3 EC2Helper.py --profile <aws_profile> --type security-group --action get_usage  --regions <The region/s to works on> --assetIds <list of instances to remediate>
          or 
          python3 EC2Helper.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type security-group --action get_usage  --regions <The region/s to works on> --assetIds <list of instances to remediate> 



## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


