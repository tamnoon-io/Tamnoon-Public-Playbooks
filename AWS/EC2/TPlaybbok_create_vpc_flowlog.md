
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Create VPC FLowlog.

## Description
This playbook describes how to execute Tamnoon EC2Helper automation to enable and create VPC flow logs.

The authentication process for this playbook follows the standard AWS set of fallbacks:
1. If an AWS profile or aws access key and secret are given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder Automation/EC2Helper
2. Execute the automation 
 
          python3 EC2Helper.py --profile <aws_profile> --type vpc --action create_flow_log  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun<optional dry run>
          or 
          python3 EC2Helper.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type vpc --action create_flow_log  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --dryRun<optional dry run>


actionParmas:
1. DeliverLogsPermissionArn - (Mandatory)(string) - The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account.
2. LogGroupName (Optional)(string) - The name of the target log group to contain the vpc flow logs



## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


