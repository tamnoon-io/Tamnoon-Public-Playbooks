
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: IAM - Delete IAMUser .

## Description
This playbook describes how to execute Tamnoon IAMHelper automation to delete iam user.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the code from folder Automation/IAMHelper
2. Execute the automation 
 
          python3 IAMHelper.py --profile <aws_profile> --type IAMUser --action delete --assetIds <list of instances to remediate> --dryRun<optional dry run>
          or 
          python3 IAMHelper.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type IAMUser --action delete --assetIds <list of instances to remediate> --dryRun<optional dry run>




## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


