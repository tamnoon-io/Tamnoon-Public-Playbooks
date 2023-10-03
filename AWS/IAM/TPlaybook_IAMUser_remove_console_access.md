
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: IAM - Remove IAMUser console access.

## Description
This playbook describes how to execute Tamnoon IAMHelper automation to remove iam user console access.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder AWS/Automation/IAMHelper
2. Execute the automation from the /AWS directory
      1. Using CLI parameters:
 
              python3 -m Automations.IAMActions.IAMHelper --profile <aws_profile> --type IAMUser --action remove_console_access --assetIds <list of instances to remediate> --dryRun<optional dry run>
              or 
              python3 -m Automations.IAMActions.IAMHelper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type IAMUser --action remove_console_access --assetIds <list of instances to remediate> --dryRun<optional dry run>
              or
              python3 -m Automations.IAMActions.IAMHelper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --awsSessionToken <specific session token> --type IAMUser --action remove_console_access --assetIds <list of instances to remediate> --dryRun<optional dry run>
   
      2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
   
              key1: value1
              key2: value2
          for example the yaml file should look like:

              profile: <aws auth profile to use>
              type: IAMUser
              action: remove_console_access
              regions:  <The region/s to works on>
              actionParams: {"rollBack":<True/False>}
              dryRun: <optional dry run>
              assetIds: <list of users to remediate>
      
          and the execution line:
           
               python -m Automations.IAMActions.IAMHelper --file <path to yaml file>




## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


