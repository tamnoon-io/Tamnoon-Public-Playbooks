
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Remove Unused Security Groups.

## Description
This playbook describes how to execute Tamnoon EC2Helper automation to remove unused security groups.

The authentication process for this playbook follows the standard AWS set of fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the folder Automation/EC2Helper 

### Approach 1: Remove rules before deleting the security groups
1. Execute the automation for remove inbound/outbound rules of unused security group 
 
          python3 EC2Helper.py --profile <aws_profile> --type security-group --action clean_unused_sg  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun<optional dry run>
          or 
          python3 EC2Helper.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type security-group --action clean_unused_sg  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --dryRun<optional dry run>
2. Wait some period time before delete them (recommended 1 week)

3. Execute the automation for the security group deletion
          
          python3 EC2Helper.py --profile <aws_profile> --type security-group --action remove_unused_sg  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun<optional dry run>
          or 
          python3 EC2Helper.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type security-group --action remove_unused_sg  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --dryRun<optional dry run>

### Approach 2: Delete the security groups
1. Execute the automation for remove the security group
          
          python3 EC2Helper.py --profile <aws_profile> --type security-group --action remove_unused_sg  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun<optional dry run>
          or 
          python3 EC2Helper.py --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type security-group --action remove_unused_sg  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --dryRun<optional dry run>

    

actionParmas:
1. statePath - (Optional)(string) - The path where to save the state file, json that contain the snapshot of existing configuration before changes
2. rollBack (Optional) (boolean)- Boolean flag to sign if this is a rollback call (required the existing of state file)
3. onlyDefaults (Optional)(boolean) - Flag to sign if need to work only over default security groups 
4. actionType (Optional)(string) - Which action to run over the Security Group - Clean or Remove - Clean (default) will clean the Security Group rules and Remove will delete the Security Group
5. deletionTag (Optional)(boolean) - Flag is use the Tamnoon deletion tag for deletion decision
   


## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


