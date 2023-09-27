
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: RDS - Enable RDS instance deletion-protection.

## Description
This playbook describes how to execute Tamnoon RDSHelper automation to enable database instance deletion protection configration.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the AWS folder from  [Tamnoon-Public-Playbooks](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks)
2. Execute the automation from AWS directory
   1. Using CLI parameters:

          python -m Automations.RDSActions.RDSHelper --profile <aws_profile> --type rds --action deletion-protection  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun <optional dry run>
          or
          python -m Automations.RDSActions.RDSHelper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type rds --action deletion-protection  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun <optional dry run>
          or
          python -m Automations.RDSActions.RDSHelper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --awsSessionToken <specific session token> --type rds --action deletion-protection  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params >  --dryRun <optional dry run>
   2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
   
           key1: value1
           key2: value2
      for example the yaml file should look like:

          profile: <aws auth profile to use>
          type: rds
          action: deletion-protection
          regions:  <The region/s to works on>
          actionParams: {"rollBack":<True/False>}
          dryRun: <optional dry run>
          assetIds: <list of instances to remediate>
      
      and the execution line:
           
           python -m Automations.EC2Actions.EC2Helper --file <path to yaml file>

### This play book support actionParams - Below is description of what value it can take      

actionParmas:
1. rollBack (Optional) - Boolean flag to sign if this is a rollback call (required the existing of state file) 
   
   


## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


