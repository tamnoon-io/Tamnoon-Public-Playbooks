
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Switch to use IMDSv2 for EC2.

## Description
This playbook describes how to execute Tamnoon EC2Helper automation to switch for using IMSDv2 instead of v1.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the AWS folder from  [Tamnoon-Public-Playbooks](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks)
2. Execute the automation from AWS directory
   1. Using CLI parameters:

          python -m Automations.EC2Actions.EC2Helper --profile <aws_profile> --type ec2 --action enforce_imdsv2  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --revert <true/false if to revert this action> --dryRun<optional dry run>
          or
          python -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> ec2 --action enforce_imdsv2  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --revert <true/false if to revert this action> --dryRun<optional dry run>
          or
          python -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --awsSessionToken <specific session token> ec2 --action enforce_imdsv2  --regions <The region/s to works on> --assetIds <list of instances to remediate>  --actionParams <The action params > --revert <true/false if to revert this action> --dryRun<optional dry run>
   2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
   
           key1: value1
           key2: value2
      for example the yaml file should look like:

          profile: <aws auth profile to use>
          type: ec2
          action: enforce_imdsv2
          regions:  <The region/s to works on>
          actionParams: '{"HttpPutResponseHopLimit":<optional>, "revert":<optional>, "statePath":<optional>}'
          dryRun: <optional dry run>
          assetIds: <list of instances to remediate>
      
      and the execution line:
           
           python -m Automations.EC2Actions.EC2Helper --file <path to yaml file>

### This play book support actionParams - Below is description of what value it can take      

actionParmas:
1. HttpPutResponseHopLimit - (Optional) - The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. If no parameter is specified, the existing state is maintained. The value is number >=1.
2. revert (Optional) - Boolean flag to sign if this is a rollback call (required the existing of state file)
3. statePath (Optional) - The path where to save the state file, json that contain the snapshot of existing configuration before changes 
   
   


## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


