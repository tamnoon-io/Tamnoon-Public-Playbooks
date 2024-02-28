
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Remove/Replace rules in Security Groups.

## Description
This playbook describes how to execute Tamnoon EC2Helper automation to remove or replace rules in security groups.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:

1. Clone the folder Azure
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/AWS
      git checkout

   ``````  
2. go to Tamnoon-Service/TamnoonPlaybooks/AWS in your terminal/shell
3. run the remedy


        python3 -m Automations.EC2Actions.EC2Helper --profile <aws_profile> --type security-group --action remove_or_replace_rules --regions <comma separated The region/s to works on or all> --assetIds <comma list of security groups to remediate or all>  --actionParams <The action params>  --dryRun<optional dry run>

    or

        python3 -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type security-group --action remove_or_replace_rules --regions <comma separated The region/s to works on or all> --assetIds <comma list of security groups to remediate or all>  --actionParams <The action params>  --dryRun<optional dry run>

    or

        python -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --awsSessionToken <specific session token> --type security-group --action remove_or_replace_rules --regions <comma separated The region/s to works on or all> --assetIds <comma list of security groups to remediate or all>  --actionParams <The action params>  --dryRun<optional dry run>

### actionParmas:
- to remove rules:
    - Ports (Required): space separated list of ports to match Port Ranges from the security rule.
    - oldCidrs (Required): list of IP CIDRs to match Source from the security rule.
    - allprivate (Optional): filters the private IP CIDRs
    - replace (Optional): true/false. to replace rules, it is required to be true. It's default value is false; therefore, when absent, remedy will asume remove rules operation.  
    example, --actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8 12.0.0.0/8", "allprivate": false, "replace": false}'  
    or  
    --actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8 12.0.0.0/8", "allprivate": false}'  
    both actionParams suggest remove rules operation

- to replace rules:
    same as above with two changes.
    - replace (Required): true/false. to replace rules, it is required to be true. It's default value is false; therefore, when absent, remedy will asume remove rules operation.  
    example, --actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8 12.0.0.0/8", "allprivate": false, "replace": true, "newCidrs":"11.0.0.0/8"}'  

    - newCidrs (Required): new IP CIDR for source.
    example, --actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8", "allprivate": false, "replace": false, "newCidrs":"11.0.0.0/8"}'  

- for rollback
    - rollBack (Required): true/false. Boolean flag to sign if this is a rollback call (required the existing of state file)
    - statePath (Required): The path string to the state file that contains getting details of remedy output which can be then used to undo those changes.

    when rollback, it is recommended that you provide **--regions all**, because the hierarchy of authentication profile. If by the hierarchy, your session does not have the region where the security group should be, **it will not be found** unless you provide --regions in rollback command. To keep it safe, you should use **--regions all**. 

## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups and its firewall rules
2. Python v3.6  and above + boto3 package installed ( pip install boto3)


