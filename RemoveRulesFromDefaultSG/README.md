
<img src="../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: automatically remove inbound and outbound rules from unused default security groups.

## Description
This playbook describes how to remove inbound and outbound network rules from unused default security groups within an AWS account. 
The execution script saves the current state per security group in case that rollback is needed.
The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile were given, use it as an AWS credentials source.
2. If no profile, use as variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration
The full path to a JSON file that will contain the current revoked security group states in a case the rollback is needed

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Iterate over all regions within the AWS account 
2. Check for the defaults Security group within the region 
3. For all the default security groups:
   1. Check it's not attached to any NIC within the region 
   2. If the security group is attached, print the warring message and move to the next one 
   3. If the security group is not attached;
      1. Delete all ingress and egress rules definitions
      2. Keep those IpPermissions of the deleted rules within the state, for rollback purposes
      
## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Permissions to save JSON state file to the filesystem 
3. Python v3.6  and above + boto3 package installed ( pip install boto3)

## Notes:


## Script help page 

			 ___                                                                                           
			(   )                                                                            .-.           
			 | |_       .---.   ___ .-. .-.    ___ .-.     .--.     .--.    ___ .-.         ( __)   .--.   
			(   __)    / .-, \ (   )   '   \  (   )   \   /    \   /    \  (   )   \        (''")  /    \  
			 | |      (__) ; |  |  .-.  .-. ;  |  .-. .  |  .-. ; |  .-. ;  |  .-. .         | |  |  .-. ; 
			 | | ___    .'`  |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
			 | |(   )  / .'| |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
			 | | | |  | /  | |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
			 | ' | |  ; |  ; |  | |  | |  | |  | |  | |  | '  | | | '  | |  | |  | |   .-.   | |  | '  | | 
			 ' `-' ;  ' `-'  |  | |  | |  | |  | |  | |  '  `-' / '  `-' /  | |  | |  (   )  | |  '  `-' / 
			  `.__.   `.__.'_. (___)(___)(___)(___)(___)  `.__.'   `.__.'  (___)(___)  `-'  (___)  `.__.'  

        		 Welcome Tamnoon Remediation script for unused default security groups 

			 Dependencies:
				 
			 To run this script you should have:		
                           1.EC2 write permissions to modify security group in a given account				 
                           2.Filesystem write permissions to the state file path to read/write for the execution state file				 
                           3.Python v3.6 and above and boto3 package installed
            The script is based on AWS Boto3 API 
				 https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.SecurityGroup.revoke_ingress				
                              https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.SecurityGroup.revoke_egress


			 Executions Examples:
				 python3 TAWSDefaultSGRemidiation.py --profile <aws authz profile> --statePath <path to state json file > 
				 python3 TAWSDefaultSGRemidiation.py --profile <aws authz profile> --statePath <path to state json file > --rollBack True
				 python3 TAWSDefaultSGRemidiation.py --profile <aws authz profile> --statePath <path to state json file > --rollBack True --sgTorollBack <sg id of the sg to rollback>


			 Parameter Usage:
				 logLevel - The logging level (optional). Default = Info
				 profile -  The AWS creds profile to use
				 dryRun - (optional) A flag that will mark to avoid actual execution of revoking and just check permissions"
				 statePath -  The full path to a JSON file that will contain the current revoked sg states in a case we want to rollback
				 rollBack - (optional) A flag that sign if this is a rollback execution
				 sgTorollBack - The id for specific security group that we want to rollback
