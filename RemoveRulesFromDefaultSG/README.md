
<img src="../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Automatically Remove inbound and outbound rules from unused default security groups.

## Description
This playbook describes how to remediate unused default security groups 
The execution script also saves the current state per security group in case that rollback is needed
The execution is based on AWS creds configuration based on the next fallbacks:
1. If AWS profile were given, use it as an AWS creds source
2. If no profile, use en variable creds for aws 
3. If not env variables provided, use the current ./~aws configuration
The full path to a JSON file that will contain the current revoked sg states in a case we want to rollback

After authenticated via AWS API, the script execution will be run on the same AWS account that those creds defined in 

## Playbook steps:
1. Iterate over all regions within the AWS account 
2. Check for the defaults Security group within the region 
3. If there are default sg:
   1. Check that they are not attached to any NIC within the region 
   2. If the sg is attached print the warring message and move to the next one 
   3. If the sg is not attached;
      1. Delete all ingress and egress rule definition 
      2. Kep those IpPermissions of the deleted rules within the state for rollback purposes
      
## Prerequisites 
1. Aws creds defined on the execution machine with permission to change SecurityGroups
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