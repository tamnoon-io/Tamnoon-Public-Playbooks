
<img src="../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Recommended remediation for lack of MFA
The playbook can remediate - Root users, Iam users, or both 

## Playbook steps:
1. SCP reduces the scope and limits all console activities without MFA  for the attached (target) AWS accounts.
2. Automation Script (Optional - only for scenarios that handled IAm users):
   1. Create an IAM policy that allows the user to create a new MFA for himself 
   2. Inject the new policy to all users without MFA.


## How to execute:
1. Create a new SCP on the Organization level, and use the next policy files per scenario:
   1. If targeting only root users, use the file - OrgSCPForRoot.json
   2. If targeting only IAMusers, use the file - OrgSCPForIamUSers.json
   3. If  targeting both, use the file - OrgSCPForRootAndIAmUSer.json
2. Attach as a target the relevant accounts in the SCP console.
3. In the case of IAMUsers :
   1. Execute the script RemediateMFA.py to create a new IAM Policy using the script help screen (python3 RemediateMFA.py --help)
   1. Execute the script RemediateMFA.py	to inject the new Iam POlicy to all users without MFA.
4. Communicate to your organization about this change - The users could not do any activity from the console without signing in using MFA.

## Prerequisites 
1. Permission to add new SCP in the Organization account.
2. Python3 and Boto3 pacakge installed. 
3. Permission to create Iam Policy on the target account. 
4. Permission to attach Iam Policy to Iam User in the target account. 
5. Permission to list Iam Policies and Iam Users in the target account.

## Notes:
1. Usage of IAMusers credentials keys are still allowed (the policy block only activity that happened from the console)

## Disclaimer:
The policy tries to block only console activities. In rare cases, the policy can fail some AWS API calls triggered using Access Keys. 
It could happen because the execution value of  ViaAWSService is equal to false (it seems like a console activity).
if that's happened, you need to extend the noAction section at the Deny statement of the Iam User part in the SCP policy with the relevant service
or contact Tamnoon Support - idan@tamnoon.io


## Script Help print

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

        		 Welcome To Tamnoon AWS MFA enforcement script 

			 Dependencies:
				 
			 Description:
				 This script is part of the MFA enforcement playbook
				 The assumption is that Tamnoon SCP policy is already setup on the organization level
				 This script will help to:
					 1. Create basicIamPolicyForUsers policy - this policy allow the identity to manage their own IAM configuration
					 2. Inject policy fom step 1 to all users in the account and tag them with Tamnoon remediation tag

				 The script is based on AWS API and documentation 
				 https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html


			 Executions Examples:
				 python3 RemediateMFA.py --profile <aws_profile> --action <The action to execute> --params <the params for the action>
				 python3 RemediateMFA.py --profile <aws_profile> --action create_policy 
				 python3 RemediateMFA.py --profile <aws_profile> --action remediate_user --names "user1,user2" 


			 Parameter Usage:
				 logLevel - The logging level (optional). Default = Info
				 profile -  The AWS profile to use to execute this script
				 action -   The  action to execute - (create_policy, remediate_user)
				 names  - List of user names to inject the policy to, no value means all users