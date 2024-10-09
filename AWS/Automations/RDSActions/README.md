
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: automatically execute bulk operation for RDS Service.

## Description
This playbook will help you to execute different operations over the RDS service
The Supported operations are:

        1. deletion-protection
        2. SecurityGroup - delete
        3. Vpc - create_flow_log
    
It uses the exact AWS Authentication fallback mechanism.
If there is no profile, use the credentials for AWS from the environment variable.
If the AWS credentials not exists in the environment variables, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Based on the given action to execute the script will run the relevant api call 
2. Some actions may require specific additional params that will be delivered as actionParams property to the script:


      
## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to change SecurityGroups
2. Python v3.6  and above + boto3 package installed ( pip install boto3)

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

        		 Welcome To Tamnoon RDSActions Helper- The script that will help you with your RDSActions Service Actions 

			 Dependencies:
				 
			 Authentication:
				 The script support the fallback mechanism auth as AWS CLI
					 profile - send the aws profile as input parameter
					 key and secret - send the aws key and secret as input parameter
			 Supported Actions:
				 1. RDSActions - 
						 Deletion protection

				 The script is based on AWS API and documentation 
				 https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html


			 Parameter Usage:
				 logLevel - The logging level (optional). Default = Info
				 profile (optional) -  The AWS profile to use to execute this script
				 awsAccessKey (optional) -  The AWS access key to use to execute this script
				 awsSecret (optional) -  The AWS secret to use to execute this script
				 awsSessionToken (optional) -  The AWS session token to use to execute this script
				 regions (optional) -   The AWS regions to use to execute this script (specific region, list of regions, or All)
				 type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....
				 action -   The EC2 action to execute - (snapshot-delete, sg-delete)
				 actionParmas (optional)  - A key value Dictionary of action params. each " should be \" for exampel {\"key1\":\"val1\"}
				 assetIds (optional) - List of assets ids (string seperated by commas)"
				 dryRun (optional) - Flag to mark if this is dry run execution"
				 file (optional) - The path to yaml file with the CLI execution params for this script"