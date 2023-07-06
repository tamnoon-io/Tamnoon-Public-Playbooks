
<img src="../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: automatically execute bulk operation for EC2 Service.

## Description
This playbook will help you to execute different operations over the EC2 service
The Supported operations are:

        1. Snapshot - delete,ls, encrypt
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

        		 Welcome To Tamnoon EC2 Helper- The script that will help you with your EC2 Service Actions 

			 Dependencies:
				 
			 Supported Actions:
				 1. Snapshot - 
						 delete, ls
						 encrypt
							 actionParams:
								 KmsKeyId (OPTIONAL) 
									 The kms key to use for encryption, If this parameter is not specified, your KMS key for Amazon EBS is used
				 2. SecurityGroup - delete  
				 3. Vpc - 
						 create_flow_log
							 actionParams:
								 DeliverLogsPermissionArn (REQUIRED)
									 The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account. 
								 LogGroupName (OPTIONAL)
									 The name of a new or existing CloudWatch Logs log group where Amazon EC2 publishes your flow logs. 

				 The script is based on AWS API and documentation 
				 https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html


			 Executions Examples:
				 python3 EC2Helper.py --profile <aws_profile> --type <The ec2 service type> --action <The action to execute> --actionParmas <the params for the action> --assetIds <list of assets to work on, comma-separated>
				 python3 EC2Helper.py  --type snapshot --action delete --assetIds "snap-1,snap-2" --dryRun True


			 Parameter Usage:
				 logLevel - The logging level (optional). Default = Info
				 profile -  The AWS profile to use to execute this script
				 type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....
				 action -   The EC2 action to execute - (snapshot-delete, sg-delete)
				 actionParmas (optional)  - A key value Dictionary of action params. each " should be \" for exampel {\"key1\":\"val1\"}
				 assetIds  - List of assets ids (string seperated by commas)"