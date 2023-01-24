
<img src="../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: automatically remediate soft configurations for S3 Bucket.

## Description
This playbook describes how to solve soft misconfiguration over s3 bucket.
The script has a revert option where you can always revert specific actions.
The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile were given, use it as an AWS credentials source.
2. If no profile, use as variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Based on the given action to execute the script will run the relevant api call 
2. Some of the actions may require specific additional params that will be delivered as actionParams property to the script:
    1. For action - server_logging: "{"target_bucket": The name of the s3 bucket that will contain the logs}"
    2. For action - encryption: "{"kms": The arn of the kms managed key to use}
    3. For action - mfa_protection:
                        "{"mfa": The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device } 
       ##### For example - "{"mfa":"arn:aws:iam::123456789:mfa/bob 572055"}" where 572055 is the serial from that mfa on execution time

      
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

        		 Welcome To S3 soft remediation 

			 Dependencies:
				 
			 This script will know how to handle soft configuration for remediate s3 misconfiguration
 			 Supported Actions:
				 1. Bucket Server side logging
				 2. Bucket Server side encryption
				 3. Bucket Versioning
				 4. Bucket MFA deletion protection

				 The script is based on AWS API and documentation 
				 https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html


			 Executions Examples:
				 python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action <The S3 action to execute> --bucketName <The S3 bucket name>
				 --actionParmas <key value dictionary with the action execution params> --revert <true/false if to revert this action>

				 python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action server_logging  --bucketName <The S3 bucket name>
				 --actionParmas {"target_bucket":<the target buckt to contain the logs>} --revert <true/false if to revert this action>

				 python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action encryption  --bucketName <The S3 bucket name> 
				 --actionParmas {"kms":<the target buckt to contain the logs>} --revert <true/false if to revert this action>

				 python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action versioning  --bucketName <The S3 bucket name>
				 --revert <true/false if to revert this action>

				 python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action mfa_protection  --bucketName <The S3 bucket name>
				 --actionParmas {"mfa":<The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device>}  --revert <true/false if to revert this action>



			 Parameter Usage:
				 logLevel - The logging level (optional). Default = Info
				 profile -  The AWS profile to use to execute this script
				 action -   The S3 action to execute - (server_logging, encryption, versioning, mfa_protection)
					 * for mfa_protection you have to execute the script as the root user of the account according to: 
					 https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html
				 bucketName - The bucket name
				 actionParmas  - A key value Dictionary of action params:"
					 1. for action - server_logging:"
						 "{"target_bucket":<The name of the s3 bucket that will contain the logs>}"
					 2. for action - encryption:"
						 "{"kms":<The arn of the kms managed key to use>}
					 3. for action - mfa_protection:"
						 "{"mfa":<The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device>}
						 "for example - "{"mfa":"arn:aws:iam::123456789:mfa/bob 572055"}" where 572055 is the serial from that mfa on execution time
				 revert  - A true false flag to a sign if this action need to revert"
