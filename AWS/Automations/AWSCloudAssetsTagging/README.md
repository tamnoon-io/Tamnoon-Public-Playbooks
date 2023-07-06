
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: AWS Bulk resource tagging

## Description
This playbook describe how to execute BUlk resource tagging in AWS.
The execution is based on AWS APIs:
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/resource-explorer-2.html
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/index.html

## Playbook steps:
1. Use the script - resourceTagging.py


## Prerequisites 
1. AWS CLI Installed 
2. Python v3.6  and above + boto3 package installed ( pip install boto3)

## Notes:
The dynamic tagging currently support only the asset id or arn 

## Example use case 
### Tag all snapshots to allocate and trace their cost. 
#### Step 1 - Tag your resources with a specific cost tag using this playbook 
        Execute the script - python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey costAllocTag --tagValue {{id}}
#### Step 2 - Activate the tag as a cost allocation tag
        https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/activating-tags.html
#### Step 3 - After 24 hours from the activation, you can start tracing your snapshot's cost under the cost explorer screen when you group by the activated tag (in our example costAllocTag)



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

        		 Welcome To AWS resource tagging helper 

			 Dependencies:
				 AWS CLI
				 Python v3.8 and up
				 Boto3 pacakge 1.26 and above

			 This script will help you to bulk tag assets in your AWS environment
 			 The script provides the ability to tag dynamic value to each asset (for example, its asset id or arn
 
			 This script is based on AWS API and rely on the fallback mechanism of AWS Authentication and Authorization
			 (Profile, creds file, os environment)


			 Executions Examples:
				 python3 resourceTagging.py --profile <aws_profile> --action ls  
				 python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey testtag --tagValue {{id}}
				 python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey testtag --tagValue someTagValue
				 python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey testtag --revert true


			 Parameter Usage:
				 logLevel - The logging level (optional). Default = Info
				 profile  - The AWS profile to use to execute this script
				 action   - Which action to execute:
					 1.listOfSupportedResources - print out the supported service and resources that the script can tag
					 2.tag - tag the given assets or the entire assets related to the service with the given tag value
				 service - The service which all resources from will be tagged:
					 It could be high level, for example, ec2 - in that case, all resources under ec2 will tag (instances, snapshots, volumes...)
					 Or it could be as the output of the  listOfSupportedResources execution - for example, ec2:snapshot will tag only snapshots
				 tagKey  - The name of the tag (the key part of the tag)"
				 tagValue  - The value of the tag, two options are supported:"
					 1. Dynamic value - property have to be surrounded by {{}}, for example, {{id}} - the id of the resource"
					 2. Static value - string value to bulk all over the resources"
				 revert  - A true false flag to a sign if this action need to revert"