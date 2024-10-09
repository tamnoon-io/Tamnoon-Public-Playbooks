
[comment]: <> (This is a readonly file, do not edit directly, to change update the subnet_disable_public_ip_assignment_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: AWS - Turn off auto public IP assignment
## Description

This playbook describes how to execute Tamnoon EC2Helper automation to turn off automatic public IP address assignments.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).

## Playbook Steps: 


1. Clone the Repository
	``````
	git clone --branch main --single-branch https://github.com/tamnoon-io/Tamnoon-Public-Playbooks.git
	``````

2. Move to AWS Folder
	``````
	cd TamnoonPlaybooks/AWS
	``````

3. Execute the automation

	1. Using CLI parameters:
		``````sh
		python3 -m Automations.EC2Actions \
		subnet \
		disable_public_ip_assignment \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of subnet ids> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		subnet \
		disable_public_ip_assignment \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of subnet ids> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		subnet \
		disable_public_ip_assignment \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of subnet ids> --dryRun <optional dry run>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		subnet \
		disable_public_ip_assignment \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		regions:
		  - us-east-1
		assetIds:
		  - subnet-id
		actionParams:
		  excluded_subnets:
		    - subnet1
		      subnet2
		
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		subnet \
		disable_public_ip_assignment \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "regions": ["us-east-1"],
		  "assetIds": ["subnet-id"],
		  "actionParams": {
		    "excluded_subnets": [
		      "subnet1",
		      "subnet2"
		    ]
		  }
		}
		``````
### profile - (Optional)
Use the aws profile for setting up session during automation.
### awsAccessKey - (Optional)
Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.
### awsSecret - (Optional)
Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.
### awsSessionToken - (Optional)
Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey
### regions - (Optional)
List of Regions used to find Subnet associated with of ec2 instance. If not used, default region is us-east-1.
### actionParams - (Optional)
- For automation:  
  1. excluded_subnets - (Optional)(string) - List of subnets to exclude (by name or ids), comma seperated string  

- For rollback:
  1. rollBack - (Optional) (boolean)- Boolean flag to sign if this is a rollback call (required the existing of state file)
  2. lastExecutionResultPath - (Required) - The path for the last execution that we want to roll-back from.
### assetIds - (Required)
The Subnet id identifier.
