
[comment]: <> (This is a readonly file, do not edit directly, to change update the security_group_get_usage_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Investigation Playbook: AWS - Get Security Group Usage
## Description

This playbook describes how to execute Tamnoon EC2Helper automation to get security group usage, i.e., if security group is being used or not by finding its associations with network interfaces, lambda functions, VPC configs, etc.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS cretentials defined on the execution machine with permission to change SecurityGroups.
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
		security-group \
		get_usage \
		--profile <aws_profile> \
		--regions <comma separated list of regions or all> \
		  --assetIds <comma separated securirity group ids or all>  \n  --actionParams <action params here>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		get_usage \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <comma separated list of regions or all> \
		  --assetIds <comma separated securirity group ids or all>  \n  --actionParams <action params here>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		get_usage \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--regions <comma separated list of regions or all> \
		  --assetIds <comma separated securirity group ids or all>  \n  --actionParams <action params here>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		get_usage \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		profile: tamnoon
		regions: all
		assetIds: all
		actionParams:
		  onlyDefaults: false
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		get_usage \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "profile": "tamnoon",  
		  "regions": "all",  
		  "assetIds": "all",  
		  "actionParams":  {  
		    "onlyDefaults": false  
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
List of Regions used to find security group of ec2 instance. If not used, default region is us-east-1.
### assetIds - (Required)
The Security Group's id identifier.
### actionParams - (Optional)
The ActionParams parameter provides the automation with parameters that are specific to the action taken. In this case get_usage.  
  In general, the value of the ActionParams parameter is one, single-quoted text string that specifies a json.  
  ```'{"param1key": "param1value", "param2key": "param2value"}'```  
  There is one optional action parameters associated with the action get_usage:  
  1. onlyDefaults (Optional)(boolean) - Flag to sign if need to work only over default security groups   
  ```  
  '{ "onlyDefaults": "True"  }'  
```
