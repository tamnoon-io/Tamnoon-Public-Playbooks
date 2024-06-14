
[comment]: <> (This is a readonly file, do not edit directly, to change update the snapshot_ls.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: AWS EC2 - List EBS Snapshot.
## Description

This playbook describes how to execute Tamnoon EC2Helper automation to list EBS Snapshot.  
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
	snapshot \
	ls \
	--profile <aws_profile> \
	--regions <The region/s to works on> \
	--assetIds <list of instances to remediate>
	``````
	or  
	``````sh
	python3 -m Automations.EC2Actions \
	snapshot \
	ls \
	--awsAccessKey <aws_access_key> \
	--awsSecret <aws_secret> \
	--regions <The region/s to works on> \
	--assetIds <list of instances to remediate>
	``````
	or  
	``````sh
	python3 -m Automations.EC2Actions \
	snapshot \
	ls \
	--awsAccessKey <aws_access_key> \
	--awsSecret <aws_secret> \
	--awsSessionToken <specific session token> \
	--regions <The region/s to works on> \
	--assetIds <list of instances to remediate>
	``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
	``````sh
	python3 -m Automations.EC2Actions \
	snapshot \
	ls \
	--file path-to-yml-file
	``````
	And the contents of yml/yaml file would look like  
	``````yaml
	regions:
	  - us-east-1
	assetIds:
	  - snapshot-id
	``````

	2. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
	``````json
	{
	  "regions": ["us-east-1"],
	  "assetIds": ["snapshot-id"]
	}
	``````
### Note
This automation does not use actionParams for automation.  
This automation does not support rollback.
### profile - (Optional)
Use the aws profile for setting up session during automation.
### awsAccessKey - (Optional)
Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.
### awsSecret - (Optional)
Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.
### awsSessionToken - (Optional)
Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey
### regions - (Optional)
List of Regions used to find snapshot of ec2 instance. If not used, default region is us-east-1.
