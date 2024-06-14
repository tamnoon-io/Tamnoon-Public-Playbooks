
[comment]: <> (This is a readonly file, do not edit directly, to change update the security_group_clean_unused_sg.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: AWS - Clean Unused Security Group
## Description

This playbook describes how to remove inbound/outbound rules of unused security group. This is first step of overall cleanup security groups process. While second step can be found [here](./TPlaybook_security_group_delete.md).  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


2. AWS cretentials defined on the execution machine with permission to change SecurityGroups and its firewall rules.
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
	clean_unused_sg \
	--profile <aws_profile> \
	--regions <The region/s to works on> \
	--assetIds <comma separated list of security group IDs> \
	--dryRun<optional dry run>
	``````
	or  
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	clean_unused_sg \
	--awsAccessKey <aws_access_key> \
	--awsSecret <aws_secret> \
	--regions <The region/s to works on> \
	--assetIds <comma separated list of security group IDs> \
	--dryRun<optional dry run>
	``````
	or  
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	clean_unused_sg \
	--awsAccessKey <aws_access_key> \
	--awsSecret <aws_secret> \
	--awsSessionToken <specific session token> \
	--regions <The region/s to works on> --assetIds <comma separated list of security group IDs> --dryRun<optional dry run>
	``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	clean_unused_sg \
	--file path-to-yml-file
	``````
	And the contents of yml/yaml file would look like  
	``````yaml
	regions:
	  - us-east-1
	assetIds:
	  - security-group-id
	actionParams:
	  onlyDefaults: false
	  actionType: clean
	  deletionTag: false
	``````

	2. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
	``````json
	{
	  "regions": ["us-east-1"],
	  "assetIds": ["security-group-id"],
	  "actionParams": {
	    "onlyDefaults":false,
	    "actionType":"clean",
	    "deletionTag":false
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
- For automation:  
  1. onlyDefaults (Optional)(boolean) - Flag to sign if need to work only over default security groups.  
  2. actionType (Optional)(string) - Which action to run over the Security Group - Clean or Remove - Clean (default) will clean the Security Group rules and Remove will delete the Security Group.  
  3. deletionTag (Optional)(boolean) - Flag is use the Tamnoon deletion tag for deletion decision.  

- For rollback:  
  1. statePath - (Optional)(string) - The path where to save the state file, json that contain the snapshot of existing configuration before changes.  
  2. rollBack (Optional) (boolean)- Boolean flag to sign if this is a rollback call (required the existing of state file).
