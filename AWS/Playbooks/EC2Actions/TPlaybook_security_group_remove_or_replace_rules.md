
[comment]: <> (This is a readonly file, do not edit directly, to change update the security_group_remove_or_replace_rules_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: AWS - Remove Or Replace Rules in Security Group
## Description

This playbook describes how to execute Tamnoon EC2Helper automation to remove or replace rules in security groups.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS cretentials defined on the execution machine with permission to change SecurityGroups and its firewall rules.
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
		remove_or_replace_rules \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of security group IDs> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		remove_or_replace_rules \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of security group IDs> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		remove_or_replace_rules \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--regions <The region/s to works on> --assetIds <comma separated list of security group IDs> --dryRun <optional dry run>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		remove_or_replace_rules \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		regions:
		  - us-east-1
		assetIds:
		  - security-group-id
		actionParams:
		  Ports: "10 11"
		  oldCidrs: "10.0.0.0/8 12.0.0.0/8"
		  allprivate: false
		  replace: false
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		security-group \
		remove_or_replace_rules \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "regions": ["us-east-1"],
		  "assetIds": ["security-group-id"],
		  "actionParams": {
		    "Ports": "10 11",
		    "oldCidrs": "10.0.0.0/8 12.0.0.0/8",
		    "allprivate": false,
		    "replace": false
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
The ActionParams parameter provides the automation with parameters that are specific to the action taken. In this case remove_or_replace_rules.  
  In general, the value of the ActionParams parameter is one, single-quoted text string that specifies a json.  
  ```'{"param1key": "param1value", "param2key": "param2value"}'```  

  - to remove rules:  
    - Ports (Required): space separated list of ports to match Port Ranges from the security rule.  
    - oldCidrs (Required): list of IP CIDRs to match Source from the security rule.  
    - allprivate (Optional): filters the private IP CIDRs  
    - replace (Optional): true/false. to replace rules, it is required to be true. It's default value is false; therefore, when absent, remedy will asume remove rules operation.    
    example,   ```--actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8 12.0.0.0/8", "allprivate": false, "replace": false}'``` or  ```--actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8 12.0.0.0/8", "allprivate": false}'```  
    both actionParams suggest remove rules operation  

  - to replace rules:  
    same as above with two changes.  
    - replace (Required): true/false. to replace rules, it is required to be true. It's default value is false; therefore, when absent, remedy will asume remove rules operation.    
    example, ```--actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8 12.0.0.0/8", "allprivate": false, "replace": true, "newCidrs":"11.0.0.0/8"}'```  
    - newCidrs (Required): new IP CIDR for source.  
    example, ```--actionParams '{"Ports": "10 11", "oldCidrs": "10.0.0.0/8", "allprivate": false, "replace": false, "newCidrs":"11.0.0.0/8"}'```    

- for rollback  
    - rollBack (Required): true/false. Boolean flag to sign if this is a rollback call (required the existing of state file)  
    - statePath (Required): The path string to the state file that contains getting details of remedy output which can be then used to undo those changes.  
  
    when rollback, it is recommended that you provide **--regions all**, because the hierarchy of authentication profile. If by the hierarchy, your session does not have the region where the security group should be, **it will not be found** unless you provide --regions in rollback command. To keep it safe, you should use **--regions all**. 
## SampleOutput

``````
{  
    "us-east-1": {  
        "sg-xxxxxxxxxxxxxxxx": {  
            "sgr-yyyyyyyyyyyyyyyy": {  
                "inputrule": {  
                    "SecurityGroupRuleId": "sgr-yyyyyyyyyyyyyyyy",  
                    "GroupId": "sg-xxxxxxxxxxxxxxxx",  
                    "GroupOwnerId": "account-id",  
                    "IsEgress": false,  
                    "IpProtocol": "tcp",  
                    "FromPort": 10,  
                    "ToPort": 10,  
                    "CidrIpv4": "10.0.0.0/8",  
                    "Tags": []  
                },  
                "ruleremoved": true,  
                "rulereplaced": true,  
                "rulescreated": [  
                    {  
                        "SecurityGroupRuleId": "sgr-zzzzzzzzzzzzzzzz",  
                        "GroupId": "sg-xxxxxxxxxxxxxxxx",  
                        "GroupOwnerId": "account-id",  
                        "IsEgress": false,  
                        "IpProtocol": "tcp",  
                        "FromPort": 10,  
                        "ToPort": 10,  
                        "CidrIpv4": "11.11.0.0/16"  
                    }  
                ],  
                "rulesreplaced": true  
            }  
        }  
    },  
}
``````
