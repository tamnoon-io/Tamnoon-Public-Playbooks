
[comment]: <> (This is a readonly file, do not edit directly, to change update the describe_stack_resources_security_groups.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: CloudFormation - describe-stack-resources - Security Groups
## Description

This automation describes how to execute Tamnoon CloudFormation automation to determine whether the provided security group is deployed by a CloudFormation stack and to provide details about resources deployed by the stack.  
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
		``````
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		security_groups \
		--profile <aws_profile> \
		--assetIds <security-group-id> \
		--regions <comma separated list of regions or all>
		``````
		or  
		``````
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		security_groups \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <security-group-id> \
		--regions <comma separated list of regions or all>
		``````
		or  
		``````
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		security_groups \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--assetIds <security-group-id> \
		--regions <comma separated list of regions or all>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		awsAccessKey: <aws-access-key>
		awsSecret: <aws-secret-key>
		assetIds:
		  - security-grp-id1
		  - security-grp-id2
		  - security-grp-id3
		  - security-grp-id4
		regions:
		  - region-name1
		  - region-name2
		  - region-name3
		logLevel: INFO
		outputType: json
		outDir: ./
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		security_groups \
		--file path-to-yaml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "awsAccessKey": "<aws-access-key>",
		  "awsSecret": "<aws-secret-key>",
		  "assetIds": ["security-grp-id1", "security-grp-id2", "security-grp-id3"],
		  "regions": [
		    "region-name1",
		    "region-name2",
		    "region-name3"
		  ],
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "./"
		}
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		security_groups \
		--file path-to-json-file
		``````
Note : This action does not require actionParams  
### profile - (Optional)
Use the aws profile for setting up session during automation.
### awsAccessKey - (Optional)
Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.
### awsSecret - (Optional)
Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.
### awsSessionToken - (Optional)
Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey.
### regions - (Optional)
List of regions. If not given, the default value is 'all', i.e., the remedy will evaluate all the Security Groups without checking their regions.
### assetIds - (Required)
List of security group IDs.If not given, the default value is 'all', i.e., the remedy will evaluate all the Security Groups in given regions.
## Sample Output

For Security Group Not Deployed by CloudFormation Template :-   
``````
{
    "<security-group-id>": {
        "Tags": "No tags found for Security Group",
        "CloudFormationStackInfo": "Security Group was not deployed by CloudFormation."
    }
}
``````
For Security Group Deployed by CloudFormation Template :-   
``````
{
    "<security-group-id>": {
        "Tags": [
            {
                "Key": "aws:cloudformation:stack-id",
                "Value": "<cloudformation-template-stack-id>"
            },
            {
                "Key": "aws:cloudformation:stack-name",
                "Value": "<cloudformation-template-stack-name>"
            },
            {
                "Key": "aws:cloudformation:logical-id",
                "Value": "<cloudformation-template-logical-id>"
            }
        ],
        "CloudFormationStackInfo": {
            "StackID": "<cloudformation-template-stack-id>",
            "StackStatus": "<stack-status>",
            "CreationTime": "<stack-creation-time>",
            "Resources": [
                {
                    "LogicalResourceId": "<cloudformation-template-logical-id>",
                    "PhysicalResourceId": "<resource-name-deployed-by-cloudformation-template>",
                    "ResourceType": "<resource-type>",
                    "ResourceStatus": "<resource-status>"
                }
            ]
        }
    }
}
``````
