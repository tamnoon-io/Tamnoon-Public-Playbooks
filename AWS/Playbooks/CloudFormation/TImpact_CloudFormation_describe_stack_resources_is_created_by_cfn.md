
[comment]: <> (This is a readonly file, do not edit directly, to change update the describe_stack_resources_is_created_by_cfn.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: CloudFormation - describe-stack-resources - Is Created By CloudFormation
## Description

This automation describes how to execute Tamnoon CloudFormation automation to determine whether the provided resource arn is deployed by CloudFormation stack and also determines the associations/relationships for resource arns of type Elatic Beanstalk, EC2 AutoScaling Groups etc.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. Following AWS Actions must be allowed for your AWS Account to successfully execute automation: 

	1. ec2:DescribeInstances

	2. autoscaling:DescribeAutoScalingGroups

	3. elasticbeanstalk:DescribeEnvironments

	4. CloudFormation:DescribeStacks

	5. CloudFormation:DescribeStackResources
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
	
	If Resource ARN is Provided and to determine whether the resource is deployed by cloudformation Stack then Use below Execution Commands :  

	1. Using CLI parameters:

	- Here For <resource-arn> you can provide AWS ARNs of Security Group ID, S3 bucket, EC2 Instance ID, Lambda Function, ECS Task, AutoScaling Group etc.
		``````
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--profile <aws_profile> \
		--assetIds <resource-arn> \
		--regions <comma separated list of regions or all>
		``````
		or  
		``````
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <resource-arn> \
		--regions <comma separated list of regions or all>
		``````
		or  
		``````
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--assetIds <resource-arn> \
		--regions <comma separated list of regions or all>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		profile: <aws-profile>
		assetIds:
		  - <resource-arn-1>
		  - <resource-arn-2>
		  - <resource-arn-3>
		  - <resource-arn-4>
		regions:
		  - region-name1
		  - region-name2
		  - region-name3
		logLevel: INFO
		outputType: json
		outDir: ./
		``````
		or  
		``````yaml
		awsAccessKey: <aws-access-key>
		awsSecret: <aws-secret-key>
		assetIds:
		  - <resource-arn-1>
		  - <resource-arn-2>
		  - <resource-arn-3>
		  - <resource-arn-4>
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
		is_created_by_cfn \
		--file path-to-yaml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "profile": "<aws-profile>",
		  "assetIds": [
		    "<resource-arn-1>",
		    "<resource-arn-2>",
		    "<resource-arn-3>",
		    "<resource-arn-4>"
		  ],
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
		or  
		``````json
		{
		  "awsAccessKey": "<aws-access-key>",
		  "awsSecret": "<aws-secret-key>",
		  "assetIds": [
		    "<resource-arn-1>",
		    "<resource-arn-2>",
		    "<resource-arn-3>",
		    "<resource-arn-4>"
		  ],
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
		is_created_by_cfn \
		--file path-to-json-file
		``````
	
	If EC2 Instance Id ARN is provided and you want to determine whether the Instance ID is created by AutoScaling Group which in turn created by CloudFormation Stack then Use Below Command to Execute :  

	1. Using CLI parameters:
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--profile <aws_profile> \
		--assetIds <ec2-instance-arn> \
		--regions <comma separated list of regions or all> \
		--actionParams '{"include-asg": true}'
		``````
		or  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <ec2-instance-arn> \
		--regions <comma separated list of regions or all> \
		--actionParams '{"include-asg": true}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		awsAccessKey: <aws-access-key>
		awsSecret: <aws-secret-key>
		assetIds: <ec2-instance-arn>
		regions:
		  - us-east-1
		  - us-east-2
		  - ap-southeast-2
		actionParams:
		  include-asg: true
		logLevel: INFO
		outputType: json
		outDir: ./
		``````
		or  
		``````yaml
		profile: <aws-profile>
		assetIds: <ec2-instance-arn>
		regions:
		  - us-east-1
		  - us-east-2
		  - ap-southeast-2
		actionParams:
		  include-asg: true
		logLevel: INFO
		outputType: json
		outDir: ./
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--file path-to-yaml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "profile": "<aws-profile>",
		  "assetIds": "<ec2-instance-arn>",
		  "regions": [
		    "us-east-1",
		    "us-east-2",
		    "ap-southeast-2"
		  ],
		  "actionParams": {
		    "include-asg": true
		  },
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "./"
		}
		``````
		or  
		``````json
		{
		  "awsAccessKey": "<aws-access-key>",
		  "awsSecret": "<aws-secret-key>",
		  "assetIds": "<ec2-instance-arn>",
		  "regions": [
		    "us-east-1",
		    "us-east-2",
		    "ap-southeast-2"
		  ],
		  "actionParams": {
		    "include-asg": true
		  },
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "./"
		}
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--file path-to-json-file
		``````
	
	If EC2 Instance Id ARN is provided and you want to determine whether the Instance ID is created by AutoScaling Group that was created by Elastic Beanstalk which in turn created by CloudFormation Stack then Use Below Command to Execute :  

	1. Using CLI parameters:
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--profile <aws_profile> \
		--assetIds <resource-arn> \
		--regions <comma separated list of regions or all> \
		--actionParams '{"include-asg": true, "include-ebs": true}'
		``````
		or  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--profile <aws_profile> \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <ec2-instance-arn> \
		--regions <comma separated list of regions or all> \
		--actionParams '{"include-asg": true, "include-ebs": true}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		profile: <aws-profile>
		assetIds: <ec2-instance-arn>
		regions:
		  - us-east-1
		  - us-east-2
		  - ap-southeast-2
		actionParams:
		  include-asg: true
		  include-ebs: true
		logLevel: INFO
		outputType: json
		outDir: ./
		``````
		or  
		``````yaml
		awsAccessKey: <aws-access-key>
		awsSecret: <aws-secret-key>
		assetIds: <ec2-instance-arn>
		regions:
		  - us-east-1
		  - us-east-2
		  - ap-southeast-2
		actionParams:
		  include-asg: true
		  include-ebs: true
		logLevel: INFO
		outputType: json
		outDir: ./
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--file path-to-yaml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "profile": "aws-profile",
		  "assetIds": "<ec2-instance-arn>",
		  "regions": [
		    "us-east-1",
		    "us-east-2",
		    "ap-southeast-2"
		  ],
		  "actionParams": {
		    "include-asg": true,
		    "include-ebs": true
		  },
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "./"
		}
		``````
		or  
		``````json
		{
		  "awsAccessKey": "<aws-access-key>",
		  "awsSecret": "<aws-secret-key>",
		  "assetIds": "<ec2-instance-arn>",
		  "regions": [
		    "us-east-1",
		    "us-east-2",
		    "ap-southeast-2"
		  ],
		  "actionParams": {
		    "include-asg": true,
		    "include-ebs": true
		  },
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "./"
		}
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.CloudFormation \
		describe-stack-resources \
		is_created_by_cfn \
		--file path-to-json-file
		``````
### profile - (Optional)
Use the aws profile for setting up session during automation.
### awsAccessKey - (Optional)
Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.
### awsSecret - (Optional)
Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.
### awsSessionToken - (Optional)
Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey.
### regions - (Optional)
List of regions. If not given, the default value is 'all', i.e., the remedy will evaluate all provided resource arns irrespective of there regions.
### assetIds - (Required)
Single or List of resource arns.If not provided, there is no default value.
### actionParams - (Optional)
- for the automation *Determine If EC2 Instance Created By AutoScaling Groups is Part of CloudFormation, Use*
	```
	--actionParams = '{"include-asg": true}'
	``` 

- for the automation *Determine If EC2 Instance Created By AutoScaling Groups Created By Elastic Beanstalk is Part of CloudFormation, Use*
	```
	--actionParams = '{"include-asg": true, "include-ebs": true}'
	```
## Sample Output

``````
{
    "arn:aws:ecs:::example-ecs": "This resource is created by CloudFormation Stack.",
    "arn:aws:s3:::example-bucket": "This resource is created by CloudFormation Stack.",
    "arn:aws:s3:us-east-1:example-bucket": "This resource does not appear to be part of a Cloudformation stack, but you should verify manually.",
    "arn:aws:lambda:us-east-1:123456789012:instance/i-0abcd1234efgh5678": "This resource does not appear to be part of a Cloudformation stack, but you should verify manually."
}
``````
