
[comment]: <> (This is a readonly file, do not edit directly, to change update the ec2_get_imdsv1_usage_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Investigation Playbook: Ec2 - Switch to use IMDSv2 for EC2
## Description

Before configuring an EC2 instance to require it to use IMDSv2 and prevent it from using IMDSv1, it's important to determine if in the recent past the instance made any calls to IMDSv1. If it has not called IMDSv1, then the road is clear to prevent it from using it, without breaking anything. However, if it has been calling it, it's important to identify and upgrade the components that are making such calls before preventing the use of it. This automation determines the use of IMDSv1. It uses AWS Cloudwatch metric ["MetadatanoToken"](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html#ec2-cloudwatch-metrics) to count for each instance the number of times it made calls to the insecure ("token-less") IMDSv1.  
This automation provides the investigative part of handling alerts about the use of IMDSv1. [TPlaybook_set_IMDSv2.md](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md) provides remediation for such alerts by preventing the use of IMDv1.  
This automation is same as querying the CloudWatch metric MetadataNoToken on AWS portal as follows.  

1. Under CloudWatch, open All metrics

2. Choose EC2

3. Then choose "Per-Instance Metrics"

4. Change the timeframe to be 2W

All Instances that this metric is 0 for them are found by this Automation, for which we can enable IMDSv2 using [IMDSv2 Automation](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md).  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS credentials defined on the execution machine with permission to ec2::describeInstances
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
		ec2 \
		get_imdsv1_usage \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of instances to remediate or all>  \
		--actionParams <The action params >
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		get_imdsv1_usage \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of instances to remediate or all>  \
		--actionParams <The action params >
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		get_imdsv1_usage \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of instances to remediate or all>  \
		--actionParams <The action params >
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		get_imdsv1_usage \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		profile: tamnoon
		regions:
		 - all
		assetIds:
		 - all
		actionParams:
		  days: 6
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		get_imdsv1_usage \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "profile": "tamnoon",  
		  "regions": [
		    "all"
		  ],  
		  "assetIds": [
		    "all"
		  ],  
		  "actionParams":  {  
		    "days": 6  
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
List of Regions used to find ec2 instance. If not used, default region is us-east-1.
### assetIds - (Required)
The EC2 Instance's id identifier.
### actionParams - (Optional)
The ActionParams parameter provides the automation with parameters that are specific to the action taken. In this case get_imdsv1_usage.  
  In general, the value of the ActionParams parameter is one, single-quoted text string that specifies a json.  
  ```'{"param1key": "param1value", "param2key": "param2value"}'```  
  There is one optional action parameters associated with the action get_imdsv1_usage:  
  1. days - (Optional) - The past duration to find the IMDSv1 usage before current time. Default value 14 days. Example,  
  ```  
  --actionParams '{"days": 90}'  
  ```

## Sample Output

``````
{  
    "us-east-2": {  
        "from": "Sun Jan 1 12:09:33 2024",  
        "to": "Thu Jan 15 12:09:33 2024",  
        "i-xxxxxxxxxxxxxxxx": {  
            "InstanceName": "instance-1",  
            "Image": {  
                "ImageId": "ami-zzzzzzzzzzzzzzzzz",  
                "ImageName": "al2023-ami-2023.1.20230629.0-kernel-6.1-x86_64",  
                "ImageDescription": "Amazon Linux 2023 AMI 2023.1.20230629.0 x86_64 HVM kernel-6.1"  
            },  
            "UserData": null,  
            "SumOfMetadataNoTokenMetrics": 0.0,  
            "message": "ec2 instance i-xxxxxxxxxxxxxxxx has not been using IMDSv1 during past 15 days"  
        },  
        "i-yyyyyyyyyyyyyyyy": {  
            "InstanceName": "instance-2",  
            "Image": {  
                "ImageId": "ami-wwwwwwwwwwwwwwwww",  
                "ImageName": "al2023-ami-2023.3.20240131.0-kernel-6.1-x86_64",  
                "ImageDescription": "Amazon Linux 2023 AMI 2023.3.20240131.0 x86_64 HVM kernel-6.1"  
            },  
            "UserData": "This is user data",  
            "SumOfMetadataNoTokenMetrics": 0.0,  
            "message": "ec2 instance i-yyyyyyyyyyyyyyyy has not been using IMDSv1 during past 15 days"  
        }  
    }  
}
``````
### Note
This automation does not support rollback.
