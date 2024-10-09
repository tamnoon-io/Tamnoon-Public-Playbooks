
[comment]: <> (This is a readonly file, do not edit directly, to change update the ec2_find_load_balancers_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Investigation Playbook: AWS - Find Load Balancer Associated With EC2 Instance.
## Description

A load balancer distributes incoming network traffic across multiple servers to ensure optimal resource utilization, enhance reliability, and mitigate server overload. It helps maintain high availability and scalability of web applications or services.  
This playbook describes how to execute Tamnoon AWS type ec2 instance and action find-load-balancers to get details of  load balancer associated with provided ec2 instance ids.  
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
		find_load_balancers \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of instances to remediate or all>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		find_load_balancers \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of instances to remediate or all>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		find_load_balancers \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of instances to remediate or all>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		find_load_balancers \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		profile: tamnoon
		regions: all
		assetIds: all
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		ec2 \
		find_load_balancers \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "profile": "tamnoon",  
		  "regions": "all",  
		  "assetIds": "all" 
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
List of Regions used to find load balancers. If not used, default region is us-east-1.
### assetIds - (Required)
Comma separated list of EC2 Instance's IDs or all
## Sample Output

``````
{  
    "us-east-1": {  
        "running": {  
            "i-xxxxxxxxxxxxxxxxx": [  
                {  
                    "LoadBalancerArn": "load balancer arn",  
                    "load_balancer_name": "load balancer name",  
                    "type": "network",  
                    "port": 0,  
                    "target_groups": {  
                        "TargetGroupArn": "target group arn",  
                        "TargetGroupName": "target group name",  
                        "Protocol": "TCP",  
                        "port": 80  
                    },  
                    "security_groups": [  
                        "security group id"  
                    ],  
                    "listeners": [  
                        {  
                            "ListenerArn": "listener arn",  
                            "Port": 80,  
                            "Protocol": "TCP"  
                        }  
                    ]  
                },  
            ],  
        },  
        "stopped": {},  
        "pending": {},  
        "terminated": {},  
        "stopping": {},  
        "shutting_down": {}  
    }  
}
``````
### Note
This automation does not require actionParams
