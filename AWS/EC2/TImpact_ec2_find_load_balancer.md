
<img src='../../images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Find Load Balancer Associated With EC2 Instance.

## Description
A load balancer distributes incoming network traffic across multiple servers to ensure optimal resource utilization, enhance reliability, and mitigate server overload. It helps maintain high availability and scalability of web applications or services.

This playbook describes how to execute Tamnoon AWS type ec2 instance and action find-load-balancers to get details of  load balancer associated with provided ec2 instance ids.
## Prerequisites

1. Python v3.9 + boto3 package installed (pip install boto3)
## Playbook Steps: 


1. Based on the given action to execute the script will run the relevant API call

2. Run the Execution
	``````sh
	python -m Automations.EC2Actions.EC2Helper \
	--type ec2 \
	--action find-load-balancers \
	--profile t1 \
	--regions us-west-1 \
	--assetIds i-0d13cc87cc14980d1,i-06af900fd9dd8a2f2 
	``````
 	Or
	``````sh
	python -m Automations.EC2Actions.EC2Helper \
	--type ec2 \
	--action find-load-balancers \
	--regions us-west-1 \
	--assetIds i-0d13cc87cc14980d1,i-06af900fd9dd8a2f2 \
	--awsAccessKey <your-aws-access-key> \
	--awsSecret <your-aws-secret-key>
	``````

	JSON or YAML File input will be supported soon.

### profile
The AWS profile to use to execute this script
### assetIds - (REQUIRED)
It can be 'all', or  comma_separated EC2 instance ids.
### regions  - (OPTIONAL)
If region is provided, it gives load balancers from provided region else gives load balancers from default region. 
### awsAccessKey 
awsAccessKey available in aws account. This is required when profile is not provided in input parameters else not required. 
### awsSecret 
awsSecret key available in aws account. This is required when profile is not provided in input parameters else not required.