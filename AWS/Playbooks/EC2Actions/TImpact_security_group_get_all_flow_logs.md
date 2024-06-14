
[comment]: <> (This is a readonly file, do not edit directly, to change update the security_group_get_all_flow_logs.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Investigation Playbook: AWS - Get All Flow Logs of Security Groups
## Description

This playbook describes how to execute Tamnoon EC2Helper automation to get all flow logs of a security group.  
The automation attempts to collect information about inbound traffic to the members of any given Security Group. It does so by  

1. identifying the ENIs associated with that Security Group

2. identifying the Flowlog associated with these ENIs

3. identifying the Cloudwatch log group associated with that flowlog

4. querying in Cloudwatch that log group and summarizing the infromation by source IP and destination port.

For each Security Group for which this process succeeded, it outputs a json file with that information. At the end of its run, it also writes an output file for the run itself that for each security group says if information was retrieved and to which file it was saved. The success of this automation depends on the existence of flowlogs that log traffic for the security group members, and their availability within log groups in Cloudwatch. Follow [Tamnoon Playbook: Ec2 - Create VPC FLowlog](./TPlaybbok_create_vpc_flowlog.md) to enable creation of flow logs.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. Executing the script requires a role with permissions to discover log groups and query them. [logs:DescribeLogGroups, loap-southeast-1gs:DescribeLogStreams, logs:StartQuery. logs:GetQueryResults](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html)
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
	get_all_flow_logs \
	--profile <aws_profile> \
	--regions <comma separated list of regions or all> \
	  --assetIds <comma separated securirity group ids or all>  \n  --actionParams <action params here>
	``````
	or  
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	get_all_flow_logs \
	--awsAccessKey <aws_access_key> \
	--awsSecret <aws_secret> \
	--regions <comma separated list of regions or all> \
	  --assetIds <comma separated securirity group ids or all>  \n  --actionParams <action params here>
	``````
	or  
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	get_all_flow_logs \
	--awsAccessKey <aws_access_key> \
	--awsSecret <aws_secret> \
	--awsSessionToken <specific session token> \
	--regions <comma separated list of regions or all> \
	  --assetIds <comma separated securirity group ids or all>  \n  --actionParams <action params here>
	``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	get_all_flow_logs \
	--file path-to-yml-file
	``````
	And the contents of yml/yaml file would look like  
	``````yaml
	profile: tamnoon
	regions: all
	assetIds: all
	actionParams:
	  exclude_private_ips_from_source: false
	  hoursback: 10
	  exclude_src_ports:
	    - 8443
	      8444
	``````

	2. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
	``````sh
	python3 -m Automations.EC2Actions \
	security-group \
	get_all_flow_logs \
	--file path-to-json-file
	``````
	And the contents of json file would look like  
	``````json
	{
	  "profile": "tamnoon",  
	  "regions": "all",  
	  "assetIds": "all",  
	  "actionParams":  {  
	    "exclude_private_ips_from_source": false,  
	    "hoursback": 10,  
	    "exclude_src_ports": [8443,8444]    
	  } 
	}
	``````
## Sample Output

``````
[  
    {  
        "interfaceId": "eni-xxxxxxxxxxxxxxxxx",  
        "srcAddr": "source ip address 1",  
        "srcPort": "source ip address port 1",  
        "dstAddr": "destination ip address 1",  
        "dstPort": "destination ip address port 1",  
        "count": "3"  
    },  
    {  
        "interfaceId": "eni-xxxxxxxxxxxxxxxxx",  
        "srcAddr": "source ip address 2",  
        "srcPort": "source ip address port 2",  
        "dstAddr": "destination ip address 1",  
        "dstPort": "destination ip address port 1",  
        "count": "2"  
    }  
]
``````
### Note
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
List of Regions used to find security group of ec2 instance. If not used, default region is us-east-1.
### assetIds - (Required)
The Security Group's id identifier.
### actionParams
The ActionParams parameter provides the automation with parameters that are specific to the action taken. In this case get_all_flow_logs.  
  In general, the value of the ActionParams parameter is one, single-quoted text string that specifies a json.  
  ```'{"param1key": "param1value", "param2key": "param2value"}'```  
  There are two optional action parameters associated with the action get_all_flow_logs:  
  1. excludePrivateIPsFromSource (Optional)(boolean) - Flag to sign if need to find flow logs to &/or from only public IPs. Default is true.  
  2. hoursback - (Optional)(number) - Number of past hours to search the logs from current time. Default is 720 hours (30 days)  
  3. exclude_src_ports - comma-separated list of source ports that should be filtered out when fetching flowlogs (note that source ports smaller than 1024 are already filtered out)  
  ```  
  '{ "excludePrivateIPsFromSource": "True", "hoursback": "720", "exclude_src_ports": "8443,8444"  }'  
```
