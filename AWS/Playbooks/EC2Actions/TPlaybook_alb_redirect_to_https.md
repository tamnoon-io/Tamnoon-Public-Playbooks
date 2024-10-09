
[comment]: <> (This is a readonly file, do not edit directly, to change update the alb_redirect_to_https_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Set AWS ALB to Redirect HTTP to HTTPs
## Description

This automation describes how to execute Tamnoon automation to change Application Load Balancer listener actions rules that **forward** http (port 80) requests to https (port 443). Modified rules will **redirect** similar requests from http (port 80) to https (port 443) instead. This automation will also update default action of such listener with similar redirect action.  
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
		alb \
		redirect_to_https \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of application load balancers IDs> \
		--dryRun <optional dry run> \
		--actionParams <optional, required for rollback>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		alb \
		redirect_to_https \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of application load balancers IDs> \
		--dryRun <optional dry run> \
		--actionParams <optional, required for rollback>
		``````
		or  
		``````sh
		python3 -m Automations.EC2Actions \
		alb \
		redirect_to_https \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of application load balancers IDs> \
		--dryRun <optional dry run> \
		--actionParams <optional, required for rollback>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		alb \
		redirect_to_https \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		profile: tamnoon-profile
		regions:
		  - region-1
		assetIds:
		  - alb1
		  - alb2
		dryRun: true
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.EC2Actions \
		alb \
		redirect_to_https \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "profile":"tamnoon-profile",
		  "regions": ["region-1"],
		  "assetIds": ["alb1", "alb2"],
		  "dryRun": true
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
List of Regions used to find Application Load Balancers. If not used, default region is us-east-1.
### assetIds - (Required)
Comma separated list of Application Load Balancer's IDs or all.
### actionParams - (Optional)
- For Rollback:
  1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (requires the existence of state file)
  2. statePath - (Required) - The path for the last execution that we want to roll-back from.
## Sample Output

``````
{
    "us-east-1": {
        "alb1": {
            "prev_state": {
                "listener": {
                    "ListenerArn": "listener arn here",
                    "LoadBalancerArn": "load balancer arn here",
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [
                        {
                            "Type": "forward",
                            "TargetGroupArn": "elastic load balancer target group arn here",
                            "ForwardConfig": {
                                "TargetGroups": [
                                    {
                                        "TargetGroupArn": "elastic load balancer target group arn here",
                                        "Weight": 1
                                    }
                                ],
                                "TargetGroupStickinessConfig": {
                                    "Enabled": false
                                }
                            }
                        }
                    ]
                },
                "rules": [
                    {
                        "RuleArn": "elastic load balancer listener rule arn here",
                        "Priority": "rule priority value here",
                        "Conditions": [
                            {
                                "Field": "query-string",
                                "QueryStringConfig": {
                                    "Values": [
                                        {
                                            "Key": "key1",
                                            "Value": "value1"
                                        }
                                    ]
                                }
                            }
                        ],
                        "Actions": [
                            {
                                "Type": "redirect",
                                "Order": 1,
                                "RedirectConfig": {
                                    "Protocol": "HTTPS",
                                    "Port": "443",
                                    "Host": "#{host}",
                                    "Path": "/#{path}",
                                    "Query": "#{query}",
                                    "StatusCode": "HTTP_301"
                                }
                            }
                        ],
                        "IsDefault": false
                    }
                ]
            },
            "current_state": {
                "listener": {
                    "ListenerArn": "listener arn here",
                    "LoadBalancerArn": "load balancer arn here",
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [
                        {
                            "Type": "redirect",
                            "RedirectConfig": {
                                "Protocol": "HTTPS",
                                "Port": "443",
                                "Host": "#{host}",
                                "Path": "/#{path}",
                                "Query": "#{query}",
                                "StatusCode": "HTTP_301"
                            }
                        }
                    ]
                },
                "rules": [
                    {
                        "RuleArn": "elastic load balancer listener rule arn here",
                        "Priority": "rule priority value here",
                        "Conditions": [
                            {
                                "Field": "query-string",
                                "QueryStringConfig": {
                                    "Values": [
                                        {
                                            "Key": "key1",
                                            "Value": "value1"
                                        }
                                    ]
                                }
                            }
                        ],
                        "Actions": [
                            {
                                "Type": "redirect",
                                "Order": 1,
                                "RedirectConfig": {
                                    "Protocol": "HTTPS",
                                    "Port": "443",
                                    "Host": "#{host}",
                                    "Path": "/#{path}",
                                    "Query": "#{query}",
                                    "StatusCode": "HTTP_301"
                                }
                            }
                        ],
                        "IsDefault": false
                    }
                ]
            }
        }
    }
}
``````
Here, prev_state describes state of listener and rules before automation execution. Similarly, current_state describes state of listener and rules after automation execution. **rules** do not show default rule action, because that is described by **listener**'s defaultActions.  
