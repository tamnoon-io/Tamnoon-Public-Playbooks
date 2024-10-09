
[comment]: <> (This is a readonly file, do not edit directly, to change update the events_history_readme.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Investigation Playbook: IAM - Cloudtrail - Events History.
## Description

This automation describes how to execute Tamnoon Logs Investigation automation to find events history of cloudtrail. This is done
by finding AttributeKey & its AttributeValue from events history of cloudtrail. This automation supports finding activity from *at most 90 recent days* to *at least 0.01 recent days (~ 15 recent minutes)*.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS credentials should have permission to cloudtrail:LookupEvents action for finding events history.
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
		python3 -m Automations.LogsInvestigation \
		events-history \
		--profile <aws_profile> \
		--regions <comma separated list of regions or all> \
		--actionParams <dictionary with the specific action params>
		``````
		or  
		``````
		python3 -m Automations.LogsInvestigation \
		events-history \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <comma separated list of regions or all> \
		--actionParams <dictionary with the specific action params>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		awsAccessKey: <aws_access_key>
		awsSecret: <aws_secret>
		regions:
		  - ap-southeast-2
		  - us-east-1
		  - us-east-2
		actionParams:
		  AttributeKey: Username
		  Value: xxxx
		  days: 0.25
		logLevel: INFO
		outputType: json
		outDir: ./
		testId: test-case-description
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.LogsInvestigation \
		events-history \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "awsAccessKey": "<aws_access_key>",
		  "awsSecret": "<aws_secret>",
		  "regions": [
		    "ap-southeast-2",
		    "us-east-1",
		    "us-east-2"
		  ],
		  "actionParams": {
		    "AttributeKey": "Username",
		    "Value": "xxxx",
		    "days": 0.25
		  },
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "./",
		  "testId": "test-case-description"
		}
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.LogsInvestigation \
		events-history \
		--file path-to-json-file
		``````
### profile - (Optional)
Aws Account Profile
### awsAccessKey - (Optional)
Aws Access Key
### awsSecret - (Optional)
Aws Secret Key
### awsSessionToken - (Optional)
Aws Session Token
### regions - (Optional)
This automation supports regions. Even though some Attributes themselves may not be restricted by regions - such as Username, AccessKeyId, etc - their usage can be traced differently across different regions.

Therefore, when you run this automation, you may want to specify from which regions to find activity of given Attribute.
You may specify regions as comma separated list or as all.

example:   
```
--regions us-east-1,us-east-2  
```  
or  
```
--regions all
```
### actionParams - (Required)
- AttributeKey: Attribute Key supported by events history. Automation will find the events history for this AttributeKey. There is no default value.
    example:  
    ```cli
    --actionParams '{"AttributeKey": "AccessKeyId"}'
    ```
    Supported AttributeKeys are listed here:
    -   EventId
    -   EventName
    -   ReadOnly
    -   Username
    -   ResourceType
    -   ResourceName
    -   EventSource
    -   AccessKeyId  

- AttributeValue: Attribute Value supported by events history. Automation will find the events history for this AttributeValue. There is no default value.
    example:  
    ```cli
    --actionParams '{"AttributeValue": "xxxxx"}'
    ```

- days: number of recent days. Automation will find the events history for this given duration between now and N days ago as given in actionParams. Default value is 90.
    example:  
    ```cli
    --actionParams '{"days": 15}'
    ```  
  For more details, follow [TImpact_events_history.md](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/Playbooks/LogsInvestigations/TImpact_events_history.md)
## References


- Please find list of eventnames [here](https://gist.github.com/pkazi/8b5a1374771f6efa5d55b92d8835718c)
