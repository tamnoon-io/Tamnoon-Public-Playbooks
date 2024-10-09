
[comment]: <> (This is a readonly file, do not edit directly, to change update the iam_user_last_activity_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: IAM - Last Activity of IAMUser.
## Description

This playbook describes how to execute Tamnoon IAMHelper automation to describe last activity of IAMUser.  
## Prerequisites
1. Python v3.6 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS credentials defined on the execution machine with permission to change SecurityGroups
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
		python3 -m Automations.IAMActions \
		iam-user \
		last_activity \
		--profile <aws_profile> \
		--assetIds <comma separated usernames to delete>
		``````
		or  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		last_activity \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <comma separated usernames to delete>
		``````
		or  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		last_activity \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--assetIds <comma separated usernames to delete>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		last_activity \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		profile: "<aws-profile>"
		assetIds:
		  - "<username-1>"
		  - "<username-2>"
		  - "<username-3>"
		logLevel: "<loglevel-type>"
		outputType: "<output-type>"
		outDir: "<output-result-path>"
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		last_activity \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "profile": "<aws-profile>",
		  "assetIds": [
		    "<username-1>",
		    "<username-2>",
		    "username-3>"
		  ],
		  "logLevel": "<loglevel-type>",
		  "outputType": "<output-type>",
		  "outDir": "<output-result-path>"
		}
		``````
Note: This automation does not require any action params.  
### profile - (Optional)
Use the aws profile for setting up session during automation.
### awsAccessKey - (Optional)
Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.
### awsSecret - (Optional)
Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.
### awsSessionToken - (Optional)
Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey
### assetIds - (Required)
Comma separated list of usernames to find last activity.
## Sample Output

``````
{
  "executionResults": [
    {
      "user": "xxxxxxx",
      "last-password-used": "Never",
      "unused for (in days)": "Never Used"
    },
    {
      "user": "xxxxx",
      "last-password-used": "2024-05-20 12:08:20",
      "unused for (in days)": 30
    }
  ]
}  
``````
