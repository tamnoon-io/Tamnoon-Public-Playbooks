
[comment]: <> (This is a readonly file, do not edit directly, to change update the iam_user_deactivate_access_key_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: IAM - Deactivate IAMUser Access Key.
## Description

This playbook describes how to execute Tamnoon IAMHelper automation to deactivate AccessKeys.  
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
		deactivate_access_key \
		--profile <aws_profile> \
		--assetIds <comma separated usernames to deactivate accesskeys> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <comma separated usernames to deactivate accesskeys> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--assetIds <comma separated usernames to deactivate accesskeys> \
		--dryRun <optional dry run>
		``````
		For RollBack :  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
		--profile <aws_profile> \
		--assetIds <comma separated usernames to deactivate accesskeys> \
		--actionParams '{"rollBack": true, "specificKeys": "xxxxxxxxx"}'\
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <comma separated usernames to deactivate accesskeys> \
		--actionParams '{"rollBack": true, "specificKeys": "xxxxxxxxx"}' \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--assetIds <comma separated usernames to deactivate accesskeys> \
		--actionParams '{"rollBack": true, "specificKeys": "xxxxxxxxx"}' \
		--dryRun <optional dry run>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
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
		For RollBack :  
		``````yaml
		profile: "<aws-profile>"
		assetIds:
		  - "<username-1>"
		  - "<username-2>"
		  - "<username-3>"
		actionParams:
		  rollBack: "true"
		  specificKeys: "xxxxxxxx"
		logLevel: "<loglevel-type>"
		outputType: "<output-type>"
		outDir: "<output-result-path>"
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.IAMActions \
		iam-user \
		deactivate_access_key \
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
		For RollBack :  
		``````json
		{
		  "profile": "<aws-profile>",
		  "assetIds": [
		    "<username-1>",
		    "<username-2>",
		    "username-3>"
		  ],
		  "actionParams": {
		    "rollBack": "true",
		    "specificKeys": "xxxxxxxx"
		  },
		  "logLevel": "<loglevel-type>",
		  "outputType": "<output-type>",
		  "outDir": "<output-result-path>"
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
### assetIds - (Required)
Comma separated list of usernames whose accesskeys to deactivate
### actionParams - (Optional)
1. rollBack (Optional) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. specificKeys (Optional) - List of specific Access Key ids to remediate (comma separated string) - "key1,key2"
## Sample Output

``````
{
  "executionResults":
    [
      {
        "asset_id": "username",
        "action": "Inactive access key - xxxxxxxxxx",
        "status": "Success"
      }
    ]
}
``````
For RollBack :  
``````
{
  "executionResults": 
        [
            {
                "asset_id": "username",
                "action": "Inactive access key - xxxxxxxxxx",
                "status": "Roll-Back"
            }
        ]
}
``````
