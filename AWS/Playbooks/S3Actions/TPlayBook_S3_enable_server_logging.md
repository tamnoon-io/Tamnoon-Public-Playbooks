
[comment]: <> (This is a readonly file, do not edit directly, to change update the s3_enable_server_logging_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: S3 - Enable Server Logging.
## Description

This playbook describes how to execute Tamnoon S3 soft configuration automation to enable server logging.
  
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
		``````
		python3 -m Automations.S3Actions \
		s3 \
		server_logging \
		--profile <aws-profile> \
		--bucketNames <comma separated s3 bucket name(s)> \
		--actionParams '{"target_bucket":"<the target bucket to contain the logs>"}' \
		--revert <true/false_if_to_revert_this_action>
		``````
		or  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		server_logging \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--bucketNames <comma separated s3 bucket name(s)> \
		--actionParams '{"target_bucket":"<the target bucket to contain the logs>"}' \
		--revert <true/false_if_to_revert_this_action>
		``````
		or  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		server_logging \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--bucketNames <comma separated s3 bucket name(s)> \
		--actionParams '{"target_bucket":"<the target bucket to contain the logs>"}' \
		--revert <true/false_if_to_revert_this_action>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		profile: "<aws-profile>"
		bucketNames:
		  - "<S3-Bucket-Name1>"
		  - "<S3-Bucket-Name2>"
		  - "<S3-Bucket-Name3>"
		actionParams:
		  target_bucket: "<the target bucket to contain the logs>"
		logLevel: "<loglevel-type>"
		outputType: "<output-type>"
		outDir: "<output-result-path>"
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.S3Actions \
		s3 \
		server_logging \
		--file path-to-yml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "profile": "<aws-profile>",
		  "bucketNames": [
		    "<S3-Bucket-Name1>",
		    "<S3-Bucket-Name2>",
		    "<S3-Bucket-Name3>"
		  ],
		  "actionParams": {
		    "target_bucket": "<the target bucket to contain the logs>"
		  },
		  "logLevel": "<loglevel-type>",
		  "outputType": "<output-type>",
		  "outDir": "<output-result-path>"
		}
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.S3Actions \
		s3 \
		server_logging \
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
### bucketNames - (Required)
Comma separated list of S3 Buckets Name
### regions - (Optional)
List of Regions. If not given then default value is 'all', i.e., remedy will configure all the S3 Buckets without checking its regions.
### actionParams - (Required)
1. target_bucket - The target bucket to save the logs to.
### revert - (Optional)
Boolean Value true/false used to revert the action.
## Sample Output

``````
{
  "region-name": [
        {
            "bucket_name": "s3-bucket-name1",
            "result": "Server Logging for bucket set successfully."
        }
    ]
}
``````
For Revert :  
``````
{
  "region-name": [
        {
            "bucket_name": "s3-bucket-name1",
            "result": "Server Logging for bucket reverted successfully."
        }
    ]
}
``````
