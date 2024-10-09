
[comment]: <> (This is a readonly file, do not edit directly, to change update the s3_block_public_access_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: S3 - Enable Block Public Access Configuration.
## Description

This playbook describes how to execute Tamnoon S3 soft configuration automation to block public access.
  
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
		configure_public_access \
		--profile <aws_profile> \
		--bucketNames <comma separated s3 bucket name(s)> \
		--actionParams '{"BlockPublicAcls": true/false, "IgnorePublicAcls": true/false, "BlockPublicPolicy": true/false, "RestrictPublicBuckets": true/false}'
		``````
		or  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		configure_public_access \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--bucketNames <comma separated s3 bucket name(s)> \
		--actionParams '{"BlockPublicAcls": true/false, "IgnorePublicAcls": true/false, "BlockPublicPolicy": true/false, "RestrictPublicBuckets": true/false}'
		``````
		or  
		``````
		python3 -m Automations.S3Actions \
		s3 \
		configure_public_access \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <specific session token> \
		--bucketNames <comma separated s3 bucket name(s)> \
		--actionParams '{"BlockPublicAcls": true/false, "IgnorePublicAcls": true/false, "BlockPublicPolicy": true/false, "RestrictPublicBuckets": true/false}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		profile: "<aws-profile>"
		bucketNames:
		    - "<S3-Bucket-Name1>"
		    - "<S3-Bucket-Name2>"
		    - "<S3-Bucket-Name3>"
		actionParams:
		  BlockPublicAcls: true
		  IgnorePublicAcls: true
		  BlockPublicPolicy: true
		  RestrictPublicBuckets: true
		logLevel: "<loglevel-type>"
		outputType: "<output-type>"
		outDir: "<output-result-path>"
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.S3Actions \
		s3 \
		configure_public_access \
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
		    "BlockPublicAcls": true,
		    "IgnorePublicAcls": true,
		    "BlockPublicPolicy": true,
		    "RestrictPublicBuckets": true
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
		configure_public_access \
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
### actionParams - (Optional)
1. BlockPublicAcls (boolean) -

    Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Setting this element to TRUE enables the block public access for S3 bucket
    
    Enabling this setting doesn’t affect existing policies or ACLs.
2. IgnorePublicAcls (boolean) -

    Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Setting this element to TRUE causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket. 

    Enabling this setting doesn’t affect the persistence of any existing ACLs and doesn’t prevent new public ACLs from being set.
3. BlockPublicPolicy (boolean) -

    Specifies whether Amazon S3 should block public bucket policies for this bucket. Setting this element to TRUE causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access.

    Enabling this setting doesn’t affect existing bucket policies.
4. RestrictPublicBuckets (boolean) -

    Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Setting this element to TRUE restricts access to this bucket to only Amazon Web Service principals and authorized users within this account if the bucket has a public policy.

    Enabling this setting doesn’t affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.
## Sample Output

``````
{
  "region-name": [
    {
      "bucket_name": "s3-bucket-name",
      "result": "Block Public Access enabled successfully."
    },
    {
      "bucket_name": "s3-bucket-name",
      "result": "Block Public Access enabled successfully."
    }
  ]
}
``````
