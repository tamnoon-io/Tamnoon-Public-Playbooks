
[comment]: <> (This is a readonly file, do not edit directly, to change update the rds_deletion_protection_readme_data.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: RDS - Enable RDS Instance Deletion Protection.
## Description

This playbook describes how to execute Tamnoon RDSHelper automation to enable database instance deletion protection configration.  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. AWS credentials defined on the execution machine with permission to change SecurityGroups.
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
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of DBInstanceIdentifiers> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of DBInstanceIdentifiers> \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of DBInstanceIdentifiers> \
		--dryRun <optional dry run>
		``````
		For RollBack :  
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--profile <aws_profile> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of DBInstanceIdentifiers> \
		--actionParams '{"rollBack": true}' \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of DBInstanceIdentifiers> \
		--actionParams '{"rollBack": true}' \
		--dryRun <optional dry run>
		``````
		or  
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--awsSessionToken <aws_session_token> \
		--regions <The region/s to works on> \
		--assetIds <comma separated list of DBInstanceIdentifiers> \
		--actionParams '{"rollBack": true}' \
		--dryRun <optional dry run>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--file path-to-yml-file
		``````
		And the contents of yml/yaml file would look like  
		``````yaml
		profile: tamnoon-profile
		regions:
		  - region-1 
		  - region-2
		  - region-3
		assetIds:
		  - rds-dbinstance-1
		  - rds-dbinstance-2
		  - rds-dbinstance-3
		``````
		For RollBack :  
		``````yaml
		profile: tamnoon-profile
		regions:
		  - region-1
		  - region-2
		  - region-3
		assetIds:
		  - rds-dbinstance-1
		  - rds-dbinstance-2
		  - rds-dbinstance-3
		actionParams:
		  rollBack: true
		``````

	2. Using JSON file: a json file is a text file with a "json" extension whose execution command is in the format:
		``````sh
		python3 -m Automations.RDSActions \
		rds \
		deletion_protection \
		--file path-to-json-file
		``````
		And the contents of json file would look like  
		``````json
		{
		  "profile": "tamnoon-profile",
		  "regions": [
		    "region-1",
		    "region-2",
		    "region-3"
		  ],
		  "assetIds": [
		    "rds-dbinstance-1",
		    "rds-dbinstance-2",
		    "rds-dbinstance-3"
		  ]
		}
		``````
		For RollBack :  
		``````json
		{
		  "profile": "tamnoon-profile",
		  "regions": [
		    "region-1",
		    "region-2",
		    "region-3"
		  ],
		  "assetIds": [
		    "rds-dbinstance-1",
		    "rds-dbinstance-2",
		    "rds-dbinstance-3"
		  ],
		  "actionParams": {
		    "rollBack": true
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
List of Regions used to find rds database instance. If not used, default region is us-east-1.
### assetIds - (Required)
Comma separated list rds database instances.
### actionParams - (Optional)
1. rollBack - Boolean flag to sign if this is a rollback call. It disables deletion protection for rds database instance.
## Sample Output

``````
{
  "region-name": {
    "rds-db-instance-1": {
      "deletion_protection": "Enabled deletion protection for instance."
    }
  }
}
``````
For DryRun :  
``````
{
  "region-name": {
    "rds-db-instance-1": {
      "deletion_protection": "Dry Run - Enable deletion protection for instance. Nothing Executed!!"
    }
  }
}
``````
For RollBack :  
``````
{
  "region-name": {
    "rds-db-instance-1": {
      "deletion_protection": "Roll Back - Disabled deletion protection for instance."
    }
  }
}
``````
