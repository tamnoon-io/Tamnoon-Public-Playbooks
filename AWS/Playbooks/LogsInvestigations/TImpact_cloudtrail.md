
[comment]: <> (This is a readonly file, do not edit directly, to change update the cloudtrail_data_readme.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Investigation Playbook: IAM - Cloudtrail.
## Description

This automation describes how to execute Tamnoon Logs Investigation automation to find cloudtrail trail logs stored in s3 bucket. This is done
by finding QueryFieldName & its Value from s3 bucket of cloudtrail trail. This automation supports finding activity from the day s3 bucket configured for storing CloudTrail trail logs *to at least 0.01 recent days (~ 15 recent minutes).*  
## Prerequisites
1. Python v3.9 and above + boto3 package installed (pip install boto3).  
2. The authentication is based on AWS credentials configuration with the following fallbacks:  
    1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.  
    2. If no profile, use as environment variable credentials for aws.  
    3. If not environmental variables provided, use the current ./~aws configuration  

    After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above).


3. CloudTrail Trail must be configured with s3 bucket available in given region.

4. AWS credentials should have permission to following actions for querying cloudtrail logs :

	1. cloudtrail:DescribeTrails

	2. athena:StartQueryExecution

	3. athena:GetQueryExecution

	4. athena:GetQueryResults

	5. athena:StopQueryExecution

	6. s3:ListBucket

	7. s3:DeleteObject
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
		cloudtrail \
		--profile <aws_profile> \
		--assetIds <trail-name> \
		--regions <comma separated list of regions or all> \
		--actionParams <dictionary with the specific action params>
		``````
		or  
		``````
		python3 -m Automations.LogsInvestigation \
		cloudtrail \
		--awsAccessKey <aws_access_key> \
		--awsSecret <aws_secret> \
		--assetIds <trail-name> \
		--regions <comma separated list of regions or all> \
		--actionParams <dictionary with the specific action params>
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		assetIds: <trail_name>
		awsAccessKey: <aws_access_key>
		awsSecret: <aws_secret>
		regions:
		  - ap-southeast-2
		  - us-east-1
		  - us-east-2
		actionParams:
		  eventname: <event-name>
		  days: 0.25
		logLevel: INFO
		outputType: json
		outDir: ../../../logs
		testId: test-case-description
		
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.LogsInvestigation \
		cloudtrail \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "assetIds": "<trail_name>",
		  "awsAccessKey": "<aws_access_key>",
		  "awsSecret": "<aws_secret>",
		  "regions": [
		    "ap-southeast-2",
		    "us-east-1",
		    "us-east-2"
		  ],
		  "actionParams": {
		    "eventname": "<event-name>",
		    "days": 0.25
		  },
		  "logLevel": "INFO",
		  "outputType": "json",
		  "outDir": "../../../logs",
		  "testId": "test-case-description"
		}
		
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.LogsInvestigation \
		cloudtrail \
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
### assetIds - (Required)
This contains Cloudtrail Trail Name
### actionParams - (Required)
- QueryFieldName: QueryFieldName Key supported by athena table schema. Automation will find the logs for this QueryFieldName. There is no default value.

    example:  
    ```cli
    --actionParams '{"QueryFieldName": ['value1', 'value2', ...]}'
    ``` 
-  QueryFieldName can be replaced by any of the supported QueryFieldNames displayed below.
    ```cli 
    --actionParams '{"eventname": ['eventname-1', 'eventname-2', ...]}'
    ```
- QueryFieldNames such as  *useridentity*, *additionaleventdata*, *resources* and *tlsdetails* contains sub-fields so to match those. You need to use *.* operator as shown below. 
    example:  
    ```cli
    --actionParams '{"useridentity.username": "<value>"}'
    ```
  OR
    ```cli
    --actionParams '{"useridentity.username": ['value1', 'value2', ...]}'
    ```
Note : While filtering using resources , one additional key named filtered_resource is added into the result json file each record. filtered_resource is the filter resource arn provided in actionParams.
    
- days: number of recent days. Automation will find the event history for this given duration between now and N days ago as given in actionParams. Default value is 90.

    example:  
    ```cli
    --actionParams '{"days": "15"}'
    ```  
- cleanup: To delete the generated tables, s3 bucket output logs.

    example:  
    ```cli
    --actionParams '{"cleanup": true}'
    ```  
  For more details, follow [TImpact_cloudtrail.md](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/Playbooks/LogsInvestigations/TImpact_cloudtrail.md)
## References

Supported QueryFieldNames are listed here:  
``````
    -   eventname
    -   eventsource
    -   awsregion
    -   sourceipaddress
    -   errorcode
    -   errormessage
    -   useridentity
        1. type 
        2. principalid
        3. arn
        4. accountid
        5. invokedby
        6. accesskeyid
        7. username
    -   eventtype  
    -   readonly
    -   recipientaccountid 
    -   vpcendpointid 
    -   additionaleventdata
        1. SignatureVersion
        2. CipherSuite
        3. bytesTransferredIn
        4. AuthenticationMethod
        5. x-amz-id-2
        6. bytesTransferredOut
    -   resources
        1. arn
        2. type
    -   requestparameters
        1. bucketName 
        2. Host
        3. key
    -   responseelements 
        1. x-amz-server-side-encryption-aws-kms-key-id
        2. x-amz-server-side-encryption
        3. x-amz-server-side-encryption-context
    -   tlsdetails
        1. tlsversion
        2. ciphersuite
        3. clientprovidedhostheader

``````

- To know more about fields and what values can be used to query the fields follow [Cloudtrail Event Reference Record Contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

- Please find list of eventnames [here](https://gist.github.com/pkazi/8b5a1374771f6efa5d55b92d8835718c)
