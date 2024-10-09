# Do not edit this file directly. To make changes, update the associated json files that are located in CloudFormation.

describe_stack_resources_security_groups= {'help': 'This action determines whether the security group id was deployed as part of a CloudFormation stack and, if so, describes the resources deployed in the stack.', 'cli_args': {'profile': 'Use the aws profile for setting up session during automation.', 'awsAccessKey': 'Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.', 'awsSecret': 'Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.', 'awsSessionToken': 'Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey.', 'regions': "List of regions. If not given, the default value is 'all', i.e., the remedy will evaluate all the Security Groups without checking their regions.", 'assetIds': "List of security group IDs.If not given, the default value is 'all', i.e., the remedy will evaluate all the Security Groups in given regions.", 'file': 'The path to a yml/json file that contain all the script input parameters.', 'outputType': 'The type of output of script execution. available options are json (default) and csv', 'outDir': 'The path to store output of script execution. The default is the current working directory.', 'logLevel': 'Used to categorize and prioritize log levels based on severity or importance. Its values can be INFO, DEBUG, WARNING, ERROR, or CRITICAL. The default value is INFO.', 'testId': 'Description for test to be executed'}}

describe_stack_resources_is_created_by_cfn= {'help': 'This action helps to determine whether the provided resource arn is deployed by CloudFormation stack and also determines the associations/relationships for resource arns of type Elastic Beanstalk, EC2 AutoScaling Groups etc.', 'cli_args': {'profile': 'Use the aws profile for setting up session during automation.', 'awsAccessKey': 'Use the aws access key for setting up session during automation. This must be accompanied by --awsSecret.', 'awsSecret': 'Use the aws secret key for setting up session during automation. This must be accompanied by --awsAccessKey.', 'awsSessionToken': 'Use the short term session token for setting up session during automation. This must be accompanied by --awsSecret and --awsAccessKey.', 'regions': "List of regions. If not given, the default value is 'all', i.e., the remedy will evaluate all provided resource arns irrespective of there regions.", 'assetIds': 'Single or List of resource arns.If not provided, there is no default value.', 'actionParams': '- for the automation *Determine If EC2 Instance Created By AutoScaling Groups is Part of CloudFormation, Use*\n\t```\n\t--actionParams = \'{"include-asg": true}\'\n\t``` \n\n- for the automation *Determine If EC2 Instance Created By AutoScaling Groups Created By Elastic Beanstalk is Part of CloudFormation, Use*\n\t```\n\t--actionParams = \'{"include-asg": true, "include-ebs": true}\'\n\t```', 'file': 'The path to a yml/json file that contain all the script input parameters.', 'outputType': 'The type of output of script execution. available options are json (default) and csv', 'outDir': 'The path to store output of script execution. The default is the current working directory.', 'logLevel': 'Used to categorize and prioritize log levels based on severity or importance. Its values can be INFO, DEBUG, WARNING, ERROR, or CRITICAL. The default value is INFO.', 'testId': 'Description for test to be executed'}}

common_json_data= {'help': {'EC2Actions': {'snapshot': 'An EBS snapshot is a point-in-time, incremental backup of an Amazon Elastic Block Store (EBS) volume stored in Amazon S3, allowing restoration of the volume to its exact state at the time of the snapshot.', 'security-group': 'An AWS Security Group acts as a virtual firewall that controls inbound and outbound traffic to AWS resources within a Virtual Private Cloud (VPC) based on specified security rules.', 'vpc': 'An AWS Virtual Private Cloud (VPC) is a customizable network environment that allows users to launch AWS resources in a logically isolated, secure section of the AWS Cloud.', 'ec2': 'Amazon EC2 (Elastic Compute Cloud) is a web service that provides resizable compute capacity in the cloud, allowing users to run virtual servers to host applications and services.', 'subnet': "An AWS Subnet is a segment of a VPC's IP address range where you can place groups of isolated resources based on security and operational needs within a larger VPC network.", 'alb': 'An Application Load Balancer is an Elastic Load Balancing service provided by AWS that functions at the application layer, the seventh layer of the Open Systems Interconnection (OSI) model.'}, 'CloudFormation': {'describe-stack-resources': 'Determines whether the resource is part of a CloudFormation stack. If so, the results describe all resources deployed by the CloudFormation stack.'}, 'RDSActions': {'rds': 'Amazon Relational Database Service (Amazon RDS) is an easy-to-manage relational database service optimized for total cost of ownership. It is simple to set up, operate, and scale with demand. Amazon RDS automates the undifferentiated database management tasks, such as provisioning, configuring, backups, and patching'}, 'IAMActions': {'iam-user': 'An AWS Identity and Access Management (IAM) user is an entity that you create in AWS. The IAM user represents the human user or workload who uses the IAM user to interact with AWS. A user in AWS consists of a name and credentials.'}, 'S3Actions': {'s3': 'Amazon Simple Storage Service (Amazon S3) is an object storage service that offers industry-leading scalability, data availability, security, and performance.S3 is used to store and protect any amount of data for a range of use cases, such as data lakes, websites, mobile applications, backup and restore, archive, enterprise applications, IoT devices, and big data analytics.'}, 'LogsInvestigation': {'cloudtrail': 'AWS CloudTrail is an AWS service that helps you enable operational and risk auditing, governance, and compliance of your AWS account. Actions taken by a user, role, or an AWS service are recorded as events in CloudTrail. The recorded events are stored in S3 bucket and queried using athena.', 'events-history': 'The Event history provides a viewable, searchable, downloadable, and immutable record of the past 90 days of management events in an AWS Region'}}, 'usage': {'EC2Actions': 'python3 -m Automations.EC2Actions', 'CloudFormation': 'python3 -m Automations.CloudFormation', 'S3Actions': 'python3 -m Automations.S3Actions', 'IAMActions': 'python3 -m Automations.IAMActions', 'RDSActions': 'python3 -m Automations.RDSActions', 'EBS_Encryption': '', 'LogsInvestigation': 'python3 -m Automations.LogsInvestigation'}}
