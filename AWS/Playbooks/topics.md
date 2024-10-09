

### alb - 	redirect_to_https
[TPlaybook_alb_redirect_to_https.md](../Playbooks/EC2Actions/TPlaybook_alb_redirect_to_https.md)
  
**Topics** - Application Load Balancer, EC2, Forward, HTTP, HTTPS, Load Balancer, Redirect

This automation describes how to execute Tamnoon automation to change Application Load Balancer listener actions rules that **forward** http (port 80) requests to https (port 443). Modified rules will **redirect** similar requests from http (port 80) to https (port 443) instead. This automation will also update default action of such listener with similar redirect action.  
### cloudtrail - 	no-action
[TImpact_cloudtrail.md](../Playbooks/LogsInvestigations/TImpact_cloudtrail.md)
  
**Topics** - cloudtrail, trails logs, athena

This automation describes how to execute Tamnoon Logs Investigation automation to find cloudtrail trail logs stored in s3 bucket. This is done
by finding QueryFieldName & its Value from s3 bucket of cloudtrail trail. This automation supports finding activity from the day s3 bucket configured for storing CloudTrail trail logs *to at least 0.01 recent days (~ 15 recent minutes).*  
### describe-stack-resources - 	is_created_by_cfn
[TImpact_CloudFormation_describe_stack_resources_is_created_by_cfn.md](../Playbooks/CloudFormation/TImpact_CloudFormation_describe_stack_resources_is_created_by_cfn.md)
  
**Topics** - cloudformation, ec2 instance, s3 bucket,lambda functions,ecs,ebs, arn, cloudformation stack

This automation describes how to execute Tamnoon CloudFormation automation to determine whether the provided resource arn is deployed by CloudFormation stack and also determines the associations/relationships for resource arns of type Elatic Beanstalk, EC2 AutoScaling Groups etc.  
### describe-stack-resources - 	security_groups
[TImpact_CloudFormation_describe_stack_resources_security_groups.md](../Playbooks/CloudFormation/TImpact_CloudFormation_describe_stack_resources_security_groups.md)
  
**Topics** - cloudformation, security groups, cloudformation stack

This automation describes how to execute Tamnoon CloudFormation automation to determine whether the provided security group is deployed by a CloudFormation stack and to provide details about resources deployed by the stack.  
### ebs - 	encryption
[TPlaybook_ebs_encryption.md](../Playbooks/EBSEncryption/TPlaybook_ebs_encryption.md)
  
**Topics** - EBS, Encryption, AWS EBS Service

This playbook describes how to remediate unencrypted EBS Volumes automatically. 
Amazon EBS encrypted volumes provide an additional layer of data protection by securing your data from unauthorized access to the underlying storage.
You can use Amazon EBS encryption to increase the data protection of your applications deployed in the cloud and to fulfill compliance requirements for encryption at rest.  
### ec2 - 	enforce_imdsv2
[TPlaybook_ec2_enforce_imdsv2.md](../Playbooks/EC2Actions/TPlaybook_ec2_enforce_imdsv2.md)
  
**Topics** - EC2, IMDSv2, Switch to IMDSv2

This playbook describes how to execute Tamnoon EC2Helper automation to switch for using IMSDv2 instead of v1.  
### ec2 - 	find_load_balancers
[TImpact_ec2_find_load_balancers.md](../Playbooks/EC2Actions/TImpact_ec2_find_load_balancers.md)
  
**Topics** - EC2, Load Balancers, Find Load Balancers

A load balancer distributes incoming network traffic across multiple servers to ensure optimal resource utilization, enhance reliability, and mitigate server overload. It helps maintain high availability and scalability of web applications or services.  
This playbook describes how to execute Tamnoon AWS type ec2 instance and action find-load-balancers to get details of  load balancer associated with provided ec2 instance ids.  
### ec2 - 	get_imdsv1_usage
[TImpact_ec2_get_imdsv1_usage.md](../Playbooks/EC2Actions/TImpact_ec2_get_imdsv1_usage.md)
  
**Topics** - EC2, IMDSv1, IMDSv1 usage, MetadataNoToken, CloudWatch

Before configuring an EC2 instance to require it to use IMDSv2 and prevent it from using IMDSv1, it's important to determine if in the recent past the instance made any calls to IMDSv1. If it has not called IMDSv1, then the road is clear to prevent it from using it, without breaking anything. However, if it has been calling it, it's important to identify and upgrade the components that are making such calls before preventing the use of it. This automation determines the use of IMDSv1. It uses AWS Cloudwatch metric ["MetadatanoToken"](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html#ec2-cloudwatch-metrics) to count for each instance the number of times it made calls to the insecure ("token-less") IMDSv1.  
This automation provides the investigative part of handling alerts about the use of IMDSv1. [TPlaybook_set_IMDSv2.md](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md) provides remediation for such alerts by preventing the use of IMDv1.  
This automation is same as querying the CloudWatch metric MetadataNoToken on AWS portal as follows.  

1. Under CloudWatch, open All metrics

2. Choose EC2

3. Then choose "Per-Instance Metrics"

4. Change the timeframe to be 2W

All Instances that this metric is 0 for them are found by this Automation, for which we can enable IMDSv2 using [IMDSv2 Automation](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md).  
### events-history - 	no-action
[TImpact_events_history.md](../Playbooks/LogsInvestigations/TImpact_events_history.md)
  
**Topics** - Events History, LookUpEvents API, SDK API

This automation describes how to execute Tamnoon Logs Investigation automation to find events history of cloudtrail. This is done
by finding AttributeKey & its AttributeValue from events history of cloudtrail. This automation supports finding activity from *at most 90 recent days* to *at least 0.01 recent days (~ 15 recent minutes)*.  
### iam-user - 	deactivate_access_key
[TPlaybook_IAMUser_deactivate_user_access_key.md](../Playbooks/IAMActions/TPlaybook_IAMUser_deactivate_user_access_key.md)
  
**Topics** - IAM Users, IAMUser Deactivate Access Key, AWS IAM Service

This playbook describes how to execute Tamnoon IAMHelper automation to deactivate AccessKeys.  
### iam-user - 	delete
[TPlaybook_delete_IAMUser.md](../Playbooks/IAMActions/TPlaybook_delete_IAMUser.md)
  
**Topics** - IAM, Delete IAMUser, AWS IAM Service

This playbook describes how to execute Tamnoon IAMHelper automation to delete IAM User.  
### iam-user - 	last_activity
[TImpact_last_activity_IAMUser.md](../Playbooks/IAMActions/TImpact_last_activity_IAMUser.md)
  
**Topics** - IAM, Last Activity of IAMUsers, AWS IAM Service

This playbook describes how to execute Tamnoon IAMHelper automation to describe last activity of IAMUser.  
### iam-user - 	ls
[TImpact_list_IAMUser.md](../Playbooks/IAMActions/TImpact_list_IAMUser.md)
  
**Topics** - IAM, List IAMUsers, AWS IAM Service

This playbook describes how to execute Tamnoon IAMHelper automation to list IAM Users available in AWS account.  
### iam-user - 	remove_console_access
[TPlaybook_IAMUser_remove_console_access.md](../Playbooks/IAMActions/TPlaybook_IAMUser_remove_console_access.md)
  
**Topics** - IAM Users, IAMUser Remove Console Access, AWS IAM Service

This playbook describes how to execute Tamnoon IAMHelper automation to remove IAM User console access.  
### rds - 	deletion_protection
[TPlaybook_rds_deletion_protection.md](../Playbooks/RDSActions/TPlaybook_rds_deletion_protection.md)
  
**Topics** - RDS(Relational Database Service), RDS Deletion Protection Configuration, AWS RDS Service

This playbook describes how to execute Tamnoon RDSHelper automation to enable database instance deletion protection configration.  
### s3 - 	block_http
[TPlayBook_S3_deny_http_access.md](../Playbooks/S3Actions/TPlayBook_S3_deny_http_access.md)
  
**Topics** - S3, Block HTTP, HTTP Access to S3 Bucket

This playbook describes how to execute Tamnoon S3 soft configuration automation to add deny policy for HTTP access.
  
### s3 - 	check_public_access
[TImpact_S3_check_public_access.md](../Playbooks/S3Actions/TImpact_S3_check_public_access.md)
  
**Topics** - S3, Public Access, Access Configuration

This playbook describes how to execute Tamnoon S3 automation to find which s3 buckets have public access.
  
This automation investigates policies and ACLs of S3 buckets that can allow public access to the buckets.  

- Buckets are considered public if they have some policy that allows action `s3:ListBucket` or `s3:*` to Principal `*` and having resource as the bucketName. For more details on policies, follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html).  Similarly, if buckets have similar policy but only with effect `Deny`, then irrespective of other policies, it will be denied access by public.

- It is possible for buckets to be public if they have some ACLs that allows for `READ` or `FULL_CONTROL` permission given to Everyone (`https://acs.amazonaws.com/groups/global/AllUsers`). For more details on ACLs, follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acls.html).

- Buckets that are public can be blocked for public access by Bucket Level Block Public Access and Account Level Block Public Access.

	- Block Public Access (BPA) is made of four values, out of which, two values are used for blocking public access of s3 buckets:

		- IgnorePublicAcls - ignores all the ACLs that are defined on the bucket and blocks the public access to the bucket, if it has been allowed via ACLs.

		- RestrictPublicBuckets - ignores all policies that are defined on the bucket and blocks the public access to the bucket, if it has been allowed via policies. It additionally reduces the previous public access - that is if any account could access this bucket previously, it will now allow to the accounts only from same organization as that of bucket owner.
	Bucket level BPA will take precedence for Account level first, then Bucket level.  

- For more details of BlockPublicAccess follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).
### s3 - 	configure_public_access
[TPlayBook_S3_block_public_access.md](../Playbooks/S3Actions/TPlayBook_S3_block_public_access.md)
  
**Topics** - S3, Block Public Access, Block Public Access Configuration

This playbook describes how to execute Tamnoon S3 soft configuration automation to block public access.
  
### s3 - 	encryption
[TPlayBook_S3_enable_encryption.md](../Playbooks/S3Actions/TPlayBook_S3_enable_encryption.md)
  
**Topics** - S3, Encryption, S3 Bucket Encryption

This playbook describes how to execute Tamnoon S3 soft configuration automation to enable bucket encryption.
  
### s3 - 	mfa_protection
[TPlayBook_S3_enable_mfa_protection.md](../Playbooks/S3Actions/TPlayBook_S3_enable_mfa_protection.md)
  
**Topics** - S3, MFA, MFA Protection

This playbook describes how to execute Tamnoon S3 soft configuration automation to enable bucket mfa delete protection.
  
### s3 - 	server_logging
[TPlayBook_S3_enable_server_logging.md](../Playbooks/S3Actions/TPlayBook_S3_enable_server_logging.md)
  
**Topics** - S3, Server Logging, S3 Server Logging

This playbook describes how to execute Tamnoon S3 soft configuration automation to enable server logging.
  
### s3 - 	versioning
[TPlayBook_S3_enable_versioning.md](../Playbooks/S3Actions/TPlayBook_S3_enable_versioning.md)
  
**Topics** - S3, Server Versioning, S3 Server Versioning

This playbook describes how to execute Tamnoon S3 soft configuration automation to enable bucket versioning.
  
### security-group - 	clean_unused_sg
[TPlaybook_security_group_clean_unused.md](../Playbooks/EC2Actions/TPlaybook_security_group_clean_unused.md)
  
**Topics** - Security Group, Unused Security Group, Delete Security Group, Clean Security Group, Default Security Group, Delete by tag

This playbook describes how to remove inbound/outbound rules of unused security group. This is first step of overall cleanup security groups process. While second step can be found [here](./TPlaybook_security_group_delete.md).  
### security-group - 	delete
[TPlaybook_security_group_delete.md](../Playbooks/EC2Actions/TPlaybook_security_group_delete.md)
  
**Topics** - Security Group, Delete Security Group

This playbook describes how to execute Tamnoon AWS EC2Helper automation to delete the security groups. This can also be treated as second step of cleaning up security groups. The first step of removing inbound/outbound rules from security groups can be found [here](./TPlaybook_security_group_clean_unused.md).  
### security-group - 	get_all_flow_logs
[TImpact_security_group_get_all_flow_logs.md](../Playbooks/EC2Actions/TImpact_security_group_get_all_flow_logs.md)
  
**Topics** - Security Group, Flow Logs, CloudWatch, Network, Exclude Private IPs, Exclude Ports

This playbook describes how to execute Tamnoon EC2Helper automation to get all flow logs of a security group.  
The automation attempts to collect information about inbound traffic to the members of any given Security Group. It does so by  

5. identifying the ENIs associated with that Security Group

6. identifying the Flowlog associated with these ENIs

7. identifying the Cloudwatch log group associated with that flowlog

8. querying in Cloudwatch that log group and summarizing the infromation by source IP and destination port.

For each Security Group for which this process succeeded, it outputs a json file with that information. At the end of its run, it also writes an output file for the run itself that for each security group says if information was retrieved and to which file it was saved. The success of this automation depends on the existence of flowlogs that log traffic for the security group members, and their availability within log groups in Cloudwatch. Follow [Tamnoon Playbook: Ec2 - Create VPC FLowlog](./TPlaybook_vpc_create_flow_log.md) to enable creation of flow logs.  
### security-group - 	get_usage
[TImpact_security_group_get_usage.md](../Playbooks/EC2Actions/TImpact_security_group_get_usage.md)
  
**Topics** - Security Group, Security Group Usage, Associations, Network Interfaces, Lambda Functions, VPC Configs

This playbook describes how to execute Tamnoon EC2Helper automation to get security group usage, i.e., if security group is being used or not by finding its associations with network interfaces, lambda functions, VPC configs, etc.  
### security-group - 	remove_or_replace_rules
[TPlaybook_security_group_remove_or_replace_rules.md](../Playbooks/EC2Actions/TPlaybook_security_group_remove_or_replace_rules.md)
  
**Topics** - Security Group, Remove Inbound Rules, Remove Oubound Rules, Replace Inbound Rules, Replace Oubound Rules, IPs, CIDRs, Ports

This playbook describes how to execute Tamnoon EC2Helper automation to remove or replace rules in security groups.  
### snapshot - 	delete
[TPlaybook_snapshot_delete.md](../Playbooks/EC2Actions/TPlaybook_snapshot_delete.md)
  
**Topics** - EC2, EBS, Snapshot, Delete Snapshot

This playbook describes how to execute Tamnoon EC2Helper automation to delete EBS Snapshot.  
### snapshot - 	encrypt
[TPlaybook_snapshot_encrypt.md](../Playbooks/EC2Actions/TPlaybook_snapshot_encrypt.md)
  
**Topics** - EC2, EBS, Snapshot, Encrypt Snapshot

This playbook describes how to execute Tamnoon EC2Helper automation to encrypt EBS Snapshot.  
### snapshot - 	ls
[TPlaybook_snapshots_list.md](../Playbooks/EC2Actions/TPlaybook_snapshots_list.md)
  
**Topics** - EC2, EBS, Snapshot, List Snapshot

This playbook describes how to execute Tamnoon EC2Helper automation to list EBS Snapshot.  
### subnet - 	disable_public_ip_assignment
[TPlaybook_subnet_disable_public_ip_assignment.md](../Playbooks/EC2Actions/TPlaybook_subnet_disable_public_ip_assignment.md)
  
**Topics** - VPC, Subnet, Disable Public IP Assignment, Turn Off Public IP Assignment

This playbook describes how to execute Tamnoon EC2Helper automation to turn off automatic public IP address assignments.  
### vpc - 	create_flow_log
[TPlaybook_vpc_create_flow_log.md](../Playbooks/EC2Actions/TPlaybook_vpc_create_flow_log.md)
  
**Topics** - VPC, Flow Log, Create Flow Log

This playbook describes how to execute Tamnoon EC2Helper automation to enable and create VPC flow logs.  
