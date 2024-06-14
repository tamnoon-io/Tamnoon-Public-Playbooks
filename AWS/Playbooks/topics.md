

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

For each Security Group for which this process succeeded, it outputs a json file with that information. At the end of its run, it also writes an output file for the run itself that for each security group says if information was retrieved and to which file it was saved. The success of this automation depends on the existence of flowlogs that log traffic for the security group members, and their availability within log groups in Cloudwatch. Follow [Tamnoon Playbook: Ec2 - Create VPC FLowlog](./TPlaybbok_create_vpc_flowlog.md) to enable creation of flow logs.  
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
