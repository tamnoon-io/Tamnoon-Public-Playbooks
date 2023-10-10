
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Switch to use IMDSv2 for EC2.

## Description
This impact script describes how to investigate the impact of playbook [IMDSv2](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md) TPlaybook_set_IMDSv2.md execution 


## Impact investigation steps:
1. Query the CloudWatch metric MetadataNoToken.
   1. Under CloudWatch, open All metrics
   2. Chose EC2
   3. Then choose “Per-Instance Metrics”
   4. Change the timeframe to be 2W
   4. All Instances that this metric is 0 for them can be remediated using this playbook, The rest need further investigation

    


