
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Investigation Playbook: Ec2 - Switch to use IMDSv2 for EC2.

## Description
Before configuring an EC2 instance to require it to use IMDSv2 and prevent it from using IMDSv1, it's important to determine if in the recent past the instance made any calls to IMDSv1. If it has not called IMDSv1, then the road is clear to prevent it from using it, without breaking anything. However, if it has been calling it, it's important to identify and upgrade the components that are making such calls before preventing the use of it. This automation determines the use of IMDSv1. It uses AWS Cloudwatch metric ["MetadatanoToken"](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html#ec2-cloudwatch-metrics) to count for each instance the number of times it made calls to the insecure ("token-less") IMDSv1.
This automation provides the investigative part of handling alerts about the use of IMDSv1. [TPlaybook_set_IMDSv2.md](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md) provides remediation for such alerts by preventing the use of IMDv1.

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

This automation is same as querying the CloudWatch metric MetadataNoToken on AWS portal as follows.
   1. Under CloudWatch, open All metrics
   2. Chose EC2
   3. Then choose “Per-Instance Metrics”
   4. Change the timeframe to be 2W
   4. All Instances that this metric is 0 for them are found by this Automation, for which we can enable IMDSv2 using [IMDSv2 Automation](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks/blob/main/AWS/EC2/TPlaybook_set_IMDSv2.md).



## Impact investigation steps:
1. Clone the AWS folder from  [Tamnoon-Public-Playbooks](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks)
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Public-Playbooks.git
      git sparse-checkout set AWS
      git checkout

   ``````  
2. Execute the automation from AWS directory
   1. Using CLI parameters:  
   ```
      python3 -m Automations.EC2Actions.EC2Helper --profile <aws_profile> --type ec2 --action get_imdsv1_usage --regions <The region/s to works on> --assetIds <comma separated list of instances to remediate or all>  --actionParams <The action params >
   ```  
   or  
   ```
      python3 -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type ec2 --action get_imdsv1_usage --regions <The region/s to works on> --assetIds <comma separated list of instances to remediate or all>  
   ```  
   or  
   ```
      python3 -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --awsSessionToken <specific session token> --type ec2 --action get_imdsv1_usage --regions <The region/s to works on> --assetIds <comma separated list of instances to remediate or all>  
   ```  

### This play book support actionParams - Below is description of what value it can take      
1. days - (Optional) - The past duration to find the IMDSv1 usage before current time. Default value 14 days. Example,
   ```
   --actionParams '{"days": 90}'  
   ```  
    

## Prerequisites 
1. AWS cretentials defined on the execution machine with permission to ec2::describeInstances
2. Python v3.8  and above + boto3 package installed ( pip install boto3)



