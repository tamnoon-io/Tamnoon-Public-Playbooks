
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Ec2 - Get all Flow logs.

## Description
This playbook describes how to execute Tamnoon EC2Helper automation to get all flow logs of a security group.

The automation attempts to collect information about inbound traffic to the members of any given Security Group. It does so by  

   (i) identifying the ENIs associated with that Security Group
   
   (ii) identifying the Flowlog associated with these ENIs
   
   (iii) identifying the Cloudwatch log group associated with that flowlog
   
   (iv) querying in Cloudwatch that log group and summarizing the infromation by source IP and destination port.

For each Security Group for which this process succeeded, it outputs a json file with that information.
At the end of its run, it also writes an output file for the run itself that for each security group says if information was retrieved and to which file it was saved.
The success of this automation depends on the existence of flowlogs that log traffic for the security group members, and their availability within log groups in Cloudwatch.
Follow [Tamnoon Playbook: Ec2 - Create VPC FLowlog](./TPlaybbok_create_vpc_flowlog.md) to enable creation of flow logs. 

The execution is based on AWS credentials configuration based on the next fallbacks:
1. If AWS profile or aws access key and secret were given, use it as an AWS credentials source.
2. If no profile, use as environment variable credentials for aws.
3. If not environmental variables provided, use the current ./~aws configuration

After authentication via AWS API, the script execution will run on the same AWS account of those credentials defined in fallbacks 1-3 (see above)

## Playbook steps:
1. Clone the AWS folder from  [Tamnoon-Public-Playbooks](https://github.com/tamnoon-io/Tamnoon-Public-Playbooks)
   ```
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/AWS
      git checkout
   ```
2. Execute the automation from AWS directory
   1. Using CLI parameters:
   ```
   python -m Automations.EC2Actions.EC2Helper --profile <aws_profile> --type security-group --action get_all_flow_logs  --regions <The region/s to works on or "all"> --assetIds <comma-separated list of SG Ids or "all"> --actionParams <see below>
   ```
    or 
   ```
   python -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --type security-group --action get_all_flow_logs  --regions <The region/s to works on "all"> --assetIds <comma-separated list of SG Ids or "all"> --actionParams <see below>
   ``` 
    or 
   ```
   python -m Automations.EC2Actions.EC2Helper --awsAccessKey <aws_access_key> --awsSecret <aws_secret> --awsSessionToken <specific session token> --type security-group --action get_all_flow_logs  --regions <The region/s to works on or "all"> --assetIds <comma-separated list of SG Ids or "all"> --actionParams <see below>
   ```
         

    ### actionParams:
    The ActionParams parameter provides the automation with parameters that are specific to the action taken. In this case get_all_flow_logs. 
    In general, the value of the ActionParams parameter is one, single-quoted text string that specifies a json. 
    ```
    '{"param1key": "param1value", "param2key": "param2value"}'
    ```
    There are two optional action parameters associated with the action get_all_flow_logs:
    1. exclude_private_ips_from_source (Optional)(boolean) - Flag to sign if need to find flow logs to &/or from only public IPs. Default is true.
    2. hoursback - (Optional)(number) - Number of past hours to search the logs from current time. Default is 720 hours (30 days)
    3. exclude_src_ports - comma-separated list of source ports that should be filtered out when fetching flowlogs (note that source ports smaller than 1024 are already filtered out)
    
    ```
    '{"exclude_private_ips_from_source": "True", "hoursback": "720","exclude_src_ports":"8443,8444"}'
    ```
## Prerequisites 
1. Executing the script requires a role with permissions to discover log groups and query them.
   [logs:DescribeLogGroups, logs:DescribeLogStreams, logs:StartQuery. logs:GetQueryResults](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html)

2. Python v3.9  and above + boto3 package installed ( pip install boto3)


