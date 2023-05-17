import argparse
import json
import logging
import sys
import boto3
import botocore.exceptions


def log_setup(log_l):
    """This method setup the logging level an params
        logs output path can be controlled by the log stdout cmd param (stdout / file)
    """
    logging.basicConfig(format='[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s')
    log_level = log_l
    logging.getLogger().setLevel(log_level)


def print_help():
    text = (
        '\n'
        '\n '
        '''

\t\t\t ___                                                                                           
\t\t\t(   )                                                                            .-.           
\t\t\t | |_       .---.   ___ .-. .-.    ___ .-.     .--.     .--.    ___ .-.         ( __)   .--.   
\t\t\t(   __)    / .-, \ (   )   '   \  (   )   \   /    \   /    \  (   )   \        (''")  /    \  
\t\t\t | |      (__) ; |  |  .-.  .-. ;  |  .-. .  |  .-. ; |  .-. ;  |  .-. .         | |  |  .-. ; 
\t\t\t | | ___    .'`  |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | |(   )  / .'| |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | | | |  | /  | |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | ' | |  ; |  ; |  | |  | |  | |  | |  | |  | '  | | | '  | |  | |  | |   .-.   | |  | '  | | 
\t\t\t ' `-' ;  ' `-'  |  | |  | |  | |  | |  | |  '  `-' / '  `-' /  | |  | |  (   )  | |  '  `-' / 
\t\t\t  `.__.   `.__.'_. (___)(___)(___)(___)(___)  `.__.'   `.__.'  (___)(___)  `-'  (___)  `.__.'  

        '''
        '\t\t Welcome To Tamnoon EC2 Helper- The script that will help you with your EC2 Service Actions \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t Authentication:\n'
        '\t\t\t\t The script support the fallback mechanism auth as AWS CLI\n'
        '\t\t\t\t\t profile - send the aws profile as input parameter\n'
        '\t\t\t\t\t key and secret - send the aws key and secret as input parameter\n'
        
        
        '\t\t\t Supported Actions:\n'
        '\t\t\t\t 1. Snapshot - \n'
        '\t\t\t\t\t\t delete, ls\n'
        '\t\t\t\t\t\t\t example python3 EC2Helper.py --profile <the aws profile>  --type snapshot --action delete --assetIds "snap-1,snap-2" --dryRun True\n'
        '\t\t\t\t\t\t\t example python3 EC2Helper.py --profile <the aws profile>  --type snapshot --action ls\n'
        '\t\t\t\t\t\t encrypt\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t KmsKeyId (OPTIONAL) \n'
        '\t\t\t\t\t\t\t\t\t The kms key to use for encryption, If this parameter is not specified, your KMS key for Amazon EBS is used\n'
        '\t\t\t\t\t\t\t example python3 EC2Helper.py --profile <the aws profile>  --type snapshot --action encrypt --assetIds "snap-1,snap-2" --actionParams "{\\"KmsKeyId\\":\\"id\\"}"\n'
        '\t\t\t\t 2. SecurityGroup - '
        '\t\t\t\t\t delete  \n'
        '\t\t\t\t\t\t example python3 EC2Helper.py --profile <the aws profile>  --type security-group --action delete --assetIds "securityGroup1"\n'
        '\t\t\t\t\t clean_unused_sg\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t statePath - The path to save the last state of the remediated Security Groups \n'
        '\t\t\t\t\t\t\t\t rollBack - (OPTIONAL) rollBack flag \n'
        '\t\t\t\t\t\t\t\t sgTorollBack - (OPTIONAL) The id for specific security group that we want to rollback \n'
        '\t\t\t\t\t\t\t\t only_defaults - (OPTIONAL) Flag to mark to execute only default sg \n'
        '\t\t\t\t\t\t\t example python3 EC2Helper.py  --type security-group --action clean_unused_sg --actionParams "{\\"statePath\\"":\\"<path to state file>\\"}"\n'
        '\t\t\t\t 3. Vpc - \n'
        '\t\t\t\t\t\t create_flow_log\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t DeliverLogsPermissionArn (REQUIRED)\n'
        '\t\t\t\t\t\t\t\t\t The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account. \n'
        '\t\t\t\t\t\t\t\t LogGroupName (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t The name of a new or existing CloudWatch Logs log group where Amazon EC2 publishes your flow logs.\n'
        '\t\t\t\t\t\t\t example python3 EC2Helper.py --awsAccessKey <key> --awsSecret <secret> --type vpc --action create_flow_log --regions all\n'
        '\t\t\t\t\t\t\t --actionParams "{\"DeliverLogsPermissionArn\":\"<the role arn>\"}" --assetIds all\n'
        '\t\t\t\t\t\t\t example python3 EC2Helper.py --profile <the aws profile> --type vpc --action create_flow_log --regions all\n'
        '\t\t\t\t\t\t\t --actionParams "{\"DeliverLogsPermissionArn\":\"<the role arn>\"}" --assetIds all\n'
        


        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile (optional) -  The AWS profile to use to execute this script\n'
        '\t\t\t\t awsAccessKey (optional) -  The AWS access key to use to execute this script\n'
        '\t\t\t\t awsSecret (optional) -  The AWS secret to use to execute this script\n'
        '\t\t\t\t region -   The AWS region to use to execute this script\n'
        '\t\t\t\t type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....\n'
        '\t\t\t\t action -   The EC2 action to execute - (snapshot-delete, sg-delete)\n'
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\n\n'

    )
    print(text)


def setup_session(profile=None, region=None, aws_access_key=None, aws_secret=None):
    '''
    This method setup the boto session to AWS
    :param profile:  The aws credentials profile as they defined on the machine (~/.aws/credentials)
    :param region:   The aws target region to execute on
    :param aws_access_key:
    :param aws_secret:
    :return:
    '''
    if profile:
        if region:
            return boto3.Session(profile_name=profile, region_name=region)
        return boto3.Session(profile_name=profile)
    if aws_access_key and aws_secret:
        if region:
            return boto3.Session(region_name=region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
        return boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
    if region:
        return boto3.Session(region_name=region)
    return boto3.Session()


def do_snapshot_delete(resource, asset_id, dry_run):
    """
    Thi function execute delete for single snapshot id
    :param resource: The boto ec2 resource
    :param asset_id: The aws snapshot id
    :param dry_run: Boolean flag to mark if this is dry run or not
    :return:
    """
    logging.info(f"Going to delete snapshot - {asset_id}")
    snapshot = resource.Snapshot(asset_id)
    try:
        response = snapshot.delete(DryRun=dry_run)
    except botocore.exceptions.ClientError as ce:
        if ce.response['Error']['Code'] == 'DryRunOperation':
            logging.warning(f"This is a Dry run - operation would have succeeded")


def do_snapshot_ls(session):
    ec2_client = session.client('ec2')
    response = ec2_client.describe_snapshots(OwnerIds=['self'])
    snapshots = set()
    for snapshot in response['Snapshots']:
        snapshots.add(snapshot['SnapshotId'])
    print(','.join(snapshots))


def do_snapshot_encrypt(session, asset_id, dry_run, kms_key_id=None):
    """
    Thi function handle Snapshot encryption, If EBS default encryption is set, the function will only clone the snapshot
    :param session: boto3 session
    :param asset_id: the snapshot id to encrypt
    :param dry_run: dry run flag
    :return:
    """
    ec2_client = session.client('ec2')
    response_describe = ec2_client.describe_snapshots(SnapshotIds=[asset_id])

    snap = response_describe['Snapshots'][0]
    if snap['Encrypted']:
        logging.info(f"Snapshot {asset_id} is already encrypted, going to skip this execution")

    # response = ec2_client.get_ebs_encryption_by_default()
    # only_clone = response['EbsEncryptionByDefault']
    desc = f'Tamnoon-Automation, encrypted copy for - {asset_id}'

    if kms_key_id:
        response = ec2_client.copy_snapshot(
            Description=desc,
            Encrypted=True,
            KmsKeyId=kms_key_id,
            SourceRegion=session.region_name,
            SourceSnapshotId=asset_id
        )
    else:
        response = ec2_client.copy_snapshot(
            Description=desc,
            Encrypted=True,
            SourceRegion=session.region_name,
            SourceSnapshotId=asset_id
        )
    logging.info(f"Snapshot - {asset_id} was encrypted")


def do_snapshot_action(session, dry_run, action, asset_ids, action_parmas=None):
    """
    This function is the implementation for snapshot actions
    :param session: boto3 session
    :param asset_id:
    :param dry_run:
    :param action:
    :param action_parmas:
    :return:
    """
    if action == 'delete':
        resource = session.resource('ec2')
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_snapshot_delete(resource=resource, asset_id=asset_id, dry_run=dry_run)
    if action == 'ls':
        do_snapshot_ls(session=session)
    if action == 'encrypt':
        kms_key_id = action_parmas['kmsKeyId'] if action_parmas and 'kmsKeyId' in action_parmas else None
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_snapshot_encrypt(session=session, asset_id=asset_id, dry_run=dry_run, kms_key_id=kms_key_id)


def do_sg_delete(resource, asset_id, dry_run):
    """
    This function execute security group deletion
    :param resource: The boto ec2 resource
    :param asset_id: The security group id
    :param dry_run: dry run flag
    :return:
    """

    logging.info(f"Going to delete security group - {asset_id}")
    security_group = resource.SecurityGroup(asset_id)
    try:
        response = security_group.delete(GroupName=asset_id, DryRun=dry_run)
    except botocore.exceptions.ClientError as ce:
        if ce.response['Error']['Code'] == 'DryRunOperation':
            logging.warning(f"This is a Dry run - operation would have succeeded")
        else:
            raise Exception(ce)


def do_sg_action(session, dry_run, action, asset_ids, action_parmas=None):
    """
       This function is the implementation for security group actions
       :param session: boto3 session
       :param asset_id:
       :param dry_run:
       :param action:
       :param action_parmas:
       :return:
    """

    if action == 'delete':
        resource = session.resource('ec2')
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_sg_delete(resource=resource, asset_id=asset_id, dry_run=dry_run)
    if action == 'clean_unused_sg':
        from TAWSDefaultSGRemidiation import execute
        state_path = action_parmas['statePath']
        is_roll_back = action_parmas['rollBack'] if 'rollBack' in action_parmas else None
        only_defualts = action_parmas['sgTorollBack'] if 'sgTorollBack' in action_parmas else False
        sg_to_rb  = action_parmas['sgTorollBack'] if 'sgTorollBack' in action_parmas else None
        execute(is_rollback=is_roll_back, aws_session=session, region=session.region_name, only_defaults=only_defualts, is_dry_run=dry_run, state_path=state_path, sg_to_rb=sg_to_rb, asset_ids=asset_ids)

def _get_regions(regions_param, session):
    """
    This method extract thje list of regions to run over
    :param regions_param: The input region parameter - could be single region, multi regions (reg1,reg2...) or 'all'
    :param session: boto3 ec2 session
    :return:
    """
    regions_list = list()
    if 'all' in regions_param:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_regions(AllRegions=True)
        for region in response['Regions']:
            regions_list.append(region['RegionName'])
        return regions_list

    return regions_param.split(",")


def _get_vpcs_in_region(session):
    """
    This method return all the vpc ids inside the region
    :param session:
    :return:
    """
    try:
        ec2_client = session.client('ec2')
        vpc_ids = list()
        response = ec2_client.describe_vpcs()
        vpcs  = response['Vpcs']
        while 'NextToken' in response:
            response = ec2_client.describe_vpcs(NextToken=response['NextToken'])
            vpcs = vpcs + response['Vpcs']

        for vpc in vpcs:
            vpc_ids.append(vpc['VpcId'])

        return vpc_ids
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AuthFailure':
            logging.warning(f"The region {session.region_name} doesn't support this action please do it via console")
            return list()




def do_vpc_action(session, dry_run, action, asset_ids, parmas=None):
    """
    This i the function that handle the vpc actions
    :param session: The boto3 session
    :param dry_run:
    :param action: The action to execute
    :param asset_ids: the list of asset ids or 'all'
    :param action_parmas:
    :return:
    """
    log_group_name = None
    deliver_logs_permission_arn = None

    if not parmas or 'DeliverLogsPermissionArn' not in parmas:
        logging.error(f"Can't create a vpc flow log, missing required configuration param - DeliverLogsPermissionArn\n"
                      f"The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account.")
        return -1

    deliver_logs_permission_arn = parmas['DeliverLogsPermissionArn']
    if action == 'create_flow_log':
        # check regions
        if len(asset_ids) == 1 and asset_ids[0] == 'all':
            list_of_vpcs = _get_vpcs_in_region(session)
            for asset_id in list_of_vpcs:
                if not 'LogGroupName' in parmas:
                    log_group_name = f"Vpc_FlowLog_{asset_id}"
                else:
                    log_group_name = parmas['LogGroupName']
                do_create_flow_log(session=session, asset_id=asset_id, dry_run=dry_run,
                               log_group_name=log_group_name,
                               deliver_logs_permission_arn=deliver_logs_permission_arn)
        else:
            for asset_id in asset_ids:
                if not 'LogGroupName' in parmas:
                    log_group_name = f"Vpc_FlowLog_{asset_id}"
                else:
                    log_group_name = parmas['LogGroupName']

                logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
                do_create_flow_log(session=session, asset_id=asset_id, dry_run=dry_run, log_group_name=log_group_name,
                                   deliver_logs_permission_arn=deliver_logs_permission_arn)


def do_create_flow_log(session, dry_run, asset_id, log_group_name=None, deliver_logs_permission_arn=None):
    ec2_client = session.client('ec2')

    describe_response = ec2_client.describe_flow_logs(
        Filters=[
            {
                'Name': 'resource-id',
                'Values': [asset_id]
            },
        ],
    )

    if len(describe_response['FlowLogs']) > 0:
        logging.info(f"No Need to create a vpc flow log for vpc - {asset_id} at region {session.region_name}, it's already exists")
        return

    response = ec2_client.create_flow_logs(
        LogGroupName=log_group_name,
        ResourceIds=[asset_id],
        DeliverLogsPermissionArn=deliver_logs_permission_arn,
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs')


def _do_action(asset_type, session, dry_run, action, asset_ids, action_parmas=None):
    if asset_type == 'snapshot':
        do_snapshot_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=params)
    if asset_type == 'security-group':
        do_sg_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=action_parmas)
    if asset_type == 'vpc':
        do_vpc_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, parmas=params)


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--type', required=True, type=str)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--regions', required=False, type=str, default=None)
    parser.add_argument('--awsAccessKey', required=False, type=str, default=None)
    parser.add_argument('--awsSecret', required=False, type=str, default=None)
    parser.add_argument('--assetIds', required=False, type=str)
    parser.add_argument('--actionParams', required=False, type=json.loads, default=None)
    parser.add_argument('--dryRun', required=False, type=bool, default=False)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = None
    profile = args.profile
    action = args.action
    asset_ids = args.assetIds
    asset_ids = asset_ids.split(',') if asset_ids else None
    params = args.actionParams
    dry_run = args.dryRun
    asset_type = args.type
    regions = args.regions
    aws_access_key = args.awsAccessKey
    aws_secret = args.awsSecret

    logging.info("Going to setup resource")

    if regions:
        # in case that regions parameter is set , assume that we want to enable all vpc flow logs inside the region
        session = setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret)
        list_of_regions = _get_regions(regions_param=regions, session=session)
        for region in list_of_regions:
            session = setup_session(profile=profile, region=region, aws_access_key=aws_access_key, aws_secret=aws_secret)
            _do_action(asset_type=asset_type, session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=params)
    else:
        session = setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret)
        _do_action(asset_type=asset_type, session=session, dry_run=dry_run, action=action, asset_ids=asset_ids,
                   action_parmas=params)
