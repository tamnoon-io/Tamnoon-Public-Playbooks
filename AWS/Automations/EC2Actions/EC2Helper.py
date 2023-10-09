import argparse
import json
import logging
import sys
import os
import boto3
import botocore.exceptions
import re

from ..Utils import utils as utils


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
        '\t\t\t\t\t\t encrypt\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t KmsKeyId (OPTIONAL) \n'
        '\t\t\t\t\t\t\t\t\t The kms key to use for encryption, If this parameter is not specified, your KMS key for Amazon EBS is used\n'
        '\t\t\t\t 2. SecurityGroup - '
        '\t\t\t\t\t delete  \n'
        '\t\t\t\t\t clean_unused_sg\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t statePath - The path to save the last state of the remediated Security Groups \n'
        '\t\t\t\t\t\t\t\t rollBack - (OPTIONAL) rollBack flag \n'
        '\t\t\t\t\t\t\t\t sgTorollBack - (OPTIONAL) The id for specific security group that we want to rollback \n'
        '\t\t\t\t\t\t\t\t onlyDefaults - (OPTIONAL) Flag to mark to execute only default sg \n'
        '\t\t\t\t 3. Vpc - \n'
        '\t\t\t\t\t\t create_flow_log\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t DeliverLogsPermissionArn (REQUIRED)\n'
        '\t\t\t\t\t\t\t\t\t The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account. \n'
        '\t\t\t\t\t\t\t\t LogGroupName (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t The name of a new or existing CloudWatch Logs log group where Amazon EC2 publishes your flow logs.\n'
        '\t\t\t\t 4. EC2 - \n'
        '\t\t\t\t\t\t enforce_imdsv2\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t HttpPutResponseHopLimit (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t The desired HTTP PUT response hop limit for instance metadata requests.\n'
        '\t\t\t\t\t\t\t\t\t The larger the number, the further instance metadata requests can travel.\n'
        '\t\t\t\t\t\t\t\t\t If no parameter is specified, the existing state is maintained.\n'
        '\t\t\t\t\t\t\t\t\t The value is number >=1.\n'
        '\t\t\t\t\t\t\t\t rollBack (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t A flag to decide if to rollback to IMDSv1 - value is true \n'
        '\t\t\t\t\t\t\t\t statePath (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t the path for the state json file\n'
        '\t\t\t\t\t\t\t --actionParams "{\"DeliverLogsPermissionArn\":\"<the role arn>\"}" --assetIds <The ec2 instance ids>\n'
        '\t\t\t\t 4. Subnet - \n'
        '\t\t\t\t\t\t disable_public_ip_assignment\n'
        '\t\t\t\t\t\t\t actionParams:\n'
        '\t\t\t\t\t\t\t\t excluded_subnets (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t List of subnets to exclude - ids/Names\n'
        '\t\t\t\t\t\t\t\t rollBack (OPTIONAL)\n'
        '\t\t\t\t\t\t\t\t\t A flag to decide if to rollback to IMDSv1 - value is true \n'

        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile (optional) -  The AWS profile to use to execute this script\n'
        '\t\t\t\t awsAccessKey (optional) -  The AWS access key to use to execute this script\n'
        '\t\t\t\t awsSecret (optional) -  The AWS secret to use to execute this script\n'
        '\t\t\t\t regions (optional) -   The AWS regions to use to execute this script (specific region, list of regions, or All)\n'
        '\t\t\t\t type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....\n'
        '\t\t\t\t action -   The EC2 action to execute - (snapshot-delete, sg-delete)\n'
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\n\n'

    )
    print(text)


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
        return {}
    if action == 'ls':
        do_snapshot_ls(session=session)
        return {}
    if action == 'encrypt':
        kms_key_id = action_parmas['kmsKeyId'] if action_parmas and 'kmsKeyId' in action_parmas else None
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_snapshot_encrypt(session=session, asset_id=asset_id, dry_run=dry_run, kms_key_id=kms_key_id)
        return {}


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
    from .SecurityGroupHelper import execute, get_sg_usage
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
        return {}
    if action == 'clean_unused_sg':
        if not action_parmas or 'statePath' not in action_parmas:
            raise Exception(f'statePath have to delivered in case of Security Group cleanup - to be able to roll back ')
        state_path = action_parmas['statePath']
        is_roll_back = action_parmas['rollBack'] if 'rollBack' in action_parmas else None
        only_defualts = action_parmas['onlyDefaults'] if 'onlyDefaults' in action_parmas else False
        sg_to_rb = action_parmas['sgTorollBack'] if 'sgTorollBack' in action_parmas else None
        action_type = action_parmas['actionType'] if 'actionType' in action_parmas else "Clean"
        tag_deletion = action_parmas['deletionTag'] if 'deletionTag' in action_parmas else None

        return execute(is_rollback=is_roll_back, aws_session=session, region=session.region_name, only_defaults=only_defualts,
                is_dry_run=dry_run, state_path=state_path, sg_to_rb=sg_to_rb, asset_ids=asset_ids,
                tag_deletion=tag_deletion, action_type=action_type)

    if action == 'get_usage':
        return get_sg_usage(session=session, asset_ids=asset_ids)



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
        vpcs = response['Vpcs']
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


def do_vpc_action(session, dry_run, action, asset_ids, action_parmas=None):
    """
    This is the function that handle the vpc actions
    :param session: The boto3 session
    :param dry_run:
    :param action: The action to execute
    :param asset_ids: the list of asset ids or 'all'
    :param action_parmas:
    :return:
    """
    log_group_name = None

    deliver_logs_permission_arn = action_parmas['DeliverLogsPermissionArn']
    if action == 'create_flow_log':
        if not action_parmas or 'DeliverLogsPermissionArn' not in action_parmas:
            logging.error(
                f"Can't create a vpc flow log, missing required configuration param - DeliverLogsPermissionArn\n"
                f"The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account.")
            return {
                'error': f"Can't create a vpc flow log, missing required configuration param - DeliverLogsPermissionArn\n"
                         f"The ARN of the IAM role that allows Amazon EC2 to publish flow logs to a CloudWatch Logs log group in your account."}

        logging.info(f"Going to execute - VPC  - {action}")
        # check regions
        if len(asset_ids) == 1 and asset_ids[0] == 'all':
            list_of_vpcs = _get_vpcs_in_region(session)
            for asset_id in list_of_vpcs:
                if not 'LogGroupName' in action_parmas:
                    log_group_name = f"Vpc_FlowLog_{asset_id}"
                else:
                    log_group_name = action_parmas['LogGroupName']
                do_create_flow_log(session=session, asset_id=asset_id, dry_run=dry_run,
                                   log_group_name=log_group_name,
                                   deliver_logs_permission_arn=deliver_logs_permission_arn)
        else:
            for asset_id in asset_ids:
                if not 'LogGroupName' in action_parmas:
                    log_group_name = f"Vpc_FlowLog_{asset_id}"
                else:
                    log_group_name = action_parmas['LogGroupName']

                logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
                do_create_flow_log(session=session, asset_id=asset_id, dry_run=dry_run, log_group_name=log_group_name,
                                   deliver_logs_permission_arn=deliver_logs_permission_arn)
        return {}


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
        logging.info(
            f"No Need to create a vpc flow log for vpc - {asset_id} at region {session.region_name}, it's already exists")
        return

    response = ec2_client.create_flow_logs(
        LogGroupName=log_group_name,
        ResourceIds=[asset_id],
        DeliverLogsPermissionArn=deliver_logs_permission_arn,
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='cloud-watch-logs')

    logging.info(f"Enable flow log done for - {asset_id}")


def do_imdsv2_action(client, asset_id, dry_run, http_hope, roll_back, state_path):
    '''
    This function execute the IMDS versioning configuration for ec2 asset
    :param client:
    :param asset_id:
    :param dry_run:
    :param http_hope:
    :param roll_back:
    :param state_path:
    :return:
    '''

    try:
        if roll_back:
            if not state_path:
                logging.error(
                    f"Can't rollback without having the previous state, no json file for state was delivered to the script")
            else:
                with open(state_path, "r") as state_file:
                    state = json.load(state_file)
                    if asset_id in state:
                        instance = state[asset_id]
                        http_token = instance['HttpTokens']
                        hope = instance['HttpPutResponseHopLimit']
                        response = client.modify_instance_metadata_options(
                            InstanceId=asset_id,
                            HttpTokens='required',
                            HttpPutResponseHopLimit=http_hope,
                            DryRun=dry_run
                        )
        else:
            # get teh current state of the asset and save it to the state file
            response = client.describe_instances(InstanceIds=[asset_id])
            metadata_options = response['Reservations'][0]['Instances'][0]['MetadataOptions']
            if os.path.exists(state_path):
                with open(state_path, "r") as state_file:
                    try:
                        state = json.load(state_file)
                    except json.JSONDecodeError:
                        state = dict()


            else:
                state = dict()

            state[asset_id] = {
                "HttpTokens": metadata_options['HttpTokens'],
                "HttpPutResponseHopLimit": metadata_options['HttpPutResponseHopLimit']
            }
            json.dump(state, open(state_path, "w"))

            # in case http hope limit provided
            if http_hope > 0:
                response = client.modify_instance_metadata_options(
                    InstanceId=asset_id,
                    HttpTokens='required',
                    HttpPutResponseHopLimit=http_hope,
                    DryRun=dry_run
                )
            # in case no http hope limit provided use the current state
            else:
                response = client.modify_instance_metadata_options(
                    InstanceId=asset_id,
                    HttpTokens='required',
                    DryRun=dry_run
                )

    except botocore.exceptions.ClientError as ce:
        if ce.response['Error']['Code'] == 'DryRunOperation':
            logging.warning(f"Dry run execution!!! nothing changed")

    except Exception as e:
        logging.error(f"Something went wrong with EC2 API !!")
        raise e


def do_ec2_action(session, dry_run, action, asset_ids, action_parmas):
    """
    This is the Ec2 helper function to execute boto3 api call for ec2 configration
    :param session:
    :param dry_run:
    :param action:
    :param asset_ids:
    :param parmas:
    :return:
    """

    if action == 'enforce_imdsv2':
        client = session.client('ec2')
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            http_hope = action_parmas['HttpPutResponseHopLimit'] if params and 'HttpPutResponseHopLimit' in action_parmas else -1
            roll_back = action_parmas['rollBack'] if action_parmas and 'rollBack' in action_parmas else False
            state_path = action_parmas['statePath'] if action_parmas and 'statePath' in action_parmas else None
            do_imdsv2_action(client=client, asset_id=asset_id, dry_run=dry_run, http_hope=http_hope,
                             roll_back=roll_back, state_path=state_path)
        return {}

    return {'error': 'no action found'}


def do_disable_public_ip_assignment(client, asset_ids, dry_run, excluded_subnets, roll_back):
    """
    This function executing the logic of disabling the automated public ip assigment for subnet
    :param client:
    :param asset_ids:
    :param dry_run:
    :param excluded_subnets:
    :param roll_back:
    :return:
    """
    excluded_subnets_regex = None
    if excluded_subnets:
        excluded_subnets_regex = "|".join([x.strip() for x in re.sub(',|;', " ", excluded_subnets).split()])

    # Get all the potential subnets - list of all subnets in the region
    potential_subnets = list()
    subnets_resp  = client.describe_subnets()
    potential_subnets = potential_subnets + subnets_resp['Subnets']
    while 'NextToken' in subnets_resp and subnets_resp['NextToken']:
        subnets_resp = client.describe_subnets(NextToken=subnets_resp['NextToken'])
        potential_subnets = potential_subnets + subnets_resp['Subnets']

    results = list()
    # Work for each subnet
    for subnet in potential_subnets:
        current_setting = subnet['MapPublicIpOnLaunch']
        record = {"region": region, "vpcId": subnet['VpcId'], "subnetId": subnet['SubnetId'],
                  "MapPublicIpOnLaunch": current_setting}

        #Goin to check exclusion over subnet Name or Id
        tag_name = subnet["Tags"]["Name"] if "Tags" in subnet and "Name" in subnet["Tags"] else None

        # check if subnet should be excluded or not part of the provided subnets ids
        if (excluded_subnets_regex and \
                ((tag_name and re.search(excluded_subnets_regex, tag_name))
                 or re.search(excluded_subnets_regex, subnet['SubnetId'])))\
                or asset_ids and subnet['SubnetId'] not in asset_ids:
            logging.info(f"Subnet - {record['subnetId']} in Vpc - {record['vpcId']} at region - {record['region']} is excluded or not part of the provided subnets ids, going to skip this one")
            record['actionResult'] = "SKIP"
        else:
            if not current_setting:
                # no setting on and this is not roll-back
                if not roll_back:
                    logging.info(
                        f"For Subnet - {record['subnetId']} in Vpc - {record['vpcId']} at region - {record['region']} public ip on lunch setting is off")
                    record['actionResult'] = "NO-NEED"
                else:
                    # roll-back -execution
                    logging.info(
                        f"Enabling auto-assign public IP for subnet {record['subnetId']} in VPC {record['vpcId']} in region {record['region']} - roll-back")
                    if dry_run:
                        logging.info("############## Dry Run ###################")
                        record['actionResult'] = "DRY-RUN: CHANGED"
                    else:
                        client.modify_subnet_attribute(SubnetId=record['subnetId'], MapPublicIpOnLaunch={'Value': True})
                        record['actionResult'] = "ROLL-BACK"


            else:
                if dry_run:
                    logging.info("############## Dry Run ###################")
                    record['actionResult'] = "DRY-RUN: CHANGED"
                    logging.info(
                        f"Disabling auto-assign public IP for subnet {record['subnetId']} in VPC {record['vpcId']} in region {record['region']}")
                else:
                    logging.info(
                        f"Disabling auto-assign public IP for subnet {record['subnetId']} in VPC {record['vpcId']} in region {record['region']}")
                    client.modify_subnet_attribute(SubnetId=record['subnetId'], MapPublicIpOnLaunch={'Value': False})
                    record['actionResult'] = "CHANGED"
        results.append(record)
    return results




def do_subnet_action(session, dry_run, action, asset_ids, action_parmas):
    """
    This is the subnet helper function to execute automation over AWS subnet using boto3 api
    :param session:
    :param dry_run:
    :param action:
    :param asset_ids:
    :param parmas:
    :return:
    """
    if action == "disable_public_ip_assignment":
        client = session.client('ec2')
        excluded_subnets = action_parmas['excluded_subnets'] if action_parmas and 'excluded_subnets' in action_parmas else None
        roll_back = action_parmas['rollBack'] if action_parmas and 'rollBack' in action_parmas else None

        return do_disable_public_ip_assignment(client=client, asset_ids=asset_ids, dry_run=dry_run, excluded_subnets=excluded_subnets,
                         roll_back=roll_back)






def _do_action(asset_type, session, dry_run, action, asset_ids, action_parmas=None):
    if asset_type == 'snapshot':
        return do_snapshot_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids,
                                  action_parmas=action_parmas)
    if asset_type == 'security-group':
        return do_sg_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids,
                            action_parmas=action_parmas)
    if asset_type == 'vpc':
        return do_vpc_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=action_parmas)
    if asset_type == 'ec2':
        return do_ec2_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=action_parmas)
    if asset_type == 'subnet':
        return do_subnet_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=action_parmas)


if __name__ == '__main__':


    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--type', required=False, type=str)
    parser.add_argument('--action', required=False, type=str)
    parser.add_argument('--regions', required=False, type=str, default=None)
    parser.add_argument('--awsAccessKey', required=False, type=str, default=None)
    parser.add_argument('--awsSecret', required=False, type=str, default=None)
    parser.add_argument('--awsSessionToken', required=False, type=str, default=None)
    parser.add_argument('--assetIds', required=False, type=str)
    parser.add_argument('--actionParams', required=False, type=json.loads, default=None)
    parser.add_argument('--dryRun', required=False, type=bool, default=False)
    parser.add_argument('--file', required=False, type=str, default=None)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = dict()
    try:
        params = utils.build_params(args=args)

        profile = params.profile
        action = params.action
        asset_ids = params.assetIds
        asset_ids = asset_ids.split(',') if asset_ids else None
        action_params = params.actionParams
        action_params = json.loads(action_params) if action_params and type(action_params) != dict else action_params
        dry_run = params.dryRun
        asset_type = params.type
        regions = params.regions
        aws_access_key = params.awsAccessKey
        aws_secret = params.awsSecret
        aws_session_token = params.awsSessionToken



        if regions:
            logging.info(f"Going to run over {regions} - region")
            # in case that regions parameter is set , assume that we want to enable all vpc flow logs inside the region
            session = utils.setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret, aws_session_token=aws_session_token)
            list_of_regions = utils.get_regions(regions_param=regions, session=session)
            for region in list_of_regions:
                logging.info(f"Working on Region - {region}")
                session = utils.setup_session(profile=profile, region=region, aws_access_key=aws_access_key,
                                        aws_secret=aws_secret, aws_session_token=aws_session_token)
                action_result = _do_action(asset_type=asset_type, session=session, dry_run=dry_run, action=action,
                                           asset_ids=asset_ids, action_parmas=action_params)
                if action_result and len(action_result) > 0:
                    result[region] = action_result
        else:
            session = utils.setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret, aws_session_token=aws_session_token)
            logging.info(f"Going to run over the default - {session.region_name} - region")
            action_result = _do_action(asset_type=asset_type, session=session, dry_run=dry_run, action=action,
                                       asset_ids=asset_ids,
                                       action_parmas=action_params)
            if action_result and len(action_result) > 0:
                result[session.region_name] = action_result
    except Exception as e:
        logging.error(f"Something Went wrong!!")
        result['status'] = 'Error'
        result['message'] = str(e)

    utils.export_data(f"Tamnoon-EC2Helper-{asset_type}-{action}-execution-result", result)