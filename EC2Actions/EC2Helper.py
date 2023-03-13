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
        '\t\t\t Supported Actions:\n'
        '\t\t\t\t 1. Snapshot - \n'
        '\t\t\t\t\t\t delete, ls\n'
        '\t\t\t\t\t\t encrypt - Can support optional param to be sent as actionParmas - KmsKeyId, the kms key to use for encryption\n'
        '\t\t\t\t\t\t\t If this parameter is not specified, your KMS key for Amazon EBS is used \n'
        '\t\t\t\t 2. SecurityGroup - delete  \n'


        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 EC2Helper.py --profile <aws_profile> --type <The ec2 service type> --action <The action to execute> --actionParmas <the params for the action> --assetIds <list of assets to work on, comma-separated>\n'
        '\t\t\t\t python3 EC2Helper.py  --type snapshot --action delete --assetIds "snap-1,snap-2" --dryRun True\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile -  The AWS profile to use to execute this script\n'
        '\t\t\t\t type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....\n'
        '\t\t\t\t action -   The EC2 action to execute - (snapshot-delete, sg-delete)\n'
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" \n'
        '\t\t\t\t assetIds  - List of assets ids (string seperated by commas)"\n'
        '\n\n'

    )
    print(text)


def setup_session(profile):
    if profile:
        session = boto3.Session(profile_name=profile)
        return session

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

    #response = ec2_client.get_ebs_encryption_by_default()
    #only_clone = response['EbsEncryptionByDefault']
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


def do_sg_action(session, dry_run, action, asset_ids):
    """
       This function is the implementation for security group actions
       :param session: boto3 session
       :param asset_id:
       :param dry_run:
       :param action:
       :return:
    """

    if action == 'delete':
        resource = session.resource('ec2')
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_sg_delete(resource=resource, asset_id=asset_id, dry_run=dry_run)


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--type', required=True, type=str)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--assetIds', required=True, type=str)
    parser.add_argument('--actionParmas', required=False, type=json.loads, default=None)
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
    asset_ids = asset_ids.split(',')
    params = args.actionParmas
    dry_run = args.dryRun
    asset_type = args.type


    logging.info("Going to setup resource")
    session = setup_session(profile)


    if asset_type == 'snapshot':
        do_snapshot_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids, action_parmas=params)
    if asset_type == 'security-group':
        do_sg_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids)














