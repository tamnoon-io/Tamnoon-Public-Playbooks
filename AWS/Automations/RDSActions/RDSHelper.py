import argparse
import json
import logging
import sys
import os
import boto3
import botocore.exceptions
import re

from ..Utils import utils as utils





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
        '\t\t Welcome To Tamnoon RDSActions Helper- The script that will help you with your RDSActions Service Actions \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t Authentication:\n'
        '\t\t\t\t The script support the fallback mechanism auth as AWS CLI\n'
        '\t\t\t\t\t profile - send the aws profile as input parameter\n'
        '\t\t\t\t\t key and secret - send the aws key and secret as input parameter\n'
        '\t\t\t Supported Actions:\n'
        '\t\t\t\t 1. RDSActions - \n'
        '\t\t\t\t\t\t Deletion protection\n'

        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds.html\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile (optional) -  The AWS profile to use to execute this script\n'
        '\t\t\t\t awsAccessKey (optional) -  The AWS access key to use to execute this script\n'
        '\t\t\t\t awsSecret (optional) -  The AWS secret to use to execute this script\n'
        '\t\t\t\t awsSessionToken (optional) -  The AWS session token to use to execute this script\n'
        '\t\t\t\t regions (optional) -   The AWS regions to use to execute this script (specific region, list of regions, or All)\n'
        '\t\t\t\t type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....\n'
        '\t\t\t\t action -   The EC2 action to execute - (snapshot-delete, sg-delete)\n'
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\t\t\t\t dryRun (optional) - Flag to mark if this is dry run execution"\n'
        '\t\t\t\t file (optional) - The path to yaml file with the CLI execution params for this script"\n'
        '\n\n'

    )
    print(text)


def do_deletion_protection(client, asset_id, dry_run, roll_back):
    """
    Thi function execute rds instance modification to enable/disable deletion-protection
    :param client: The boto ec2 resource
    :param asset_id: The aws snapshot id
    :param dry_run: Boolean flag to mark if this is dry run or not
    :return:
    """


    if dry_run:
        logging.info(f"Dry Run - Going to enable deletion protection for instance - {asset_id}")
        return 'dry_run'
    try:
        deletion_protection = True
        if roll_back:
            logging.info(f"Roll Back - Going to disable deletion protection for instance - {asset_id}")
            deletion_protection = False

        response = client.modify_db_instance(
            DBInstanceIdentifier=asset_id,
            DeletionProtection=deletion_protection
        )

        return 'Roll-Back' if roll_back else 'Success'
    except Exception as e:
        logging.error(f"Something went wrong - {e}")


def do_rds_action(session, dry_run, action, asset_ids, action_parmas=None):
    """
    This function is the implementation for rds actions
    :param session: boto3 session
    :param asset_id:
    :param dry_run:
    :param action:
    :param action_parmas:
    :return:
    """
    result = dict()
    if action == 'deletion-protection':
        roll_back = action_parmas['rollBack'] if action_parmas and 'rollBack' in action_parmas else None
        client = session.client('rds')
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            result[asset_id] = {action: do_deletion_protection(client=client, asset_id=asset_id, dry_run=dry_run, roll_back=roll_back)}
    return result




def _do_action(asset_type, session, dry_run, action, asset_ids, action_parmas=None):
    if asset_type == 'rds':
        return do_rds_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids,
                                  action_parmas=action_parmas)



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

    utils.log_setup(args.logLevel)

    result = None

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

    result = dict()
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

    utils.export_data(f"Tamnoon-RDSHelper-{asset_type}-{action}-execution-result", result)