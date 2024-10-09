import argparse
import json
import logging
import sys
import os
from typing import List

from ..Utils import utils as utils

try:
    from Automations.RDSActions import help_jsons_data
except ModuleNotFoundError as ex:
    pass

rds_deletion_protection_readme_data = (
    help_jsons_data.rds_deletion_protection_readme_data
    if hasattr(help_jsons_data, "rds_deletion_protection_readme_data")
    else dict()
)
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


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


def do_deletion_protection(
        client,
        asset_id,
        dry_run,
        roll_back
):
    """
    Thi function execute rds instance modification to enable/disable deletion-protection
    :param client: The boto ec2 resource
    :param asset_id: The aws snapshot id
    :param dry_run: Boolean flag to mark if this is dry run or not
    :return:
    """

    if dry_run:
        logging.info(f"Dry Run - Going to enable deletion protection for instance - {asset_id}")
        return 'Dry Run - Enable deletion protection for instance. Nothing Executed!!'
    try:
        deletion_protection = True
        if roll_back:
            logging.info(f"Roll Back - Going to disable deletion protection for instance - {asset_id}")
            deletion_protection = False
        response = client.modify_db_instance(
            DBInstanceIdentifier=asset_id,
            DeletionProtection=deletion_protection
        )
        if roll_back:
            return "Roll Back - Disabled deletion protection for instance."
        return "Enabled deletion protection for instance."
    except Exception as e:
        logging.error(f"Something went wrong - {e}")
        return f"Something went wrong - {e}"


def do_rds_action(
        asset_type,
        session,
        dry_run,
        action,
        asset_ids,
        action_params=None
):
    """
    This function is the implementation for rds actions
    :param session: boto3 session
    :param asset_id:
    :param dry_run:
    :param action:
    :param action_params:
    :return:
    """
    result = dict()

    roll_back = action_params['rollBack'] if action_params and 'rollBack' in action_params else None
    client = session.client('rds')
    for asset_id in asset_ids:
        logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
        result[asset_id] = {
            action: do_deletion_protection(client=client, asset_id=asset_id, dry_run=dry_run, roll_back=roll_back)}
    return result


def common_args(
        parser,
        args_json_data
):
    parser.add_argument(
        "--profile",
        required=False,
        default=None,
        metavar="",
        help=args_json_data.get("profile"),
    )
    parser.add_argument(
        "--awsAccessKey",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsAccessKey"),
    )
    parser.add_argument(
        "--awsSecret",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsSecret"),
    )
    parser.add_argument(
        "--awsSessionToken",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsSessionToken")
    )
    parser.add_argument(
        '--assetIds',
        required=False,
        type=str,
        metavar="",
        help=args_json_data.get("assetIds")
    )
    parser.add_argument(
        '--regions',
        required=False,
        type=str,
        default="us-east-1",
        metavar="",
        help=args_json_data.get("regions")
    )
    parser.add_argument(
        '--actionParams',
        required=False,
        type=json.loads,
        default=None,
        metavar="",
        help=args_json_data.get("actionParams")
    )
    parser.add_argument(
        "--file",
        required=False,
        metavar="",
        type=str,
        default=None,
        help=args_json_data.get("file"),
    )
    parser.add_argument(
        "--logLevel",
        required=False,
        choices=["INFO", "DEBUG", "WARN", "ERROR"],
        metavar="",
        type=str,
        default="INFO",
        help=args_json_data.get("logLevel"),
    )
    parser.add_argument(
        "--outputType",
        required=False,
        metavar="",
        type=str,
        default="json",
        help=args_json_data.get("outputType"),
    )
    parser.add_argument(
        "--outDir",
        required=False,
        metavar="",
        type=str,
        default=os.getcwd(),
        help=args_json_data.get("outDir"),
    )
    parser.add_argument(
        "--testId",
        required=False,
        metavar="",
        type=str,
        help=args_json_data.get("testId"),
    )
    parser.add_argument(
        '--dryRun',
        required=False,
        type=bool,
        default=False,
        metavar="",
        help=args_json_data.get("dryRun")
    )


def main(argv: List):
    """
    main function
    """

    parser_usage = common_json_data.get("usage", dict()).get("RDSActions", "")
    usage = parser_usage + " [-h]"
    if len(argv) == 2 and ("--help" in argv or "-h" in argv):
        utils.print_help_valid_types(
            common_json_data.get("help", dict()).get(
                "RDSActions", dict()), usage
        )
        sys.exit(1)

    # help mapping for RDS Actions - Help Content is mapped with associated action of type RDS.
    rds_help = {
        'deletion_protection': rds_deletion_protection_readme_data
    }
    type_rds_help = {
        str(key): value.get("help", "None") for key, value in rds_help.items()
    }
    parser = argparse.ArgumentParser(
        usage=parser_usage,
        conflict_handler="resolve",
    )
    type_subparser = parser.add_subparsers(
        title="type", help="choose rds automation type", dest="type", metavar=""
    )

    rds_parser = type_subparser.add_parser(
        name="rds",
        formatter_class=argparse.RawTextHelpFormatter
    )
    rds_action_subparser = rds_parser.add_subparsers(
        title="choose rds action", dest='action', metavar="", description=utils.type_help(
            type_rds_help)
    )
    rds_deletion_protection_parser = rds_action_subparser.add_parser(
        name='deletion_protection', formatter_class=argparse.RawTextHelpFormatter
    )

    # Overriding "optional arguments" to corresponding "action" in help CLI message
    rds_deletion_protection_parser._optionals.title = "deletion_protection"

    asset_type = argv[1]
    action = argv[2]

    args_json_data = rds_help.get(action, {}).get("cli_args", {})
    common_args(rds_deletion_protection_parser, args_json_data=args_json_data)

    args = parser.parse_args()
    params = utils.build_params(args=args)
    if not params:
        print(sys.exc_info())
        exit(0)

    # Function Mapping - Function is mapped with associated asset_type and action.
    function_mapping = {
        "rds": {
            "deletion_protection": do_rds_action
        }
    }

    result = dict()

    profile = params.get(
        "profile") if args.file is not None else params.profile
    aws_access_key = params.get(
        "awsAccessKey") if args.file is not None else params.awsAccessKey
    aws_secret = params.get(
        "awsSecret") if args.file is not None else params.awsSecret
    aws_session_token = params.get(
        "awsSessionToken") if args.file is not None else params.awsSessionToken

    regions = params.get(
        'regions') if args.file is not None else params.regions.split(",")

    dry_run = params.get(
        "dryRun") if args.file is not None else params.dryRun
    log_level = params.get(
        "logLevel") if args.file is not None else params.logLevel

    output_type = params.get(
        "outputType", "JSON") if args.file is not None else str(params.outputType)

    output_directory = params.get(
        "outDir", "./") if args.file is not None else str(params.outDir)

    test_id = params.get(
        "testId", None) if args.file is not None else str(params.testId)
    if test_id is not None:
        result['testId'] = test_id

    if params.get("assetIds") is None:
        asset_ids = None
    elif args.file is None:
        asset_ids = params.assetIds.split(",")
    else:
        asset_ids = params.get('assetIds')

    action_params = params.get(
        'actionParams', None) if args.file is not None else params.actionParams

    action_params = json.loads(action_params) if action_params and not isinstance(
        action_params, dict) else params.get('actionParams', None)
    try:
        utils.log_setup(log_level)
        # in case that regions parameter is set , assume that we want to enable all vpc flow logs inside the region
        session = utils.setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret,
                                      aws_session_token=aws_session_token)
        caller_identity = utils.get_caller_identity(session=session)
        result['caller-identity'] = caller_identity
        for region in regions:
            logging.info(f"Going to run over {region} - region")
            logging.info(f"Working on Region - {region}")
            session = utils.setup_session(profile=profile, region=region, aws_access_key=aws_access_key,
                                          aws_secret=aws_secret, aws_session_token=aws_session_token)
            action_result = function_mapping[asset_type][action](
                asset_type=asset_type,
                session=session,
                dry_run=dry_run,
                action=action,
                asset_ids=asset_ids,
                action_params=action_params
            )
            if action_result:
                result[region] = action_result
            else:
                result[region] = {}

    except Exception as ex:
        logging.error("Something Went wrong!!", exc_info=log_level == "DEBUG")
        result['status'] = 'Error'
        result['message'] = str(ex)
    filename = os.path.join(
        output_directory,
        f"Tamnoon-RDSActions-{asset_type}-{action.replace('_', '-')}-execution-result"
        + "."
        + output_type,
    )
    utils.export_data(filename, result)


if __name__ == "__main__":
    main(sys.argv)
