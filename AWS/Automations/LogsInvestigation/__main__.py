import argparse
import json
import logging
import sys
import os

from Automations.Utils import utils as utils

try:
    from Automations.LogsInvestigation import help_jsons_data
except ModuleNotFoundError:
    pass

cloudtrail_data_readme = (
    help_jsons_data.cloudtrail_data_readme
    if hasattr(help_jsons_data, "cloudtrail_data_readme")
    else dict()
)
events_history_readme = (
    help_jsons_data.events_history_readme
    if hasattr(help_jsons_data, "events_history_readme")
    else dict()
)
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


def command_description():
    return (
        "\n"
        "\n "
        """

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

        """
    )


def common_args(parser, args_json_data):
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
        "--regions",
        required=False,
        metavar="",
        type=str,
        default="all",
        help=args_json_data.get("regions"),
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
        "--actionParams",
        required=False,
        help=args_json_data.get("actionParams"),
        metavar="",
        default=dict(),
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


def events_history(session, action_params, outputDirectory, outputType, asset_id=None):
    """
    This function is the implementation for cloudtrail events_history
    :param session: boto3 session
    :param asset_id:
    :param action_params:
    :param outputDirectory:
    :param outputType:
    :return:
    """
    del asset_id
    try:
        from .GetEventsHistory import get_events_history, validate_action_params
        days = action_params.get("days", 90)
        validate_action_params(action_params, days)
        attribute_key = action_params.get("AttributeKey")
        attribute_value = action_params.get("AttributeValue", "")
        result = None

        result = get_events_history(
            session=session,
            attribute_key=attribute_key,
            attribute_value=attribute_value,
            days=days,
        )
        filename = os.path.join(
            outputDirectory,
            utils.export_data_filename_with_timestamp(
                f"Tamnoon-LogsInvestigation-events-history-{session.region_name}-execution-result",
                outputType,
            ),
        )
        utils.export_data_(filename, result)
        return f"data exported to {filename}"
    except Exception as e:
        logging.error(f"Something went wrong. Error: {str(e)}")
        return str(e)


def trail_logs_investigation_using_athena(session, asset_id, action_params, outputDirectory, outputType):
    """
    This function is the implementation for cloudtrail trails
    :param session: boto3 session
    :param asset_id:
    :param action_params:
    :param outputDirectory:
    :param outputType:
    :return:
    """
    try:
        from .InvestigateTrailLogs import investigate_cloudtrail_trail_logs
        from library.LogsInvestigation import get_cloudtrail_bucket_name, find_region_of_bucket

        filter_fields = [
            'eventversion',
            'useridentity',
            'useridentity.type',
            'useridentity.arn',
            'useridentity.principalid',
            'useridentity.accountid',
            'useridentity.invokedby',
            'useridentity.accesskeyid',
            'useridentity.username',
            'eventtime',
            'eventsource',
            'eventname',
            'awsregion',
            'sourceipaddress',
            'useragent',
            'errorcode',
            'errormessage',
            'requestparameters',
            'requestparameters.bucketName',
            'requestparameters.Host',
            'requestparameters.key',
            'responseelements',
            'responseelements.x-amz-server-side-encryption-aws-kms-key-id',
            'responseelements.x-amz-server-side-encryption',
            'responseelements.x-amz-server-side-encryption-context',
            'additionaleventdata',
            'additionaleventdata.SignatureVersion',
            'additionaleventdata.CipherSuite',
            'additionaleventdata.bytesTransferredIn',
            'additionaleventdata.AuthenticationMethod',
            'additionaleventdata.x-amz-id-2',
            'additionaleventdata.bytesTransferredOut',
            'requestid',
            'eventid',
            'resources',
            'resources.arn',
            'resources.type',
            'eventtype',
            'apiversion',
            'readonly',
            'recipientaccountid',
            'serviceeventdetails',
            'sharedeventid',
            'vpcendpointid',
            'tlsdetails',
            'tlsdetails.tlsversion',
            'tlsdetails.ciphersuite',
            'tlsdetails.clientprovidedhostheader',
        ]
        action_params_query_keys = list(
            set(action_params.keys()) - {'days', 'cleanup'})
        query_filter = [(key, action_params[key]) if key.split(
            '.')[0] in filter_fields else '' for key in action_params]
        query_filter = list(filter(bool, query_filter))
        valid_query_keys = [query_keys_tuple[0]
                            for query_keys_tuple in query_filter]
        invalid_query_keys = list(
            set(action_params_query_keys) - set(valid_query_keys))
        if invalid_query_keys:
            raise ValueError(
                f"Invalid Query Field Keys are: {','.join(invalid_query_keys)}.Please Check Playbook for Valid Keys.")
        if not asset_id:
            raise ValueError(
                "Missing assetIds (trail name). assetIds is Mandatory.")
        if not action_params:
            raise ValueError(
                "Missing actionParams. actionParams are Mandatory")
        (trail_found, trail_bucket_name) = get_cloudtrail_bucket_name(session, asset_id)
        if not trail_found:
            msg = f"Trail {asset_id} not found in aws account in given region {session.region_name}."
            logging.error(msg=msg)
            return msg

        if not trail_bucket_name:
            msg = f"S3 bucket associated with trail {asset_id} not found in aws account."
            logging.error(msg=msg)
            return msg

        region_of_bucket = find_region_of_bucket(
            session=session, bucket_name=trail_bucket_name)
        if not region_of_bucket:
            msg = f"Something went wrong in finding region of S3 bucket. Athena table would have been created in same region."
            logging.error(msg=msg)
            return msg

        # using session with region of value same as that of bucket's region
        session_of_region_of_bucket = utils.setup_session(
            profile=session.profile_name, region=region_of_bucket)
        result = investigate_cloudtrail_trail_logs(
            trail_bucket_name=trail_bucket_name,
            session=session_of_region_of_bucket,
            query_filter=query_filter,
            cleanup=action_params.get('cleanup', False),
            days=action_params.get('days', 90)
        )
        filename = os.path.join(
            outputDirectory,
            utils.export_data_filename_with_timestamp(
                f"Tamnoon-LogsInvestigation-cloudtrail-{session.region_name}-execution-result",
                outputType,
            ),
        )
        utils.export_data_(filename, result)
        return f"data exported to {filename}"
    except Exception as e:
        logging.error(f"Something went wrong. Error: {str(e)}")
        return str(e)


def main(argv):
    parser_usage = common_json_data.get("usage", {}).get("LogsInvestigation",
                                                         "python3 -m Automations.LogsInvestigation")
    usage = parser_usage + " [-h]"
    functions_mapping = {
        "cloudtrail": trail_logs_investigation_using_athena,
        "events-history": events_history
    }

    help_mappings = dict()
    help_mappings = {
        "cloudtrail": cloudtrail_data_readme,
        "events-history": events_history_readme
    }

    if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
        utils.print_help_valid_types(common_json_data.get("help", {}).get("LogsInvestigation"),
                                     usage)
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description=command_description(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=parser_usage
    )
    parser._optionals.title = "arguments"
    # type parsers
    type_subparsers = parser.add_subparsers(
        title="type", dest="type", metavar="", description=""
    )
    cloudtrail_parser = type_subparsers.add_parser(
        name="cloudtrail", formatter_class=argparse.RawTextHelpFormatter
    )
    events_history_parser = type_subparsers.add_parser(
        name="events-history", formatter_class=argparse.RawTextHelpFormatter
    )

    asset_type = sys.argv[1]
    if asset_type == 'cloudtrail':
        common_args(
            cloudtrail_parser, help_mappings["cloudtrail"].get("cli_args")
        )
        cloudtrail_parser.add_argument(
            "--assetIds",
            required=False,
            help=help_mappings["cloudtrail"].get("cli_args").get("assetIds"),
            metavar="",
            type=str,
        )
    else:
        common_args(
            events_history_parser, help_mappings["events-history"].get(
                "cli_args")
        )

    if not argv:
        argv = sys.argv
    cli_args = parser.parse_args(argv[1:])
    utils.log_setup(cli_args.logLevel)

    params = utils.build_params(args=cli_args)

    action = params.get("action", "")
    profile = params.get("profile")
    asset_id = params.get("assetIds")
    action_params = params.get("actionParams")
    action_params = (
        json.loads(action_params)
        if action_params and type(action_params) != dict
        else action_params
    )

    regions = params.get("regions")
    if cli_args.file != None:
        regions = params.get("regions")
        if regions:
            if isinstance(regions, list):
                regions = ','.join(regions)
        else:
            regions = 'all'
    aws_access_key = params.get("awsAccessKey")
    aws_secret = params.get("awsSecret")
    aws_session_token = params.get("awsSessionToken")

    outputDirectory = params.get("outDir", "./")
    outputType = params.get("outputType", "json")

    result = dict()
    if params.get("testId") is not None:
        result["testId"] = params.get("testId")

    try:
        session = utils.setup_session(
            profile=profile,
            aws_access_key=aws_access_key,
            aws_secret=aws_secret,
            aws_session_token=aws_session_token,
        )
        result.update(
            {"caller-identity": utils.get_caller_identity(session=session)})

        if regions:
            list_of_regions = utils.get_regions(
                regions_param=regions, session=session)
        else:
            list_of_regions = [session.region_name]

        action_result = dict()
        logging.info(
            f"Going to execute - {action} for asset type - {asset_type}")
        logging.info(f"Going to run over {regions} - region")
        for region in list_of_regions:
            logging.info(f"Working on Region - {region}")
            session = utils.setup_session(
                profile=profile,
                region=region,
                aws_access_key=aws_access_key,
                aws_secret=aws_secret,
                aws_session_token=aws_session_token,
            )
            action_result.update(
                {
                    region: functions_mapping[asset_type](
                        session=session,
                        asset_id=asset_id,
                        action_params=action_params,
                        outputDirectory=outputDirectory,
                        outputType=outputType,
                    )
                }
            )
        result.update(action_result)
    except Exception as e:
        logging.error(f"Something Went wrong!!", exc_info=True)
        result["status"] = "Error"
        result["message"] = str(e)
    filename = os.path.join(
        outputDirectory,
        utils.export_data_filename_with_timestamp(
            f"Tamnoon-LogsInvestigation-{asset_type}-execution-result",
            outputType,
        ),
    )
    utils.export_data_(filename, result)


if __name__ == "__main__":
    main(sys.argv)
