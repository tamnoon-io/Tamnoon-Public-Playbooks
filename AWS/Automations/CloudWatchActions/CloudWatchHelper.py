import logging
import json
import argparse
import os
import sys
from datetime import datetime, timedelta
import time
import re

from Automations.Utils import utils


def _do_query_execution(
    session, region, action, asset_ids, action_params, output_directory
):
    hoursback = action_params["hoursback"] if "hoursback" in action_params else None

    if action == "flow_log":
        from . import flowlog_query_builder, get_cloudwatch_data

        log_group = action_params["log_group"] if "log_group" in action_params else None
        dst_addr = action_params["dstAddr"] if "dstAddr" in action_params else None
        dst_port = action_params["dstPort"] if "dstPort" in action_params else None
        interfac_ids = asset_ids
        exclude_private_ips_from_source = (
            action_params["excludePrivateIPsFromSource"]
            if "excludePrivateIPsFromSource" in action_params
            else None
        )
        exclude_src_ports=(
            action_params["exclude_src_ports"]
            if "exclude_src_ports" in action_params
            else None
        )
        if not log_group or not (dst_addr or interfac_ids or dst_port):
            logging.error(
                "you have to include log_group and dstAddr or interfaceId or dst_port params. Quiting"
            )
            exit()

        query = flowlog_query_builder(
            session=session,
            dst_addr=dst_addr,
            interface_ids=interfac_ids,
            dst_port=dst_port,
            exclude_private_ips_from_source=exclude_private_ips_from_source,
            exclude_src_ports=exclude_src_ports,
        )

        output = get_cloudwatch_data(
            session=session, log_group=log_group, query=query, hoursback=hoursback
        )

        return output


def _do_action(
    action_type,
    session,
    region,
    dry_run,
    action,
    asset_ids,
    action_params,
    output_directory,
):
    """
    This function route between Cloud Watch actions
    :param action_type: The specific action type watch action to execute
    :param session: The boto session to use
    :param dry_run: dry run flag
    :param action: The sub cloud watch action to execute
    :param asset_ids: List of cloud asset ids to works on
    :param action_parmas: The specific action's parameters
    :return:
    """

    if action_type == "query":
        return _do_query_execution(
            session=session,
            region=region,
            action=action,
            asset_ids=asset_ids,
            action_params=action_params,
            output_directory=output_directory,
        )


if __name__ == "__main__":
    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument("--logLevel", required=False, type=str, default="INFO")
    parser.add_argument(
        "--file", type=str, help="YAML file containing arguments.", default=None
    )
    parser.add_argument("--profile", required=False, type=str, default=None)
    parser.add_argument("--type", required=False, type=str, default="query")
    parser.add_argument("--action", required=False, type=str, default="flow_log")
    parser.add_argument("--actionParams", required=False, type=json.loads, default=None)
    parser.add_argument("--assetIds", required=False, type=str)
    parser.add_argument("--awsAccessKey", required=False, type=str, default=None)
    parser.add_argument("--awsSecret", required=False, type=str, default=None)
    parser.add_argument("--awsSessionToken", required=False, type=str, default=None)
    parser.add_argument(
        "--outputDirectory", required=False, type=str, default=os.getcwd()
    )
    parser.add_argument("--outputType", required=False, type=str, default="JSON")
    parser.add_argument("--dryRun", required=False, type=bool, default=False)
    parser.add_argument(
        "--fileoutputstr", required=False, type=str, default="TamnoonCloudWatchQuery"
    )
    parser.add_argument("--regions", required=False, type=str, default="us-east-1")

    args = parser.parse_args()
    utils.log_setup(args.logLevel)

    params = utils.build_params(args=args)

    profile = params.profile
    action = params.action
    action_type = params.type
    regions = params.regions
    asset_ids = params.assetIds

    action_params = params.actionParams if params.actionParams != None else dict()
    action_params = (
        json.loads(action_params)
        if action_params and type(action_params) != dict
        else action_params
    )
    aws_access_key_id = params.awsAccessKey
    aws_secret_access_key = params.awsSecret
    aws_session_token = params.awsSessionToken
    dry_run = params.dryRun
    output_type = params.outputType if params.outputType else "csv"
    output_directory = params.outputDirectory if params.outputDirectory else os.getcwd()
    fileoutputstr = (
        params.fileoutputstr if params.fileoutputstr else "TamnoonCloudWatchQuery"
    )
    result = dict()

    logging.info(f"Going to run over {regions} - region")
    session = utils.setup_session(
        profile=profile,
        aws_access_key=aws_access_key_id,
        aws_secret=aws_secret_access_key,
        aws_session_token=aws_session_token,
    )
    caller_identity = utils.get_caller_identity(session=session)
    result["caller-identity"] = caller_identity
    list_of_regions = utils.get_regions(regions_param=regions, session=session)
    for region in list_of_regions:
        logging.info(f"Working on Region - {region}")
        session = utils.setup_session(
            profile=profile,
            region=region,
            aws_access_key=aws_access_key_id,
            aws_secret=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )
        action_result = _do_action(
            action_type=action_type,
            session=session,
            region=region,
            dry_run=dry_run,
            action=action,
            asset_ids=asset_ids,
            action_params=action_params,
            output_directory=output_directory,
        )
        logging.info(f"output record number is: {str(len(action_result))}")
        if action_result:
            result[region] = action_result
        else:
            result[region] = {}

        logging.info(f"Going to persist output to: {fileoutputstr}-{region}")
        utils.export_data(
            file_name=os.path.join(
                output_directory, f"{fileoutputstr}-{region}" + "." + output_type
            ),
            output=action_result,
            export_format=output_type.upper(),
        )
