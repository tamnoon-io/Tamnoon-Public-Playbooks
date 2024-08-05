import argparse
import sys
import os
import json
import logging
import datetime

from library.Utils import utils as utils

try:
    from Azure.Automations.Network.help_jsons_data import *
except ModuleNotFoundError:
    network_security_group_remove_or_replace_security_rules = dict()
    network_security_group_find_associations = dict()
    common_json_data = dict()


def do_network_security_group_action_remove_or_replace_security_rules(credential,
                                                                      action,
                                                                      subscription,
                                                                      resource_groups,
                                                                      vnets,
                                                                      asset_ids,
                                                                      action_params,
                                                                      regions,
                                                                      dry_run, ):
    from .RemoveOrReplaceSecurityRules import (
        remove_or_replace_security_rules_from_nsgs,
        rollback_remove_or_replace_security_rules_from_nsgs,
    )

    is_roll_back = "rollBack" in action_params and action_params["rollBack"]
    if is_roll_back:
        return rollback_remove_or_replace_security_rules_from_nsgs(
            credential=credential,
            dry_run=dry_run,
            last_execution_result_path=action_params["lastExecutionResultPath"],
        )
    return remove_or_replace_security_rules_from_nsgs(
        credential=credential,
        subscription_id=subscription,
        resource_group_names=resource_groups,
        network_security_group_names=asset_ids,
        vnets=vnets,
        regions=regions,
        action_params=action_params,
        is_dry_run=dry_run,
    )


def do_network_security_group_action_find_associations(credential,
                                                       action,
                                                       subscription,
                                                       resource_groups,
                                                       vnets,
                                                       asset_ids,
                                                       action_params,
                                                       regions,
                                                       dry_run, ):
    from .NSGAssociations import NSGAssociations
    nsga = NSGAssociations(params)
    nsga.populate()
    return nsga.as_dict()


def common_args(parser, args_json_data, json_data):
    parser.add_argument("--subscription", required=False, metavar="", help=args_json_data.get("subscription"),
                        type=str)
    parser.add_argument("--resourceGroups", required=False, metavar="", help=args_json_data.get("resourceGroups"),
                        type=str, default="all")
    parser.add_argument("--regions", required=False, metavar="", help=args_json_data.get("regions"), type=str,
                        default="all")
    parser.add_argument("--assetIds", required=False, metavar="", help=args_json_data.get("assetIds"), type=str,
                        default="all")

    parser.add_argument("--logLevel", required=False, metavar="", type=str, default="INFO",
                        help=args_json_data.get("logLevel"))
    parser.add_argument("--dryRun", required=False, help=args_json_data.get("dryRun"), action="store_true",
                        default=False)

    parser.add_argument("--file", required=False, metavar="", help=args_json_data.get("file"), type=str, default=None)
    parser.add_argument("--outputType", required=False, metavar="", help=args_json_data.get("outputType"), type=str,
                        default="json")
    parser.add_argument("--outDir", required=False, metavar="", help=args_json_data.get("outDir"), type=str,
                        default="./")
    parser.add_argument("--testId", required=False, metavar="", type=str, help=args_json_data.get("testId"))


if __name__ == "__main__":

    parser_usage = common_json_data.get("usage", {}).get("Network", "python3 -m Automations.Network")
    usage = parser_usage + " [-h]"

    if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
        utils.print_help_valid_types(common_json_data.get("help", {}).get("Network"),
                                     usage)
        sys.exit(1)

    parser = argparse.ArgumentParser(usage=parser_usage)

    type_subparsers = parser.add_subparsers(title="type", metavar="")
    network_security_group_parser = type_subparsers.add_parser(name='network-security-group',
                                                               formatter_class=argparse.RawTextHelpFormatter)

    # Remove the default "Positional Arguments" section
    network_security_group_parser._positionals.title = None

    # This dictionary links help content with corresponding actions for the type 'network-security-group'.
    # For example, for the action 'remove_or_replace_security_rules',
    # the associated help content is fetched from 'network_security_group_remove_or_replace_security_rules.get("help")'.
    nsg_help = {
        "remove_or_replace_security_rules":
            network_security_group_remove_or_replace_security_rules.get("help"),
        "find_associations":
            network_security_group_find_associations.get("help")
    }

    nsg_actions = network_security_group_parser.add_subparsers(metavar="",
                                                               description=utils.type_help(
                                                                   nsg_help))

    nsg_action_remove_or_replace_security_rules = nsg_actions.add_parser(
        name="remove_or_replace_security_rules")
    nsg_action_remove_or_replace_security_rules._optionals.title = 'arguments'

    nsg_action_find_associations = nsg_actions.add_parser(
        name="find_associations")
    nsg_action_find_associations._optionals.title = 'arguments'

    action = sys.argv[2]
    if action == "remove_or_replace_security_rules":
        common_args(nsg_action_remove_or_replace_security_rules,
                    network_security_group_remove_or_replace_security_rules.get("cli_args", {}),
                    common_json_data)
        nsg_action_remove_or_replace_security_rules.add_argument(
            "--actionParams", required=False, metavar="", help=network_security_group_remove_or_replace_security_rules.get("cli_args", {}).get("actionParams"),
            type=utils.TypeActionParams, default=None
        )
        nsg_action_remove_or_replace_security_rules.add_argument("--vnets", required=False, metavar="",
                                                                 help=
                                                                 network_security_group_remove_or_replace_security_rules.get("cli_args", {}).get("vnets"), type=str,
                                                                 default="all")
    else:
        if action == "find_associations":
            common_args(nsg_action_find_associations, network_security_group_find_associations.get("cli_args", {}),
                        common_json_data)

    args = parser.parse_args()
    result = None

    params = utils.build_params(args=args)
    asset_ids = params.assetIds.split(",") if args.file is None else params.get('assetIds', ['all'])

    action_params = params.actionParams if args.file is None else params.get('actionParams', {})
    auth_params = None

    action_params = (
        json.loads(action_params)
        if action_params and type(action_params) != dict
        else params.get('actionParams', {})
    )
    dry_run = params.get('dryRun', False)
    asset_type = sys.argv[1]
    output_type = params.outputType.upper()
    output_dir = params.outDir if args.file is None else params.get('outDir', './')

    subscription = params.get('subscription') if args.file is not None else params.subscription

    resource_groups = params.get('resourceGroups',
                                 ['all']) if args.file is not None else params.resourceGroups.split(",")

    # todo - figure regional work
    regions = params.get('regions', ['all']) if args.file is not None else params.regions.split(",")

    utils.log_setup(params["logLevel"])

    if params.get('vnets') is None:
        vnets = ['all']
    elif args.file is None:
        vnets = params['vnets'].split(",")
    else:
        vnets = params.get('vnets', ['all'])

    utils.log_setup(params["logLevel"])

    result = dict(
        {
            "executionDate": datetime.datetime.now().ctime(),
            "executionType": asset_type,
            "executionAction": action,
            "executionResult": [],
            "actionParams": action_params,
        }
    )

    credential = utils.setup_session("default")

    # The following dictionary maps functions to their corresponding types and actions.
    # For instance, for the type 'network-security-group' and action 'remove_or_replace_security_rules',
    # the function 'do_network_security_group_action_remove_or_replace_security_rules' is mapped.
    functions_mapping = {
        'network-security-group': {
            'remove_or_replace_security_rules': do_network_security_group_action_remove_or_replace_security_rules,
            'find_associations': do_network_security_group_action_find_associations}
    }
    result["executionResult"] = functions_mapping[asset_type][action](credential=credential,
                                                                      action=action,
                                                                      subscription=subscription,
                                                                      resource_groups=resource_groups,
                                                                      vnets=vnets,
                                                                      dry_run=dry_run,
                                                                      asset_ids=asset_ids,
                                                                      action_params=action_params,
                                                                      regions=regions, )

    result_type = "dryrun" if dry_run else "execution"

    result["testId"] = params.testId
    if not output_dir.endswith("/"):
        output_dir = output_dir + "/"
    result["stateFile"] = utils.export_data_filename_with_timestamp(
        f"{output_dir}Tamnoon-Azure-Storage-{asset_type if asset_type != None else ''}-{action if action != None else ''}-{result_type}-result.{output_type}",
        export_format="JSON",
    )
    utils.export_data(
        result["stateFile"],
        result,
        export_format=(output_type),
    )
    print()
    print(f"find logs in {os.path.abspath(result['stateFile'])}")
