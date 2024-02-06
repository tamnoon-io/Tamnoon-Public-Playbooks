import argparse
import sys
import os
import json
import logging
import datetime


from library.Utils import utils as utils


def print_help():
    text = (
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
        "\t\t Welcome To Tamnoon Azure Network - The script that will help you with your Network Actions \n"
        "\n"
        "\t\t\t Dependencies:\n"
        "\t\t\t\t \n"
        "\t\t\t Authentication:\n"
        "\t\t\t\t The script support the fallback mechanism auth based on azure-identity DefaultAzureCredential \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity#install-the-package"
        "\t\t\t Supported Actions:\n"
        "\t\t\t\t 1. Network Security Group:"
        "\t\t\t\t\t Remove or Replace security rules from a Network Security Group - \n"
        "\n"
        "\t\t\t\t The script is based on Azrue Python SDK and documentation \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main\n"
        "\n\n"
        "\t\t\t Parameter Usage:\n"
        "\t\t\t\t logLevel - The logging level (optional). Default = Info\n"
        "\t\t\t\t subscription (optional) - The Azure Subscription ID to use to execute this script (specific subscription)\n"
        "\t\t\t\t resourceGroups (optional) - The Azure Resource Groups to use to execute this script (specific resource group, list of resource groups - string seperated by commas, or all. default is all)\n"
        "\t\t\t\t regions (optional) - The Azure regions to use to execute this script (specific region, list of regions - string seperated by commas, or all. default is all)\n"
        "\t\t\t\t vnets (optional) - The Virtual Networks to use to execute this script (specific virtual network, list of virtual networks - string seperated by commas, or all. default is all)\n"
        "\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)\n"
        "\t\t\t\t type - The Azure Resource type - for example - network-security-group\n"
        "\t\t\t\t action - The Azure Network API action to execute - (remove_or_replace_security_rules)\n"
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run"\n'
        '\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters"\n'
        '\t\t\t\t outputType (optional) - the type of output of script exucution. available options are json (default) and csv "\n'
        '\t\t\t\t outDir (optional) - the path to store output of script exucution. default is current working directory "\n'
        '\t\t\t\t testId (optional) - to be used when testing the multiple results of remedy"\n'
        "\n\n"
    )
    print(text)


def do_network_security_group_actions(
    credential,
    action,
    subscription,
    resource_groups,
    vnets,
    asset_ids,
    action_params,
    regions,
    dry_run,
):
    """
    This function executes network security group actions
    :param credential: the AZ authentication creds
    :param action: The action to execute
    :param subscription: subscription ID
    :param resource_groups: list of resource groups' names
    :param vnets: list of virtual networks' names
    :param asset_ids: The specific assets
    :param action_params: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    """
    if action == "remove_or_replace_security_rules":
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
            regions=regions,
            action_params=action_params,
            is_dry_run=dry_run,
        )
    if action == "find_associations":
        from .NSGAssociations import NSGAssociations

        nsga = NSGAssociations(params)
        nsga.populate()
        return nsga.as_dict()


def _do_action(
    credential,
    asset_type,
    subscription,
    resource_groups,
    vnets,
    dry_run,
    action,
    action_parmas,
    asset_ids,
    regions,
):
    if asset_type == "network-security-group":
        return do_network_security_group_actions(
            credential=credential,
            action=action,
            subscription=subscription,
            resource_groups=resource_groups,
            vnets=vnets,
            asset_ids=asset_ids,
            action_params=action_parmas,
            regions=regions,
            dry_run=dry_run,
        )
    return {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", required=False, type=str)
    parser.add_argument("--action", required=False, type=str)

    parser.add_argument("--subscription", required=True, type=str)
    parser.add_argument("--resourceGroups", required=False, type=str, default="all")
    parser.add_argument("--storage-accounts", required=False, type=str, default="all")
    parser.add_argument("--regions", required=False, type=str, default="all")
    parser.add_argument("--vnets", required=False, type=str, default="all")
    parser.add_argument("--assetIds", required=False, type=str)

    parser.add_argument(
        "--actionParams", required=False, type=utils.TypeActionParams, default=None
    )
    parser.add_argument("--authParams", required=False, type=json.loads, default=None)

    parser.add_argument("--logLevel", required=False, type=str, default="INFO")
    parser.add_argument("--dryRun", dest="execute", action="store_false")
    parser.add_argument("--execute", default=False, action="store_true")

    parser.add_argument("--file", required=False, type=str, default=None)
    parser.add_argument("--outputType", required=False, type=str, default="json")
    parser.add_argument("--outDir", required=False, type=str, default="./")
    parser.add_argument("--testId", required=False, type=str)

    if len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    try:
        args = parser.parse_args()
    except Exception as ex:
        ex

    result = None

    params = utils.build_params(args=args)

    action = params.action
    asset_ids = params.assetIds
    asset_ids = asset_ids.split(",") if asset_ids else None

    action_params = params.actionParams
    auth_params = None
    if params.authParams != None:
        auth_params = (
            json.loads(params.authParams)
            if params.authParams and type(params.authParams) != dict
            else params.authParams
        )
    action_params = (
        json.loads(action_params)
        if action_params and type(action_params) != dict
        else action_params
    )
    dry_run = not params.execute
    asset_type = params.type
    output_type = params.outputType.upper()
    output_dir = params.outDir

    subscription = params.subscription

    resource_groups = params.resourceGroups
    resource_groups = resource_groups.split(",")

    # todo - figure regional work
    regions = params.regions
    regions = regions.split(",")

    vnets = params.vnets
    vnets = vnets.split(",")

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
    # utils.setup_session("credential", auth_params)
    result["executionResult"] = _do_action(
        credential=credential,
        asset_type=asset_type,
        action=action,
        subscription=subscription,
        resource_groups=resource_groups,
        vnets=vnets,
        dry_run=dry_run,
        asset_ids=asset_ids,
        action_parmas=action_params,
        regions=regions,
    )

    result_type = "dryrun" if dry_run else "execution"
    if params.testId:
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
