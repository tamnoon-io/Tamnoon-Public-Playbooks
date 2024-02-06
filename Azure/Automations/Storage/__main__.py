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
        "\t\t Welcome To Tamnoon Azure Storage - The script that will help you with your  Storage Actions \n"
        "\n"
        "\t\t\t Dependencies:\n"
        "\t\t\t\t \n"
        "\t\t\t Authentication:\n"
        "\t\t\t\t The script support the fallback mechanism auth based on azure-identity DefaultAzureCredential \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity#install-the-package"
        "\t\t\t Supported Actions:\n"
        "\t\t\t\t 1. Blob Container:"
        "\t\t\t\t\t Replace public configuration from a Blob container - \n"
        "\t\t\t\t\t Enable log analytics with diagnostics on a Blob container - \n"
        "\t\t\t\t 2. Storage Account:"
        "\t\t\t\t\t Restrict public network access to storage accounts by virtual networks or ip address or CIDR range - \n"
        "\n"
        "\t\t\t\t The script is based on Azrue Python SDK and documentation \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main\n"
        "\n\n"
        "\t\t\t Parameter Usage:\n"
        "\t\t\t\t logLevel - The logging level (optional). Default = Info\n"
        "\t\t\t\t subscriptions (optional) -   The Azure Subscription ID to use to execute this script (specific subscription ID, comma separated list of subscription IDs, or All)\n"
        "\t\t\t\t resourceGroups (optional) -   The Azure Resource Groups to use to execute this script (specific Resource Group, comma separated list of Resource Groups, or All)\n"
        "\t\t\t\t storageAccounts (optional) -   The Azure Storage Accounts to use to execute this script (specific Storage Account, comma separated list of Storage Accounts, or All)\n"
        "\t\t\t\t regions (optional) -   The Azure regions to use to execute this script (specific region, list of regions, or All)\n"
        "\t\t\t\t type -     The Azure Storage type - for example - blob-container, storage-account ....\n"
        "\t\t\t\t action -   The Azure AStorage API action to execute - (remove_public_access_storage_containers, enable_log_analytics_logs_for_azure_storage_blobs, remove_public_network_access)\n"
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run"\n'
        '\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters"\n'
        '\t\t\t\t outputType (optional) - the type of output of script exucution. available options are json (default) and csv "\n'
        '\t\t\t\t outDir (optional) - the path to store output of script exucution. default is current working directory "\n'
        "\n\n"
    )
    print(text)


def do_blob_container_actions(
    credential,
    action,
    subscriptions,
    resource_groups,
    storage_accounts,
    regions,
    asset_ids,
    action_parmas,
    dry_run,
):
    """
    This function execute blob container actions
    :param creds: the AZ authentication creds
    :param action: The action to execute
    :param asset_ids: The specific assets
    :param action_parmas: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    """

    result = dict()
    if action == "remove_public_access_storage_containers":
        from . import StorageAccountPublicAccess

        if StorageAccountPublicAccess.validate_action_params(action_parmas):
            is_roll_back = "rollBack" in action_parmas and action_parmas["rollBack"]
            if is_roll_back:
                is_roll_back = "rollBack" in action_parmas and action_parmas["rollBack"]
            if is_roll_back:
                return StorageAccountPublicAccess.rollback_public_access(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_parmas["lastExecutionResultPath"],
                )
            return StorageAccountPublicAccess.remove_public_access(
                credential=credential,
                action_params=action_params,
                subscriptions=subscriptions,
                resource_groups=resource_groups,
                storage_accounts=storage_accounts,
                blob_containers=asset_ids,
                regions=regions,
                is_dry_run=dry_run,
            )

    if action == "enable_log_analytics_logs_for_azure_storage_blobs":
        from . import StorageAccountLogging

        if StorageAccountLogging.validate_action_params(action_parmas):
            is_roll_back = "rollBack" in action_parmas and action_parmas["rollBack"]
            if is_roll_back:
                return StorageAccountLogging.rollback_enable_storage_logging(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_parmas["lastExecutionResultPath"],
                )
            result = StorageAccountLogging.enable_storage_logging(
                credential=credential,
                dry_run=dry_run,
                subscriptions=subscriptions,
                resource_group_names=resource_groups,
                storage_accounts=storage_accounts,
                regions=regions,
                action_params=action_parmas,
            )
            return result
        return []


def do_storage_account_actions(
    credential,
    action,
    subscriptions,
    resource_groups,
    storage_accounts,
    regions,
    asset_ids,
    action_params,
    dry_run,
):
    """
    This function execute storage account actions
    :param credential: the AZ authentication creds
    :param action: The action to execute
    :param asset_ids: The specific assets
    :param action_params: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    """
    result = dict()
    if action == "remove_public_network_access":
        from . import StorageAccountNetworkAccess

        if StorageAccountNetworkAccess.validate_action_params(action_params):
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                return StorageAccountNetworkAccess.rollback_restrict_network_access(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_params["lastExecutionResultPath"],
                )
            return StorageAccountNetworkAccess.restrict_network_access(
                credential=credential,
                dry_run=dry_run,
                subscription_ids=subscriptions,
                resource_group_names=resource_groups,
                storage_account_names=storage_accounts,
                regions=regions,
                action_params=action_params,
            )
        return []


def _do_action(
    credential,
    asset_type,
    subscriptions,
    resource_groups,
    storage_accounts,
    regions,
    dry_run,
    action,
    action_parmas,
    asset_ids,
):
    if asset_type == "blob-container":
        return do_blob_container_actions(
            credential=credential,
            action=action,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            storage_accounts=storage_accounts,
            regions=regions,
            asset_ids=asset_ids,
            action_parmas=action_parmas,
            dry_run=dry_run,
        )
    if asset_type == "storage-account":
        return do_storage_account_actions(
            credential=credential,
            action=action,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            storage_accounts=storage_accounts,
            regions=regions,
            asset_ids=asset_ids,
            action_params=action_parmas,
            dry_run=dry_run,
        )
    if asset_type == "storage-account":
        return do_storage_account_actions(
            credential=credential,
            action=action,
            asset_ids=asset_ids,
            action_params=action_parmas,
            regions=regions,
            dry_run=dry_run,
        )
    return {}


if __name__ == "__main__":
    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", required=False, type=str)
    parser.add_argument("--action", required=False, type=str)

    parser.add_argument("--subscriptions", required=False, type=str, default="all")
    parser.add_argument("--resourceGroups", required=False, type=str, default="all")
    parser.add_argument("--storageAccounts", required=False, type=str, default="all")
    parser.add_argument("--regions", required=False, type=str, default="all")
    parser.add_argument("--assetIds", required=False, type=str, default="all")

    parser.add_argument(
        "--actionParams",
        required=False,
        type=utils.TypeActionParams,
        default=None,
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

    args = parser.parse_args()

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

    subscriptions = params.subscriptions
    subscriptions = subscriptions.split(",")

    resource_groups = params.resourceGroups
    resource_groups = resource_groups.split(",")

    storage_accounts = params.storageAccounts
    storage_accounts = storage_accounts.split(",")

    # todo - figure regional work
    regions = params.regions
    regions = regions.split(",")

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

    credential = None
    if auth_params != None:
        credential = utils.setup_session("shared-key", auth_params)
    else:
        credential = utils.setup_session("default")
    # utils.setup_session("credential", auth_params)
    result["executionResult"] = _do_action(
        credential=credential,
        asset_type=asset_type,
        action=action,
        subscriptions=subscriptions,
        resource_groups=resource_groups,
        storage_accounts=storage_accounts,
        regions=regions,
        asset_ids=asset_ids,
        action_parmas=action_params,
        dry_run=dry_run,
    )

    result_type = "dryrun" if dry_run else "execution"
    if params.testId:
        result["testId"] = params.testId
    if not output_dir.endswith("/"):
        output_dir = output_dir + "/"
    result["stateFile"] = utils.export_data_filename_with_timestamp(
        f"{output_dir}Tamnoon-Azure-Storage-{asset_type if asset_type != None else ''}-{action.replace('_', '-') if action != None else ''}-{result_type}-result.{output_type}",
        output_type,
    )
    utils.export_data(
        result["stateFile"],
        result,
        export_format=(output_type),
    )
    print()
    print(f"find logs in {os.path.abspath(result['stateFile'])}")
