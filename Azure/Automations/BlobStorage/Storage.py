import argparse
import sys
import os
import json
import logging
import datetime

___directory_depth = 2
___relative_path = "TamnoonPlaybooks/Azure/"

___splits = sys.path[0].split("/")
___import_path = os.path.join(
    "/".join(___splits[0 : ___splits.__len__() - ___directory_depth]), ___relative_path
)
sys.path.append(___import_path)


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
        "\t\t\t\t\t Remove public configuration from a Blob container - \n"
        "\t\t\t\t\t Enable log analytics with diagnostics on a Blob container - \n"
        "\n"
        "\t\t\t\t The script is based on Azrue Python SDK and documentation \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main\n"
        "\n\n"
        "\t\t\t Parameter Usage:\n"
        "\t\t\t\t logLevel - The logging level (optional). Default = Info\n"
        "\t\t\t\t regions (optional) -   The Azure regions to use to execute this script (specific region, list of regions, or All)\n"
        "\t\t\t\t type -     The Azure Storage type - for example - blob-container ....\n"
        "\t\t\t\t action -   The Azure AStorage API action to execute - (remove-public, enable-log-analytics-logs-for-azure-storage-blobs)\n"
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run"\n'
        '\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters"\n'
        '\t\t\t\t outputType (optional) - the type of output of script exucution. available options are json (default) and csv "\n'
        '\t\t\t\t outDir (optional) - the path to store output of script exucution. default is current working directory "\n'
        "\n\n"
    )
    print(text)


def do_remove_public(
    client, asset, dry_run, is_roll_back, last_execution_result_path, result
):
    """
    This is a specific function that remove/revert public configuration over Azure Blob Container
    :param creds:
    :param asset:
    :param dry_run:
    :param is_roll_back:
    :return:
    """

    from azure.storage.blob import BlobServiceClient

    # Create a BlobServiceClient using your account name and key
    try:
        result[asset]["is_dry_run"] = False
        if dry_run:
            logging.info(
                f"#################### This is a Dry Run ###########################"
            )
            result[asset]["is_dry_run"] = True

        blob_service_client = client

        # Get a reference to the container
        container_client = blob_service_client.get_container_client(asset)
        policy = container_client.get_container_access_policy()

        # build the signed identifier as they are today because we want to save them as is in the set_container_access_policy call
        concurrent_signed_identifier = dict()
        for identifier in policy["signed_identifiers"]:
            concurrent_signed_identifier[
                identifier.id
            ] = identifier.access_policy.permission

        if not is_roll_back:
            logging.info(
                f"Going to remove public configuration from blob container - {asset}"
            )
            if not dry_run:
                container_client.set_container_access_policy(
                    public_access=None, signed_identifiers=concurrent_signed_identifier
                )
                result[asset]["status"] = "Success"
                result[asset]["prev_state"] = {
                    "pubic_access": policy["public_access"],
                    "signed_identifiers": concurrent_signed_identifier,
                }
            else:
                logging.info(
                    f"Dry run - access policy for {asset} could changed  to None"
                )
        else:
            logging.info(
                f"This is a roll back execution - going to revert changes based on last execution file - {last_execution_result_path}"
            )
            result[asset]["type"] = "roll-back"
            with open(last_execution_result_path, "r") as prev_state:
                prev_state_json = json.load(prev_state)
                current_asset_last_state = prev_state_json[asset]
                container_client.set_container_access_policy(
                    public_access=current_asset_last_state["prev_state"][
                        "pubic_access"
                    ],
                    signed_identifiers=current_asset_last_state["prev_state"][
                        "signed_identifiers"
                    ],
                )
                result[asset]["status"] = "Success"

        return result

    except Exception as e:
        logging.error(f"Something went wrong - {e}")
        result[asset]["status"] = "Failed"
        result[asset]["reason"] = f"{e}"
        return result


def do_blob_container_actions(
    credential, action, asset_ids, action_parmas, regions, dry_run
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
    if action == "remove-public":
        for asset in asset_ids:
            result[asset] = dict()
            result[asset]["action"] = "remove-public"
            is_roll_back = False
            last_execution_result_path = None
            if "rollBack" in action_parmas:
                is_roll_back = action_parmas["rollBack"]
                if "lastExecutionResultPath" not in action_parmas:
                    raise "You trying to execute roll back with no 'lastExecutionResultPath' parameter, the script have to know the previous saved state"
                last_execution_result_path = action_parmas["lastExecutionResultPath"]
            client = utils.get_client(
                credential=credential,
                client_type="blob_service",
                client_params=dict({"StorageAccountName": asset}),
            )
            return do_remove_public(
                client=client,
                asset=asset,
                dry_run=dry_run,
                is_roll_back=is_roll_back,
                last_execution_result_path=last_execution_result_path,
                result=result,
            )

    if action == "enable-log-analytics-logs-for-azure-storage-blobs":
        from ..StorageAccount import StorageAccountLogging

        if StorageAccountLogging.validate_action_params(action_parmas):
            is_roll_back = "rollBack" in action_parmas and action_parmas["rollBack"]
            if is_roll_back:
                return StorageAccountLogging.rollback_enable_storage_logging(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_parmas["lastExecutionResultPath"],
                )
            result = []
            for storage_account in asset_ids:
                result.append(
                    StorageAccountLogging.enable_storage_logging(
                        credential=credential,
                        dry_run=dry_run,
                        regions=regions,
                        action_params=action_parmas,
                        storage_account_name=storage_account,
                    )
                )
            return result
        return []


def _do_action(
    credential,
    asset_type,
    dry_run,
    action,
    action_parmas,
    asset_ids,
    regions,
):
    if asset_type == "blob-container":
        return do_blob_container_actions(
            credential=credential,
            action=action,
            asset_ids=asset_ids,
            action_parmas=action_parmas,
            regions=regions,
            dry_run=dry_run,
        )
    return {}


if __name__ == "__main__":
    # TODO - Work on desc for params
    # TODO - support rollback
    parser = argparse.ArgumentParser()
    parser.add_argument("--logLevel", required=False, type=str, default="INFO")
    parser.add_argument("--type", required=False, type=str)
    parser.add_argument("--action", required=False, type=str)
    parser.add_argument("--regions", required=False, type=str, default=None)
    parser.add_argument("--assetIds", required=False, type=str)
    parser.add_argument("--actionParams", required=False, type=json.loads, default=None)
    parser.add_argument("--authParams", required=False, type=json.loads, default=None)
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

    # todo - figure regional work
    regions = params.regions
    regions = regions.split(",") if regions else None

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
        dry_run=dry_run,
        action=action,
        asset_ids=asset_ids,
        action_parmas=action_params,
        regions=regions,
    )

    result_type = "dryrun" if dry_run else "execution"
    if params.testId:
        result["testId"] = params.testId
    result[
        "stateFile"
    ] = f"{output_dir}Tamnoon-Azure-Storage-{asset_type if asset_type != None else ''}-{action if action != None else ''}-{result_type}-result.{output_type}"
    if not output_dir.endswith("/"):
        output_dir = output_dir + "/"
    utils.export_data(
        f"{output_dir}Tamnoon-Azure-Storage-{asset_type}-{action}-{result_type}-result",
        result,
        export_format=(output_type),
    )
