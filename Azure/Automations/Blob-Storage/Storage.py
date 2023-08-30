import argparse
import sys
import json
import logging

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
        '\t\t Welcome To Tamnoon Azure Storage - The script that will help you with your  Storage Actions \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t Authentication:\n'
        '\t\t\t\t The script support the fallback mechanism auth based on azure-identity DefaultAzureCredential \n'
        '\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity#install-the-package'
      
        '\t\t\t Supported Actions:\n'
        '\t\t\t\t 1. Blob Container:'
        '\t\t\t\t\t Remove public configuration from a Blob container - \n'
        

        '\n'
        '\t\t\t\t The script is based on Azrue Python SDK and documentation \n'
        '\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t regions (optional) -   The Azure regions to use to execute this script (specific region, list of regions, or All)\n'
        '\t\t\t\t type -     The Azure Storage type - for example - blob-container ....\n'
        '\t\t\t\t action -   The Azure AStorage API action to execute - (remove-public)\n'
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run"\n'
        '\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters"\n'
        '\n\n'

    )
    print(text)


def do_remove_public(client, asset, dry_run, is_roll_back, last_execution_result_path, result):
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
        result[asset]['is_dry_run'] = False
        if dry_run:
            logging.info(f"#################### This is a Dry Run ###########################")
            result[asset]['is_dry_run'] = True

        blob_service_client = client

        # Get a reference to the container
        container_client = blob_service_client.get_container_client(asset)
        policy = container_client.get_container_access_policy()

        # build the signed identifier as they are today because we want to save them as is in the set_container_access_policy call
        concurrent_signed_identifier = dict()
        for identifier in policy['signed_identifiers']:
            concurrent_signed_identifier[identifier.id] = identifier.access_policy.permission

        if not is_roll_back:
            logging.info(f"Going to remove public configuration from blob container - {asset}")
            if not dry_run:
                container_client.set_container_access_policy(public_access=None, signed_identifiers=concurrent_signed_identifier)
                result[asset]['status'] = 'Success'
                result[asset]['prev_state'] = {"pubic_access":policy['public_access'], 'signed_identifiers':concurrent_signed_identifier}
            else:
                logging.info(f"Dry run - access policy for {asset} could changed  to None")
        else:
            logging.info(f"This is a roll back execution - going to revert changes based on last execution file - {last_execution_result_path}")
            result[asset]['type'] = 'roll-back'
            with open(last_execution_result_path, 'r') as prev_state:
                prev_state_json = json.load(prev_state)
                current_asset_last_state = prev_state_json[asset]
                container_client.set_container_access_policy(public_access=current_asset_last_state['prev_state']['pubic_access'],
                                                             signed_identifiers=current_asset_last_state['prev_state']['signed_identifiers'])
                result[asset]['status'] = 'Success'

        return result

    except Exception as e:
        logging.error(f"Something went wrong - {e}")
        result[asset]['status'] = 'Failed'
        result[asset]['reason'] = f"{e}"
        return result




def do_blob_container_actions(client, action, asset_ids, action_parmas, dry_run):
    '''
    This function execute blob container actions
    :param creds: the AZ authentication creds
    :param action: The action to execute
    :param asset_ids: The specific assets
    :param action_parmas: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    '''


    result = dict()
    if action == "remove-public":
        for asset in asset_ids:
            result[asset] = dict()
            result[asset]['action'] = "remove-public"
            is_roll_back = False
            last_execution_result_path = None
            if 'rollBack' in action_parmas:
                is_roll_back = action_parmas["rollBack"]
                if "lastExecutionResultPath" not in action_parmas:
                    raise "You trying to execute roll back with no 'lastExecutionResultPath' parameter, the script have to know the previous saved state"
                last_execution_result_path = action_parmas["lastExecutionResultPath"]



            return do_remove_public(client=client, asset=asset, dry_run=dry_run, is_roll_back=is_roll_back, last_execution_result_path=last_execution_result_path,result=result)



def _do_action(asset_type, client, dry_run, action, asset_ids, action_parmas):
    if asset_type == 'blob-container':
        return do_blob_container_actions(client=client, action=action, asset_ids=asset_ids, action_parmas=action_parmas, dry_run=dry_run)
    return {}


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--type', required=False, type=str)
    parser.add_argument('--action', required=False, type=str)
    parser.add_argument('--regions', required=False, type=str, default=None)
    parser.add_argument('--assetIds', required=False, type=str)
    parser.add_argument('--actionParams', required=False, type=json.loads, default=None)
    parser.add_argument('--authParams', required=False, type=json.loads, default=None)
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


    action = params.action
    asset_ids = params.assetIds
    asset_ids = asset_ids.split(',') if asset_ids else None

    action_params = params.actionParams
    auth_params = params.authParams
    auth_params = json.loads(auth_params) if auth_params and type(auth_params) != dict else auth_params
    action_params = json.loads(action_params) if action_params and type(action_params) != dict else action_params
    dry_run = params.dryRun
    asset_type = params.type

    # todo - figure regional work
    regions = None


    result = dict()

    client = utils.setup_session(auth_type="shared-key", client_type="blob_service", auth_params=auth_params)

    action_result = _do_action(asset_type=asset_type, client=client, dry_run=dry_run, action=action,
                               asset_ids=asset_ids,
                               action_parmas=action_params)


    utils.export_data(f"Tamnoon-Azure-Storage-{asset_type}-{action}-execution-result", action_result)