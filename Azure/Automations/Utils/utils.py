
import logging
import json
import yaml
import time
from azure.identity import DefaultAzureCredential


class Params(dict):
    '''
    This class represent the Tamnoon Automation params
    It will be built based on dict object that containt the params key and value
    First class params
        logLevel - The level of the execution logging
        type - The target asset type - ec2/vpc... wil determine the action type
        action - The action
        dryRun - execute in dryrun mode (in case of dryrun no actual execution will happen)
        assetIds - on eor more asset id to execute on

    '''
    def __init__(self, *args, **kwargs):
        super(Params, self).__init__(*args, **kwargs)

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Params, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Params, self).__delitem__(key)
        del self.__dict__[key]


def build_params(args):
    """
    This function will build the params set for specific execution (based on file or cli)
    :param args:
    :return:
    """
    # Get params from file
    if args.file:
        try:
            with open(args.file, "r") as f:
                config = yaml.safe_load(f)
                return Params(config)
        except Exception as e:
            logging.error(f"Something went wrong with file reading - {e}")
    else:
        return Params(args.__dict__)

def log_setup(log_l):
    """This method setup the logging level an params
        logs output path can be controlled by the log stdout cmd param (stdout / file)
    """
    logging.basicConfig(format='[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s')
    log_level = log_l
    logging.getLogger().setLevel(log_level)


def setup_session(auth_type, client_type, auth_params=None):
    '''
    This method setup the Azure DefaultAzureCredential Authz creds

    :return:
    '''
    if auth_type == "default":
        default_credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
        return default_credential
    if auth_type == "shared-key":
        if client_type=="blob_service":
            if 'StorageAccountName' not in auth_params or 'accessKey' not in auth_params:
                raise "Missing required Authentication parameters -  storage_account_name, access_account_key"

            from azure.storage.blob import BlobServiceClient
            return BlobServiceClient(account_url=f"https://{auth_params['StorageAccountName']}.blob.core.windows.net",
                                        credential={"account_name": f"{auth_params['StorageAccountName']}",
                                                    "account_key": f"{auth_params['accessKey']}"})

        pass



def export_data(file_name, output, export_format='JSON'):
    """
    This method responsible to export the action execution result

    :param export_format: JSON, CSV
    :param file_path: The path to the result file
    :param output: The text to save
    :return:
    """
    if export_format == 'JSON':
        with open(f"{file_name}-{str(time.time())}.json", "w") as f:
            json.dump(output, f, ensure_ascii=False, indent=4)
        logging.info(f"Save execution result to - json to path: {file_name}-{str(time.time())}.json")
    if export_format == "CSV":
        import pandas as pd
        pd.json_normalize(output).to_csv(f"{file_name}-{str(time.time())}.csv")
        logging.info(f"Save execution result to - csv to path: {file_name}-{str(time.time())}.csv")