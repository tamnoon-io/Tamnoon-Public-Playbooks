import logging
import json
import yaml
import time


class Params(dict):
    """
    This class represent the Tamnoon Automation params
    It will be built based on dict object that containt the params key and value
    First class params
        logLevel - The level of the execution logging
        type - The target asset type - ec2/vpc... wil determine the action type
        action - The action
        dryRun - execute in dryrun mode (in case of dryrun no actual execution will happen)
        assetIds - on eor more asset id to execute on

    """

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
    logging.basicConfig(
        format="[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s"
    )
    log_level = log_l
    logging.getLogger().setLevel(log_level)


def get_client(credential, client_type, client_params=None):
    """
    Factory method returns the instance of Azure Client

    credential - (Required) Azure Credential.

    client_params - (Optional) dictionary containing values necessary to
    instantiate the client

    client_type - (Required) Following client types are supported

        client_type - generates instance of Client - with client_params dictionary having
        ===========   ============================   =====================================
        "subscription_management" - azure.mgmt.subscription.SubscriptionClient - None
        "monitor_management" - azure.mgmt.monitor.MonitorManagementClient - subscription_id (Required)
        "storage_management" - azure.mgmt.storage.StorageManagementClient - subscription_id (Required)
        "resource_management" - azure.mgmt.resource.ResourceManagementClient - subscription_id (Required)
        "log_analytics_management" - azure.mgmt.loganalytics.LogAnalyticsManagementClient - subscription_id (Required)
        "network_management" - azure.mgmt.network.NetworkManagementClient - subscription_id (Required)
        "blob_service" - azure.storage.blob.BlobServiceClient - StorageAccountName (Required)

    """
    if credential == None:
        raise Exception("credential is not found")

    if client_type == "subscription_management":
        from azure.mgmt.subscription import SubscriptionClient

        return SubscriptionClient(credential=credential)

    if client_type == "monitor_management":
        if "subscription_id" not in client_params:
            raise Exception(
                f"subscription_id is required for client_type {client_type}"
            )
        from azure.mgmt.monitor import MonitorManagementClient

        return MonitorManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "storage_management":
        if "subscription_id" not in client_params:
            raise Exception(
                f"subscription_id is required for client_type {client_type}"
            )
        from azure.mgmt.storage import StorageManagementClient

        return StorageManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "resource_management":
        if "subscription_id" not in client_params:
            raise Exception(
                f"subscription_id is required for client_type {client_type}"
            )
        from azure.mgmt.resource import ResourceManagementClient

        return ResourceManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "log_analytics_management":
        if "subscription_id" not in client_params:
            raise Exception(
                f"subscription_id is required for client_type {client_type}"
            )
        from azure.mgmt.loganalytics import LogAnalyticsManagementClient

        return LogAnalyticsManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "network_management":
        if "subscription_id" not in client_params:
            raise Exception(
                f"subscription_id is required for client_type {client_type}"
            )
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "blob_service":
        if "StorageAccountName" not in client_params:
            raise Exception(
                f"StorageAccountName is required for client_type {client_type}"
            )
        from azure.storage.blob import BlobServiceClient

        return BlobServiceClient(
            credential=credential,
            account_url=f"https://{client_params['StorageAccountName']}.blob.core.windows.net",
        )

    return None


def setup_session(auth_type, auth_params=None):
    """
    This method setup the Azure Authz creds

    :return:
    """
    if auth_type == "default":
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential(exclude_interactive_browser_credential=False)

    if auth_type == "shared-key":
        if "StorageAccountName" not in auth_params or "accessKey" not in auth_params:
            raise Exception(
                "Missing required Authentication parameters -  storage_account_name, access_account_key"
            )
        return {
            "account_name": f"{auth_params['StorageAccountName']}",
            "account_key": f"{auth_params['accessKey']}",
        }


def export_data(file_name, output, export_format="JSON"):
    """
    This method responsible to export the action execution result

    :param export_format: JSON, CSV
    :param file_path: The path to the result file
    :param output: The text to save
    :return:
    """
    file_name_with_timestamp = f"{file_name}-{str(time.time())}.{export_format}"
    if export_format == "JSON":
        with open(file_name_with_timestamp, "w") as f:
            json.dump(output, f, ensure_ascii=False, indent=4)
        logging.info(
            f"Save execution result to - json to path: {file_name_with_timestamp}"
        )
    if export_format == "CSV":
        import pandas as pd

        pd.json_normalize(output).to_csv(file_name_with_timestamp)
        logging.info(
            f"Save execution result to - csv to path: {file_name_with_timestamp}"
        )
    return file_name_with_timestamp


def is_parent_directory(directory_path, file_path):
    import os

    if directory_path == file_path:
        return True

    directory_path_match_expr = os.path.abspath(directory_path)
    file_path_match_expr = os.path.abspath(file_path)
    output_str = file_path_match_expr.replace(directory_path_match_expr, "")

    return output_str.count("/") == 1


def remove_empty_from_list(value=[]):
    return list(filter(lambda item: item is not None, value))


def resolve_path_backslash(s):
    """
    replaces all occurances of single '\\' from the string s with '\\\\'.
    It is useful when path is supposed to be in form 'C:\\Users\\username\\Documents\\file.json'.
    But when having the string parsed through escape-character-sensitive methods,
    such as json.loads, it may raise error. So we first use resolve_path_backslash
    on such strings, and then further operations can be performed on it

    :param s: (Required) input string that may contain file path

    :return: str
    """

    s = s.replace("\\\\", "____")
    s = s.replace("\\", "\\\\")
    s = s.replace("____", "\\\\")
    return s


def has_single_backslash(s):
    return s.count("\\") != (s.count("\\\\") * 2)


def validate_args(args):
    __error_in_arg = ""
    for arg in args:
        if has_single_backslash(arg):
            raise ValueError(f"{__error_in_arg} should not contain single backslash")
        else:
            __error_in_arg = arg
