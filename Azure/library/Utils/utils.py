import logging
import json
import yaml
import time
import os


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
            with open(args.file, "r", encoding="utf8") as f:
                file_extension = os.path.splitext(args.file)[1]
                if file_extension in ['.yaml', '.yml', '.YML', '.YAML']:
                    config = yaml.safe_load(f)
                    return Params(config)
                elif file_extension in ['.json', '.JSON']:
                    config = json.load(f)
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
        "sql_server" - azure.mgmt.sql.SqlManagementClient - subscription_id (Required)
        "mysql_flexible_server" - azure.mgmt.rdbms.mysql_flexibleservers - subscription_id (Required)
        "postgresql_flexible_server" - azure.mgmt.rdbms.postgresql_flexibleservers - subscription_id (Required)

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

    if client_type == "sql_server":
        from azure.mgmt.sql import SqlManagementClient

        return SqlManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "mysql_flexible_server":
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient

        return MySQLManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
        )

    if client_type == "postgresql_flexible_server":
        from azure.mgmt.rdbms.postgresql_flexibleservers import (
            PostgreSQLManagementClient,
        )

        return PostgreSQLManagementClient(
            credential=credential, subscription_id=client_params["subscription_id"]
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


def export_data_filename_with_timestamp(file_name, export_format):
    return f"{file_name}-{str(time.time())}.{export_format}"


def export_data(file_name, output, export_format="JSON"):
    """
    This method responsible to export the action execution result

    :param export_format: JSON, CSV
    :param file_path: The path to the result file
    :param output: The text to save
    :return:
    """
    if export_format.upper() == "JSON":
        with open(file_name, "w", encoding="utf8") as f:
            json.dump(output, f, ensure_ascii=False, indent=4)
        logging.info(f"Save execution result to - json to path: {file_name}")
    if export_format.upper() == "CSV":
        import pandas as pd

        pd.json_normalize(output).to_csv(file_name)
        logging.info(f"Save execution result to - csv to path: {file_name}")


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
    return s.count("\\\\") * 2 != s.count("\\")


def TypeActionParams(params):
    if has_single_backslash(params):
        raise Exception(f"--actionParams should not contain single backslash\n{params}")
    return json.loads(params)


def print_version():
    import sys

    print(f"Running on {sys.version}")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")


def isip(s):
    import ipaddress

    try:
        a = ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def isip(s):
    import ipaddress

    try:
        a = ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def iscidr(s):
    import ipaddress

    try:
        a = ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def format_datetime_for_azure_resource_name(value):
    formatted_datetime = value.strftime("%Y-%m-%d-%H-%M-%S")
    return formatted_datetime


def print_help_valid_types(json_data, tamnoon_desc_usage):
    """
    Prints help message for cases without type and action, and displays types with their descriptions.

    :param json_data: JSON object containing types as keys and their descriptions as values.
    :type json_data: dict
    :param tamnoon_desc_usage: JSON object containing usage message.
    :type tamnoon_desc_usage: dict
    :return: None
    """
    if json_data:
        print(f"\nusage: {tamnoon_desc_usage}\n")
        print("Type      :        Description")
        for key in json_data:
            print(key, " : ", json_data[key])
    else:
        logging.info("Help Json Data Is Not Found.")


def type_help(type_json_data):
    """
    Prints help message for the 'type' case and displays actions available for a given type and its description.

    :param type_json_data: JSON object containing actions as keys and their descriptions as values.
    :type type_json_data: dict
    :param json_data: JSON object containing overall description.
    :type json_data: dict
    :return: String containing the formatted help message.
    :rtype: str
    """

    string = ""
    for key in type_json_data:
        string += str(key) + " : " + str(type_json_data[key]) + "\n"
    return string



