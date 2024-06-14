import logging
import time
import json
from datetime import datetime
from library.Utils.execution_result import AzureExecutionResult
from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import (
    isip,
    get_client,
    format_datetime_for_azure_resource_name,
)
from library.DBServer.DBAction import DBTypes
from library.DBServer import (
    SQLServerUtils,
    MySQLFlexibleServerUtils,
    PostgreSQLFlexibleServerUtils,
)
from library.DBServer.DBActionsGenerator import (
    SQLServerActionsGenerator,
    MySQLFlexibleServerActionsGenerator,
    PostgreSQLFlexibleServerActionsGenerator,
)

AZURE_SQL_SERVER = "Microsoft.Sql/servers"
AZURE_MYSQL_SERVER = "Microsoft.DBforMySQL/flexibleServers"
AZURE_POSTGRE_SQL_SERVER = "Microsoft.DBforPostgreSQL/flexibleServers"
AZURE_SQL_SERVER_FIREWALL_RULES = "Microsoft.Sql/servers/firewallRules"
AZURE_MYSQL_SERVER_FIREWALL_RULES = "Microsoft.DBforMySQL/flexibleServers/firewallRules"
AZURE_POSTGRE_SQL_SERVER_FIREWALL_RULES = (
    "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules"
)


def print_help(asset_type=DBTypes.SQL):
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
        f"\t\t Welcome To Tamnoon Azure DB Server Restrict Firewall Rules - This script will help you with removing or replacing Firewall Rules from your {asset_type.pretty_str()} Server.\n"
        "\n"
        "\t\t\t Dependencies:\n"
        "\t\t\t\t \n"
        "\t\t\t Authentication:\n"
        "\t\t\t\t The script support the fallback mechanism auth based on azure-identity DefaultAzureCredential \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity#install-the-package"
        "\t\t\t Supported Actions:\n"
        "\t\t\t\t\t Restrict Firewall rules of public network access of the MySQL Server - \n"
        "\t\t\t\t\t Supported for - MySQL Server, MySQL Flexible Server, PostgreSQL Flexible Server \n"
        "\n"
        "\t\t\t\t The script is based on Azrue Python SDK and documentation \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main\n"
        "\n\n"
        "\t\t\t Parameter Usage:\n"
        "\t\t\t\t logLevel - The logging level (optional). Default = Info\n"
        "\t\t\t\t subscriptions (optional) -   The Azure Subscription ID to use to execute this script (specific subscription ID, comma separated list of subscription IDs, or all). Default = all\n"
        "\t\t\t\t resourceGroups (optional) -   The Azure Resource Groups to use to execute this script (specific Resource Group, comma separated list of Resource Groups, or all). Default = all\n"
        "\t\t\t\t regions (optional) -   The Azure regions to use to execute this script (specific region, list of regions, or all). Default = all\n"
        "\t\t\t\t type (required) -     sql-server - The Azure Resource type of SQL server  ....\n"
        "\t\t\t\t                       mysql-server - The Azure Resource type of MySQL Flexible server  ....\n"
        "\t\t\t\t                       postgresql-server - The Azure Resource type of PostgreSQL Flexible server  ....\n"
        f"\t\t\t\t action (required) -   restrict_firewall_rules - The Azure {asset_type.pretty_str()} Server API action to execute\n"
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        """
        \t\t\t\t actionParams - 
        \t\t\t\t    for remedy -
        \t\t\t\t        1. remove_rule_name - (Optional*) name of firewall rule to remove or replace. This will be used to find firewall rule that can be removed or replaced.
        \t\t\t\t        2. remove_rule_range - (Optional*) ip address range*** of firewall rule to remove or replace. It should be in the form of <start_ip_address>-<end_ip_address>. This will be used to find firewall rule that can be removed or replaced. Example, "0.0.0.0-255.255.255.255"
        \t\t\t\t        3. replace - (Optional) true if you want to replace rule, false if you want to remove only. If you do not provide this action param, then default will be false.
        \t\t\t\t        4. replacement_rule_name - (Optional**) new name you want to replace. If not provided, then default will be Tamnoon-replacement-<timestamp>. if replacement_rule_ranges have multiple ranges, then after first replacement, every replacement will have <replacement_rule_name>-<n> or Tamnoon-replacement-<n>-<timestamp> where <n> is number of replacement range.
        \t\t\t\t        5. replacement_ranges - (Optional**) - list of ip address ranges***. Example
        \t\t\t\t            ["0.0.0.0-99.99.99.255","100.100.100.0-200.200.200.255"]

        \t\t\t\t        * at least one of remove_rule_name and remove_rule_range are required  
        \t\t\t\t        ** if replace is true, then replacement_ranges is required with optional replacement_rule_name  
        \t\t\t\t        *** Here start_ip_address and end_ip_address are IP Addresses only. Using CIDR will not work.

        \t\t\t\t        Examples,  
        \t\t\t\t        - to remove:  
        \t\t\t\t            --actionParams = '{"remove_rule_name":"rule-1"}'  
        \t\t\t\t            or  
        \t\t\t\t            --actionParams = '{"remove_rule_range":"0.0.0.0-255.255.255.255"}'  
        \t\t\t\t            or  
        \t\t\t\t            --actionParams = '{"remove_rule_name":"rule-1", "remove_rule_range":"0.0.0.0-255.255.255.255"}'
        \t\t\t\t        - to replace:
        \t\t\t\t            --actionParams = '{"remove_rule_name":"rule-1", "replace": true}'  
        \t\t\t\t            or  
        \t\t\t\t            --actionParams = '{"remove_rule_name":"rule-1", "replace": true, "replacement_rule_name": "rule-2"}'  
        \t\t\t\t            or  
        \t\t\t\t            --actionParams = '{"remove_rule_name":"rule-1", "replace": true, "replacement_rule_name": "rule-2", "replacement_ranges": ["0.0.0.0-99.99.99.255","100.100.100.0-200.200.200.255"]}'
        \t\t\t\t
        \t\t\t\t    for rollback - 
        \t\t\t\t        1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
        \t\t\t\t        2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.
        \t\t\t\t
"""
        f"\t\t\t\t assetIds (optional) - List of {asset_type.pretty_str()} Server names (string seperated by commas). Default = all\n"
        "\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run\n"
        "\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters\n"
        "\t\t\t\t outputType (optional) - the type of output of script exucution. available options are json (default) and csv \n"
        "\t\t\t\t outDir (optional) - the path to store output of script exucution. default is current working directory \n"
        "\n\n"
    )
    print(text)
    return True


def validate_action_params_firewall_rules(action_params):

    if "remove_rule_name" in action_params or "remove_rule_range" in action_params:

        if "replace" in action_params and action_params["replace"]:

            if (
                "replacement_ranges" in action_params
                and len(action_params["replacement_ranges"]) > 0
            ):
                for replacement_range_index, replacement_range in enumerate(
                    action_params["replacement_ranges"]
                ):
                    start = replacement_range.split("-")[0]
                    if not isip(start):
                        raise ValueError(
                            f"replacement range start at ({replacement_range_index+1}) is not an IP CIDR"
                        )

                    end = replacement_range.split("-")[1]
                    if not isip(end):
                        raise ValueError(
                            f"replacement range end at ({replacement_range_index+1}) is not an IP CIDR"
                        )

            else:

                raise KeyError(
                    "firewall rule replacement_range is required with optional replacement_rule_name"
                )
    else:
        raise KeyError("remove_rule_name or remove_rule_range is required")

    return True


def validate_action_params(
    action_params, asset_type=DBTypes.SQL, verbose=True, get_error=False
):
    """
    This method validates action params.
    Returns True for valid values, and False for invalid values.

    action_params - (Required) values to validate.

    :return: bool
    """
    is_valid_action_params = True
    try:
        logging.debug(action_params)
        if "rollBack" in action_params:
            if "lastExecutionResultPath" not in action_params:
                raise Exception(
                    "You are trying to execute roll back with no 'lastExecutionResultPath' parameter, the script have to know the previous saved state"
                )
        else:
            is_valid_action_params = validate_action_params_firewall_rules(
                action_params
            )
    except Exception as ex:
        logging.error(ex, exc_info=True)
        if verbose:
            print_help(asset_type=asset_type)
        if get_error:
            return (False, str(ex))
        else:
            is_valid_action_params = False
    if get_error:
        return (is_valid_action_params, None)
    return is_valid_action_params


def get_server_client(credential, server_type, subscription_id):
    if server_type == DBTypes.SQL:
        return get_client(
            credential,
            "sql_server",
            dict({"subscription_id": subscription_id}),
        )

    elif server_type == DBTypes.MYSQL_FLEXIBLE:
        return get_client(
            credential,
            "mysql_flexible_server",
            dict({"subscription_id": subscription_id}),
        )

    elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
        return get_client(
            credential,
            "postgresql_flexible_server",
            dict({"subscription_id": subscription_id}),
        )

    raise TypeError(f"cannot find client of type {server_type}")


def restrict_firewall_rules(
    credential,
    action_params,
    subscriptions=["all"],
    resource_groups=["all"],
    regions=["all"],
    server_names=["all"],
    server_type=DBTypes.SQL,
    dry_run=True,
):
    logging.debug(action_params)
    logging.debug(subscriptions)
    logging.debug(resource_groups)
    logging.debug(regions)
    logging.debug(server_names)
    logging.debug(dry_run)

    final_result = []
    try:
        package = None
        if server_type == DBTypes.SQL:
            package = SQLServerUtils
            server_actions_generator = SQLServerActionsGenerator(
                credential, subscriptions, resource_groups, regions, server_names
            )
        elif server_type == DBTypes.MYSQL_FLEXIBLE:
            package = MySQLFlexibleServerUtils
            server_actions_generator = MySQLFlexibleServerActionsGenerator(
                credential, subscriptions, resource_groups, regions, server_names
            )
        elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
            package = PostgreSQLFlexibleServerUtils
            server_actions_generator = PostgreSQLFlexibleServerActionsGenerator(
                credential, subscriptions, resource_groups, regions, server_names
            )
        else:
            raise ValueError(f"invalid server type {server_type}")

        server_actions = server_actions_generator.generate()
        if server_actions != None and server_actions.__len__() > 0:
            server_client = None
            for server_action in server_actions:
                server_action.data["subscription_id"]
                server_action.data["resource_group_name"]
                server_action.data["regions"]
                server_action.data[f"{server_type.value}_server_name"]

                server_client = get_server_client(
                    credential, server_type, server_action.data["subscription_id"]
                )

                server = package.get_server(
                    server_client,
                    server_action.data["resource_group_name"],
                    server_action.data[f"{server_type.value}_server_name"],
                )
                logging.debug(server)
                is_public_network_access_enabled = (
                    package.is_public_network_access_enabled(server)
                )

                if not is_public_network_access_enabled:
                    public_network_access_result = AzureExecutionResult(
                        server.id,
                        server.name,
                        server.type,
                        "no-action",
                        "",
                        server_action.data["regions"],
                        dry_run,
                    )
                    public_network_access_result.set_string_result(
                        "fail",
                        "Could not remove or replace firewall rules of server because its public network access is Disabled",
                    )
                    final_result.append(public_network_access_result.as_dict())
                #     if server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
                #         logging.warning(
                #             "azure sdk does not support enabling public_network_access"
                #         )
                #     else:
                #         enable_public_network_access_result = AzureExecutionResult(
                #             server.id,
                #             server.name,
                #             server.type,
                #             "update",
                #             "",
                #             "",
                #             dry_run,
                #         )
                #         if dry_run:
                #             enable_public_network_access_result.set_string_result(
                #                 "dryrun", "could enable public network access"
                #             )
                #         else:
                #             try:
                #                 package.enable_public_network_access(
                #                     server_client,
                #                     server_action.data["resource_group_name"],
                #                     server_action.data[f"{server_type}_server_name"],
                #                 )
                #                 enable_public_network_access_result.set_dict_result(
                #                     "success",
                #                     "Disabled",
                #                     "Enabled",
                #                 )
                #                 is_public_network_access_enabled = True
                #             except Exception as ex:
                #                 logging.error(ex, exc_info=True)
                #                 enable_public_network_access_result.set_string_result(
                #                     "fail", str(ex)
                #                 )
                #                 is_public_network_access_enabled = False

                #         public_network_access_result.append_result_to_list(
                #             enable_public_network_access_result
                #         )
                if is_public_network_access_enabled:
                    public_network_access_result = AzureExecutionResult(
                        server.id,
                        server.name,
                        server.type,
                        "no-action",
                        "",
                        server_action.data["regions"],
                        dry_run,
                    )
                    firewall_rules = package.get_firewall_rules(
                        server_client,
                        server_action.data["resource_group_name"],
                        server.name,
                    )
                    for firewall_rule in firewall_rules:
                        is_replace = (
                            "replace" in action_params and action_params["replace"]
                        )
                        if is_replace:
                            replace = action_params
                            find_rule_name = (
                                action_params["remove_rule_name"]
                                if "remove_rule_name" in action_params
                                else None
                            )
                            find_rule_range_start = (
                                action_params["remove_rule_range"].split("-")[0]
                                if "remove_rule_range" in action_params
                                else None
                            )
                            find_rule_range_end = (
                                action_params["remove_rule_range"].split("-")[1]
                                if "remove_rule_range" in action_params
                                else None
                            )
                            is_replace = (
                                "replace" in action_params and action_params["replace"]
                            )
                            is_name = find_rule_name == firewall_rule.name
                            is_start = (
                                find_rule_range_start == firewall_rule.start_ip_address
                            )
                            is_end = find_rule_range_end == firewall_rule.end_ip_address
                            if is_name or (is_start and is_end):
                                for (
                                    replacement_range_index,
                                    replacement_range,
                                ) in enumerate(action_params["replacement_ranges"]):
                                    replace_name = ""
                                    if "replacement_rule_name" in action_params:
                                        if (
                                            action_params[
                                                "replacement_ranges"
                                            ].__len__()
                                            > 1
                                        ):
                                            replace_name = f'{action_params["replacement_rule_name"]}-{replacement_range_index+1}'
                                        else:
                                            replace_name = f'{action_params["replacement_rule_name"]}'
                                    else:
                                        datetime_value = (
                                            format_datetime_for_azure_resource_name(
                                                datetime.now()
                                            )
                                        )
                                        if (
                                            action_params[
                                                "replacement_ranges"
                                            ].__len__()
                                            > 1
                                        ):
                                            replace_name = f"Tamnoon-replacement-{replacement_range_index+1}-{datetime_value}"
                                        else:
                                            replace_name = (
                                                f"Tamnoon-replacement-{datetime_value}"
                                            )

                                    replace_rule_start = replacement_range.split("-")[0]
                                    replace_rule_end = replacement_range.split("-")[1]
                                    # replace(create) here
                                    if replacement_range_index == 0:
                                        update_firewall_rule_result = (
                                            AzureExecutionResult(
                                                firewall_rule.id,
                                                firewall_rule.name,
                                                firewall_rule.type,
                                                "update",
                                                "",
                                                server_action.data["regions"],
                                                dry_run,
                                            )
                                        )
                                        if dry_run:
                                            update_firewall_rule_result.set_string_result(
                                                "dryrun",
                                                "could update firewall rules",
                                            )
                                        else:
                                            try:
                                                new_firewall_rule = package.update_firewall_rules(
                                                    server_client,
                                                    server_action.data[
                                                        "resource_group_name"
                                                    ],  # resource group name
                                                    server.name,  # server name
                                                    firewall_rule.name,
                                                    replace_name,  # firewall rule name
                                                    replace_rule_start,
                                                    replace_rule_end,
                                                )
                                                update_firewall_rule_result.set_dict_result(
                                                    "success",
                                                    dict(
                                                        {
                                                            "name": firewall_rule.name,
                                                            "start_ip_address": firewall_rule.start_ip_address,
                                                            "end_ip_address": firewall_rule.end_ip_address,
                                                        }
                                                    ),
                                                    dict(
                                                        {
                                                            "name": new_firewall_rule.name,
                                                            "start_ip_address": new_firewall_rule.start_ip_address,
                                                            "end_ip_address": new_firewall_rule.end_ip_address,
                                                        }
                                                    ),
                                                )
                                            except Exception as ex:
                                                logging.error(ex, exc_info=True)
                                                update_firewall_rule_result.set_string_result(
                                                    "fail", str(ex)
                                                )

                                        public_network_access_result.append_result_to_list(
                                            update_firewall_rule_result
                                        )
                                    else:
                                        create_firewall_rule_result = (
                                            AzureExecutionResult(
                                                firewall_rule.id,
                                                (
                                                    firewall_rule.name
                                                    if not dry_run
                                                    else replace_name
                                                ),
                                                firewall_rule.type,
                                                "create",
                                                "",
                                                server_action.data["regions"],
                                                dry_run,
                                            )
                                        )
                                        if dry_run:
                                            create_firewall_rule_result.set_string_result(
                                                "dryrun",
                                                "could create firewall rules",
                                            )
                                        else:
                                            try:
                                                new_firewall_rule = package.update_firewall_rules(
                                                    server_client,
                                                    server_action.data[
                                                        "resource_group_name"
                                                    ],  # resource group name
                                                    server.name,  # server name
                                                    replace_name,
                                                    replace_name,  # firewall rule name
                                                    replace_rule_start,
                                                    replace_rule_end,
                                                )
                                                create_firewall_rule_result.set_dict_result(
                                                    "success",
                                                    None,
                                                    dict(
                                                        {
                                                            "name": new_firewall_rule.name,
                                                            "start_ip_address": new_firewall_rule.start_ip_address,
                                                            "end_ip_address": new_firewall_rule.end_ip_address,
                                                        }
                                                    ),
                                                )

                                            except Exception as ex:
                                                logging.error(ex, exc_info=True)
                                                create_firewall_rule_result.set_string_result(
                                                    "fail", str(ex)
                                                )

                                        public_network_access_result.append_result_to_list(
                                            create_firewall_rule_result
                                        )
                        else:
                            remove_rule_name = (
                                action_params["remove_rule_name"]
                                if "remove_rule_name" in action_params
                                else None
                            )
                            remove_rule_range_start = (
                                action_params["remove_rule_range"].split("-")[0]
                                if "remove_rule_range" in action_params
                                else None
                            )
                            remove_rule_range_end = (
                                action_params["remove_rule_range"].split("-")[1]
                                if "remove_rule_range" in action_params
                                else None
                            )
                            is_name = remove_rule_name == firewall_rule.name
                            is_start = (
                                remove_rule_range_start
                                == firewall_rule.start_ip_address
                            )
                            is_end = (
                                remove_rule_range_end == firewall_rule.end_ip_address
                            )
                            if is_name or (is_start and is_end):
                                remove_firewall_rule_result = AzureExecutionResult(
                                    firewall_rule.id,
                                    firewall_rule.name,
                                    firewall_rule.type,
                                    "remove",
                                    "",
                                    server_action.data["regions"],
                                    dry_run,
                                )
                                if dry_run:
                                    remove_firewall_rule_result.set_string_result(
                                        "dryrun", "could remove firewall rule"
                                    )
                                else:
                                    try:
                                        package.remove_firewall_rule(
                                            server_client,
                                            server_action.data[
                                                "resource_group_name"
                                            ],  # resource group name
                                            server.name,  # server name
                                            firewall_rule.name,  # firewall rule name
                                        )
                                        remove_firewall_rule_result.set_dict_result(
                                            "success",
                                            dict(
                                                {
                                                    "name": firewall_rule.name,
                                                    "start_ip_address": firewall_rule.start_ip_address,
                                                    "end_ip_address": firewall_rule.end_ip_address,
                                                }
                                            ),
                                            None,
                                        )
                                    except Exception as ex:
                                        logging.error(ex, exc_info=True)
                                        remove_firewall_rule_result.set_string_result(
                                            "fail", str(ex)
                                        )
                                public_network_access_result.append_result_to_list(
                                    remove_firewall_rule_result
                                )

                    if firewall_rules.__len__() == 0:
                        public_network_access_result.set_string_result(
                            "fail", "could not find firewall rules"
                        )
                    final_result.append(public_network_access_result.as_dict())
                # end if block
                package.close_client(server_client)

        else:
            result = AzureExecutionResult(
                "",
                "",
                "",
                "no-action",
                "",
                "",
                dry_run,
            )
            result.set_string_result(
                "fail",
                f"Could not find {server_type.pretty_str()} Server(s) for remedy. Please check the parameters provided are correct.",
            )
            final_result.append(result.as_dict())
    except Exception as ex:
        logging.error(ex, exc_info=True)
        result = AzureExecutionResult(
            "",
            "",
            "",
            "no-action",
            "",
            "",
            dry_run,
        )
        result.set_string_result("fail", str(ex))
        final_result.append(result.as_dict())
    return final_result


def rollback_restrict_firewall_rules(
    credential, last_execution_result_path, dry_run=True, server_type=DBTypes.SQL
) -> [dict]:
    """
    This method resets the modifications done by restrict_firewall_rules() method.
    credential - (Required) Azure Credential.
    last_execution_result_path - (Required) path to the file that has json result.
    dry_run - (Optional) if False then performs actual operations on Cloud; default
    is True, where script will output the actions that can be performed by the
    script to rollback the result
    :return: [dict]
    """
    new_actions = []
    with open(last_execution_result_path, "r") as prev_state:
        prev_state_json = json.load(prev_state)

        if (
            (
                prev_state_json["executionType"] == "sql-server"
                and server_type == DBTypes.SQL
            )
            or (
                prev_state_json["executionType"] == "mysql-server"
                and server_type == DBTypes.MYSQL_FLEXIBLE
            )
            or (
                prev_state_json["executionType"] == "postgresql-server"
                and server_type == DBTypes.POSTGRE_SQL_FLEXIBLE
            )
        ) and prev_state_json["executionAction"] == "restrict_firewall_rules":
            rollback_actions = serialize_rollback_actions(
                prev_state_json["executionResult"]
            )
            for action in rollback_actions:
                result = AzureExecutionResult.load(action)
                if action["ExecutionResultData"]["ResultType"] != "object":
                    logging.warning(
                        f'skipping rollback of result of type {action["ExecutionResultData"]["ResultType"]}'
                    )
                    continue

                if action["Asset"]["Type"] in [
                    AZURE_SQL_SERVER_FIREWALL_RULES,
                    AZURE_MYSQL_SERVER_FIREWALL_RULES,
                    AZURE_POSTGRE_SQL_SERVER_FIREWALL_RULES,
                ]:
                    if action["ActionStatus"] == "success":
                        server_client = None
                        subscription_id = action["Asset"]["Id"].split("/")[2]
                        resource_group_name = action["Asset"]["Id"].split("/")[4]
                        server_name = action["Asset"]["Id"].split("/")[8]
                        firewall_rule_name = action["Asset"]["Name"]

                        package = None
                        if server_type == DBTypes.SQL:
                            package = SQLServerUtils
                        elif server_type == DBTypes.MYSQL_FLEXIBLE:
                            package = MySQLFlexibleServerUtils
                        elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
                            package = PostgreSQLFlexibleServerUtils

                        if action["Asset"]["Action"] == "create":
                            server_client = get_server_client(
                                credential, server_type, subscription_id
                            )
                            package.remove_firewall_rule(
                                server_client,
                                resource_group_name,  # resource group name
                                server_name,  # sql server name
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ][
                                    "name"
                                ],  # firewall rule name
                            )
                            package.close_client(server_client)
                            action["Asset"]["Action"] = "remove"
                            (
                                action["ExecutionResultData"]["Result"]["prev_state"],
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                            ) = (
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"],
                            )
                            new_actions.append(action)
                        elif action["Asset"]["Action"] == "update":
                            package = None
                            if server_type == DBTypes.SQL:
                                package = SQLServerUtils
                            elif server_type == DBTypes.MYSQL_FLEXIBLE:
                                package = MySQLFlexibleServerUtils
                            elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
                                package = PostgreSQLFlexibleServerUtils

                            server_client = get_server_client(
                                credential, server_type, subscription_id
                            )
                            package.update_firewall_rules(
                                server_client,
                                resource_group_name,  # resource group name
                                server_name,  # sql server name
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ]["name"],
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "name"
                                ],  # firewall rule name
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "start_ip_address"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "end_ip_address"
                                ],
                            )
                            package.close_client(server_client)
                            action["Asset"]["Action"] = "update"
                            (
                                action["ExecutionResultData"]["Result"]["prev_state"],
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                            ) = (
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"],
                            )
                            new_actions.append(action)
                        elif action["Asset"]["Action"] == "remove":
                            package = None
                            if server_type == DBTypes.SQL:
                                package = SQLServerUtils
                            elif server_type == DBTypes.MYSQL_FLEXIBLE:
                                package = MySQLFlexibleServerUtils
                            elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
                                package = PostgreSQLFlexibleServerUtils

                            server_client = get_server_client(
                                credential, server_type, subscription_id
                            )
                            package.update_firewall_rules(
                                server_client,
                                resource_group_name,  # resource group name
                                server_name,  # sql server name
                                action["Asset"]["Name"],
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "name"
                                ],  # firewall rule name
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "start_ip_address"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "end_ip_address"
                                ],
                            )
                            package.close_client(server_client)
                            action["Asset"]["Action"] = "create"
                            (
                                action["ExecutionResultData"]["Result"]["prev_state"],
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                            ) = (
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"],
                            )
                            new_actions.append(action)
                    elif (
                        action["ActionStatus"] == "dryrun"
                        or action["ActionStatus"] == "fail"
                    ):
                        pass
                elif action["Asset"]["Type"] in [
                    AZURE_SQL_SERVER,
                    AZURE_MYSQL_SERVER,
                    AZURE_POSTGRE_SQL_SERVER,
                ]:
                    package = None
                    if server_type == DBTypes.SQL:
                        package = SQLServerUtils
                    elif server_type == DBTypes.MYSQL_FLEXIBLE:
                        package = MySQLFlexibleServerUtils
                    elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
                        package = PostgreSQLFlexibleServerUtils

                    if action["ActionStatus"] == "success":
                        subscription_id = action["Asset"]["Id"].split("/")[2]
                        resource_group_name = action["Asset"]["Id"].split("/")[4]
                        server_name = action["Asset"]["Id"].split("/")[8]

                        if action["Asset"]["Action"] == "update":
                            if action["Asset"]["Type"] == AZURE_POSTGRE_SQL_SERVER:
                                logging.warning(
                                    "azure sdk does not support enabling public_network_access"
                                )
                            else:
                                server_client = get_server_client(
                                    credential, server_type, subscription_id
                                )
                                if (
                                    action["ExecutionResultData"]["Result"][
                                        "current_state"
                                    ]
                                    == "Disabled"
                                ):
                                    package.enable_public_network_access(
                                        server_client,
                                        resource_group_name,  # resource group name
                                        server_name,
                                    )
                                elif (
                                    action["ExecutionResultData"]["Result"][
                                        "current_state"
                                    ]
                                    == "Enabled"
                                ):
                                    package.disable_public_network_access(
                                        server_client,
                                        resource_group_name,  # resource group name
                                        server_name,
                                    )
                                package.close_client(client)
                                (
                                    action["ExecutionResultData"]["Result"][
                                        "prev_state"
                                    ],
                                    action["ExecutionResultData"]["Result"][
                                        "current_state"
                                    ],
                                ) = (
                                    action["ExecutionResultData"]["Result"][
                                        "current_state"
                                    ],
                                    action["ExecutionResultData"]["Result"][
                                        "prev_state"
                                    ],
                                )
                                new_actions.append(action)
                        else:
                            pass
                    elif (
                        action["ActionStatus"] == "dryrun"
                        or action["ActionStatus"] == "fail"
                    ):
                        pass
                else:
                    pass
                # logging.info(f"\n\t{action}")
    return new_actions
