from time import sleep
import json
import logging


from azure.identity import DefaultAzureCredential


from library.SQLServer import (
    get_sql_server,
    disable_public_network_access,
    enable_public_network_access,
    close_sql_client,
    get_firewall_rules_of_sql_server,
    remove_firewall_rule_of_sql_server,
    update_firewall_rules_of_sql_server,
)
from library.SQLServer.SQLServerAction import SQLServerAction
from library.SQLServer.SQLServerActionsGenerator import SQLServerActionsGenerator
from library.Utils.execution_result import AzureExecutionResult
from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import get_client


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
        "\t\t Welcome To Tamnoon Azure SQL Server Restrict Firewall Rules - The script that will help you with managing public network access to SQL Server and setting Firewall Rules.\n"
        "\n"
        "\t\t\t Dependencies:\n"
        "\t\t\t\t \n"
        "\t\t\t Authentication:\n"
        "\t\t\t\t The script support the fallback mechanism auth based on azure-identity DefaultAzureCredential \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity#install-the-package"
        "\t\t\t Supported Actions:\n"
        "\t\t\t\t 1. SQL Server:"
        "\t\t\t\t\t Restrict Firewall rules of public network access of the SQL Server - \n"
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
        "\t\t\t\t action (required) -   restrict_firewall_rules - The Azure SQL Server API action to execute\n"
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        """
        \t\t\t\t actionParams - 
        \t\t\t\t    for remedy -
        \t\t\t\t        1. action - (Required) - there are two actions,
        \t\t\t\t            "disable-all" - if you want to disable public network access completely.
        \t\t\t\t            "disable-by-firewall-rules" - if you want to provide firewall rules.
        \t\t\t\t        2. remove-current-firewall-rules - (Required) - Boolean flag used to sign if you want to remove current firewall rules.
        \t\t\t\t            When set to true with action set as "disable-by-firewall-rules", remedy will first remove current rules, and then create new rules as given in the actionParams
        \t\t\t\t        3. firewall-rules - (Required if action is "disable-by-firewall-rules") - list of name, start_ip_address and end_ip_address. Here start_ip_address and end_ip_address are IP Addresses only. Using CIDR will not work.
        \t\t\t\t            example, "firewall-rules": [{"name":"rule-1", "start_ip_address" : "ip_address_1", "end_ip_address" : "ip_address_2" }]
        \t\t\t\t    for rollback - 
        \t\t\t\t        1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
        \t\t\t\t        2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.
        """
        "\t\t\t\t assetIds (optional) - List of SQL Server names (string seperated by commas). Default = all\n"
        "\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run\n"
        "\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters\n"
        "\t\t\t\t outputType (optional) - the type of output of script exucution. available options are json (default) and csv \n"
        "\t\t\t\t outDir (optional) - the path to store output of script exucution. default is current working directory \n"
        "\n\n"
    )
    print(text)


def validate_action_params_firewall_rules(action_params):
    if (
        "firewall-rules" not in action_params
        or action_params["firewall-rules"].__len__() == 0
    ):
        raise KeyError("firewall-rules is required actionParam")
    for rule in action_params["firewall-rules"]:
        start_ip_address = "start_ip_address" in rule
        end_ip_address = "end_ip_address" in rule
        if not start_ip_address and not end_ip_address:
            raise ValueError(
                "firewall-rule must have name of firewall rule firewall rule or start_ip_address or end_ip_address to find rule to be removed"
            )

    return True


def validate_action_params(action_params, verbose=True):
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
            if not "action" in action_params or not [
                "disable-all",
                "disable-by-firewall-rules",
            ].__contains__(action_params["action"]):
                raise KeyError(
                    'action is required actionParam. Its accepted values are "disable-all" or "disable-by-firewall-rules"'
                )
            if not "remove-current-firewall-rules" in action_params:
                raise KeyError(
                    "remove-current-firewall-rules is required actionParam. Its accepted values are true or false"
                )
            # if action_params["action"] == "disable-all":
            #     return True
            if action_params["action"] == "disable-by-firewall-rules":
                is_valid_action_params = validate_action_params_firewall_rules(
                    action_params
                )
    except Exception as ex:
        logging.error(ex)
        if verbose:
            print_help()
        is_valid_action_params = False

    return is_valid_action_params


def restrict_firewall_rules(
    credential,
    action_params,
    subscriptions=["all"],
    resource_groups=["all"],
    regions=["all"],
    sql_server_names=["all"],
    dry_run=True,
):
    logging.debug(action_params)
    logging.debug(subscriptions)
    logging.debug(resource_groups)
    logging.debug(regions)
    logging.debug(sql_server_names)
    logging.debug(dry_run)

    final_result = []
    try:
        sql_server_actions_generator = SQLServerActionsGenerator(
            credential, subscriptions, resource_groups, regions, sql_server_names
        )
        sql_server_actions = sql_server_actions_generator.generate()

        if sql_server_actions != None and sql_server_actions.__len__() > 0:
            sql_client = None
            for sql_server_action in sql_server_actions:
                sql_server_action.data["subscription_id"]
                sql_server_action.data["resource_group_name"]
                sql_server_action.data["regions"]
                sql_server_action.data["sql_server_name"]

                sql_client = get_client(
                    credential,
                    "sql_server",
                    dict(
                        {"subscription_id": sql_server_action.data["subscription_id"]}
                    ),
                )
                sql_server = get_sql_server(
                    sql_client,
                    sql_server_action.data["resource_group_name"],
                    sql_server_action.data["sql_server_name"],
                )
                logging.debug(sql_server)

                public_network_access_result = AzureExecutionResult(
                    sql_server.id,
                    sql_server.name,
                    sql_server.type,
                    "no-action",
                    "",
                    sql_server_action.data["regions"],
                    dry_run,
                )
                if action_params["remove-current-firewall-rules"]:
                    # remove previous firewall rules
                    logging.debug(
                        f"remove-current-firewall-rules {action_params['remove-current-firewall-rules']}"
                    )

                    firewall_rules = get_firewall_rules_of_sql_server(
                        sql_client,
                        sql_server_action.data["resource_group_name"],
                        sql_server_action.data["sql_server_name"],
                    )
                    for rule in firewall_rules:
                        # remove rule here
                        remove_firewall_rule_result = AzureExecutionResult(
                            rule.id,
                            rule.name,
                            rule.type,
                            "remove",
                            "",
                            "",
                            dry_run,
                        )
                        if dry_run:
                            remove_firewall_rule_result.set_string_result(
                                "dryrun", "could remove firewall rule"
                            )
                        else:
                            try:
                                remove_firewall_rule_of_sql_server(
                                    sql_client,
                                    sql_server_action.data["resource_group_name"],
                                    sql_server_action.data["sql_server_name"],
                                    rule.name,
                                )
                                remove_firewall_rule_result.set_dict_result(
                                    "success",
                                    dict(
                                        {
                                            "name": rule.name,
                                            "start_ip_address": rule.start_ip_address,
                                            "end_ip_address": rule.end_ip_address,
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

                if action_params["action"] == "disable-all":
                    disable_all_public_network_access_result = AzureExecutionResult(
                        sql_server.id,
                        sql_server.name,
                        sql_server.type,
                        "update",
                        "",
                        sql_server.location,
                        dry_run,
                    )
                    if dry_run:
                        disable_all_public_network_access_result.set_string_result(
                            "dryrun", "could disable public network access"
                        )
                    else:
                        try:
                            disable_public_network_access(
                                sql_client,
                                sql_server_action.data["resource_group_name"],
                                sql_server_action.data["sql_server_name"],
                            )
                            disable_all_public_network_access_result.set_dict_result(
                                "success",
                                sql_server.public_network_access,
                                "Disabled",
                            )
                        except Exception as ex:
                            logging.error(ex, exc_info=True)
                            disable_all_public_network_access_result.set_string_result(
                                "fail", str(ex)
                            )
                    public_network_access_result.append_result_to_list(
                        disable_all_public_network_access_result
                    )

                elif action_params["action"] == "disable-by-firewall-rules":
                    enable_public_network_access_result = AzureExecutionResult(
                        sql_server.id,
                        sql_server.name,
                        sql_server.type,
                        "update",
                        "",
                        "",
                        dry_run,
                    )
                    if dry_run:
                        enable_public_network_access_result.set_string_result(
                            "dryrun", "could enable public network access"
                        )
                    else:
                        try:
                            enable_public_network_access(
                                sql_client,
                                sql_server_action.data["resource_group_name"],
                                sql_server_action.data["sql_server_name"],
                            )
                            enable_public_network_access_result.set_dict_result(
                                "success",
                                sql_server.public_network_access,
                                "Enabled",
                            )
                        except Exception as ex:
                            logging.error(ex, exc_info=True)
                            enable_public_network_access_result.set_string_result(
                                "fail", str(ex)
                            )

                    public_network_access_result.append_result_to_list(
                        enable_public_network_access_result
                    )
                    for rule in action_params["firewall-rules"]:
                        set_firewall_rule_result = AzureExecutionResult(
                            "",
                            rule["name"],
                            "",
                            "create",
                            "",
                            "",
                            dry_run,
                        )
                        if dry_run:
                            set_firewall_rule_result.set_string_result(
                                "dryrun", "could create firewall rules"
                            )
                        else:
                            try:
                                new_firewall_rule = update_firewall_rules_of_sql_server(
                                    sql_client,
                                    sql_server_action.data["resource_group_name"],
                                    sql_server_action.data["sql_server_name"],
                                    rule["name"],
                                    rule["start_ip_address"],
                                    rule["end_ip_address"],
                                )
                                set_firewall_rule_result.set_asset(
                                    new_firewall_rule.id,
                                    new_firewall_rule.name,
                                    new_firewall_rule.type,
                                )
                                set_firewall_rule_result.set_dict_result(
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
                                set_firewall_rule_result.set_string_result(
                                    "fail", str(ex)
                                )
                        public_network_access_result.append_result_to_list(
                            set_firewall_rule_result
                        )
                close_sql_client(sql_client)
                final_result.append(public_network_access_result.as_dict())
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
                "Could not find SQL Server(s) for remedy. Please check the parameters provided are correct.",
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
    credential,
    last_execution_result_path,
    dry_run=True,
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
            prev_state_json["executionType"] == "sql-server"
            and prev_state_json["executionAction"] == "restrict_firewall_rules"
        ):
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

                if action["Asset"]["Type"] == "Microsoft.Sql/servers/firewallRules":
                    if action["ActionStatus"] == "success":
                        if action["Asset"]["Action"] == "create":
                            sql_client = get_client(
                                credential,
                                action["Asset"]["Id"].split("/")[2],  # subscription ID
                            )
                            remove_firewall_rule_of_sql_server(
                                sql_client,
                                action["Asset"]["Id"].split("/")[
                                    4
                                ],  # resource group name
                                action["Asset"]["Id"].split("/")[8],  # sql server name
                                action["Asset"]["Name"],  # firewall rule name
                            )
                            close_sql_client(sql_client)
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
                        elif (
                            action["Asset"]["Action"] == "update"
                            or action["Asset"]["Action"] == "remove"
                        ):
                            sql_client = get_client(
                                credential,
                                action["Asset"]["Id"].split("/")[2],  # subscription ID
                            )
                            update_firewall_rules_of_sql_server(
                                sql_client,
                                action["Asset"]["Id"].split("/")[
                                    4
                                ],  # resource group name
                                action["Asset"]["Id"].split("/")[8],  # sql server name
                                action["Asset"]["Name"],  # firewall rule name
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "start_ip_address"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "end_ip_address"
                                ],
                            )
                            close_sql_client(sql_client)
                            action["Asset"]["Action"] = (
                                "create"
                                if action["Asset"]["Action"] == "remove"
                                else "update"
                            )
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
                elif action["Asset"]["Type"] == "Microsoft.Sql/servers":
                    if action["ActionStatus"] == "success":
                        if action["Asset"]["Action"] == "update":
                            # TODO: undo
                            sql_client = get_client(
                                credential,
                                action["Asset"]["Id"].split("/")[2],  # subscription ID
                            )
                            if (
                                action["ExecutionResultData"]["Result"]["current_state"]
                                == "Disabled"
                            ):
                                enable_public_network_access(
                                    sql_client,
                                    action["Asset"]["Id"].split("/")[
                                        4
                                    ],  # resource group name
                                    action["Asset"]["Id"].split("/")[8],
                                )
                            elif (
                                action["ExecutionResultData"]["Result"]["current_state"]
                                == "Enabled"
                            ):
                                disable_public_network_access(
                                    sql_client,
                                    action["Asset"]["Id"].split("/")[
                                        4
                                    ],  # resource group name
                                    action["Asset"]["Id"].split("/")[8],
                                )
                            close_sql_client(sql_client)
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
