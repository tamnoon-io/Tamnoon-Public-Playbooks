from time import sleep
import json
import logging

from library.DBServer.SQLServerUtils import (
    is_devops_audit_enabled,
    get_auditing_policy,
    setup_auditing_with_log_analytics_workspace,
    setup_auditing_with_storage_account,
    setup_auditing_using_policy,
    close_client,
    get_server,
)
from library.DBServer.DBActionsGenerator import SQLServerActionsGenerator
from library.BlobStorage import get_access_key
from library.Utils.execution_result import AzureExecutionResult
from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import get_client, setup_session


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
        "\t\t Welcome To Tamnoon Azure SQL Server Enable Auditing - The script that will help you with ensuring auditing is enabled and provide destinition for the logs.\n"
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
        if "storage-account-name" in action_params and (
            "resource-group-name" not in action_params
            or "subscription-id" not in action_params
        ):
            raise Exception(
                'To use "storage-account-name" parameter, the script also requires "resource-group-name" and "subscription-id" of storage account'
            )
        if "storage-account-name" not in action_params:
            raise Exception(
                'Remedy script requires "storage-account-name" and its "resource-group-name" and "subscription-id" to store auditing logs'
            )
    except Exception as ex:
        logging.error(ex)
        if verbose:
            print_help()
        is_valid_action_params = False

    return is_valid_action_params


def enable_auditing(
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

    if "storage-auth-method" not in action_params:
        action_params["storage-auth-method"] = "default"

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
                sql_server = get_server(
                    sql_client,
                    sql_server_action.data["resource_group_name"],
                    sql_server_action.data["sql_server_name"],
                )
                auditing_policy = get_auditing_policy(
                    sql_client,
                    sql_server_action.data["resource_group_name"],
                    sql_server_action.data["sql_server_name"],
                )

                result = AzureExecutionResult(
                    auditing_policy.id,
                    auditing_policy.name,
                    auditing_policy.type,
                    "update",
                    "",
                    "",
                    dry_run,
                )
                if dry_run:
                    result.set_string_result(
                        "dryrun",
                        f"Could update auditing settings of SQL Server",
                    )
                else:
                    try:
                        if "storage-account-name" in action_params:
                            access_key = get_access_key(
                                credential,
                                subscription_id=action_params["subscription-id"],
                                resource_group_name=action_params[
                                    "resource-group-name"
                                ],
                                storage_account_name=action_params[
                                    "storage-account-name"
                                ],
                            )
                            setup_result = setup_auditing_with_storage_account(
                                sql_client=sql_client,
                                resource_group_name=sql_server_action.data[
                                    "resource_group_name"
                                ],
                                sql_server_name=sql_server_action.data[
                                    "sql_server_name"
                                ],
                                storage_account_subscription_id=action_params[
                                    "subscription-id"
                                ],
                                storage_account_name=action_params[
                                    "storage-account-name"
                                ],
                                access_key=(
                                    access_key
                                    if action_params["storage-auth-method"]
                                    == "access_key"
                                    else None
                                ),
                            )
                            auditing_policy_vars = vars(auditing_policy)
                            setup_result_vars = vars(setup_result)
                            result.set_dict_result(
                                "success", auditing_policy_vars, setup_result_vars
                            )
                        # elif "log_analytics_workspace" in action_params:
                        #     log_analytics_workspace_name = action_params[
                        #         "log_analytics_workspace"
                        #     ]
                        #     setup_result = setup_auditing_with_log_analytics_workspace(
                        #         credential,
                        #         sql_client,
                        #         sql_server_action.data["subscription_id"],
                        #         sql_server_action.data["resource_group_name"],
                        #         sql_server_action.data["sql_server_name"],
                        #         log_analytics_workspace_name,
                        #     )
                        #     auditing_policy_vars = vars(auditing_policy)
                        #     setup_result_vars = vars(setup_result)
                        #     result.set_dict_result(
                        #         "success", auditing_policy_vars, setup_result_vars
                        #     )
                        else:
                            raise Exception("Unknown target for storing Auditing Logs")
                    except Exception as ex:
                        logging.error(ex, exc_info=True)
                        result.set_string_result("fail", str(ex))
                final_result.append(result.as_dict())
                close_client(sql_client)
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


def rollback_enable_auditing(
    credential,
    last_execution_result_path,
    dry_run=True,
) -> [dict]:
    """
    This method resets the modifications done by enable_auditing() method.
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

        action_params = prev_state_json["actionParams"]
        if (
            prev_state_json["executionType"] == "sql-server"
            and prev_state_json["executionAction"] == "enable_auditing"
        ):
            rollback_actions = serialize_rollback_actions(
                prev_state_json["executionResult"]
            )
            for action in rollback_actions:
                new_action = AzureExecutionResult.load(action)
                if action["ExecutionResultData"]["ResultType"] != "object":
                    logging.warning(
                        f'skipping rollback of result of type {action["ExecutionResultData"]["ResultType"]}'
                    )
                    continue
                if (
                    action["ActionStatus"] == "dryrun"
                    or action["ActionStatus"] == "fail"
                ):
                    logging.info(
                        f'Could not rollback because execution action status is {action["ActionStatus"]}'
                    )
                    logging.debug(action)
                    continue

                if action["Asset"]["Type"] == "Microsoft.Sql/servers/auditingSettings":
                    subscription_id = action["Asset"]["Id"].split("/")[2]
                    resource_group_name = action["Asset"]["Id"].split("/")[4]
                    sql_server_name = action["Asset"]["Id"].split("/")[8]
                    if action["ActionStatus"] == "success":
                        sql_client = get_client(
                            credential,
                            "sql_server",
                            dict({"subscription_id": subscription_id}),
                        )
                        access_key = None
                        if action_params["storage-auth-method"] == "access_key":
                            access_key = get_access_key(
                                credential,
                                subscription_id=action_params["subscription-id"],
                                resource_group_name=action_params[
                                    "resource-group-name"
                                ],
                                storage_account_name=action_params[
                                    "storage-account-name"
                                ],
                            )
                        try:
                            result = setup_auditing_using_policy(
                                sql_client=sql_client,
                                resource_group_name=resource_group_name,
                                sql_server_name=sql_server_name,
                                policy=action["ExecutionResultData"]["Result"][
                                    "prev_state"
                                ],
                                access_key=access_key,
                            )
                            new_action.set_dict_result(
                                "success",
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                                vars(result),
                            )
                        except Exception as ex:
                            logging.exception(ex)
                            new_action.set_string_result("fail", str(ex))
                        new_actions.append(new_action.as_dict())
                    else:
                        pass
                else:
                    pass
    return new_actions
