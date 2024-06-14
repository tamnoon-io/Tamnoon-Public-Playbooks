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
from library.DBServer.DBAction import DBTypes, inverse_cli_type_mapping
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
from library.BlobStorage import get_access_key
from library.Utils.execution_result import AzureExecutionResult
from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import get_client, setup_session


try:
    from Azure.Automations.DBServer import help_jsons_data as help_jsons_data
except ModuleNotFoundError:
    help_jsons_data = {}
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


def validate_action_params(server_type=DBTypes.SQL, action_params=None, verbose=True):
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
            if server_type == DBTypes.SQL:
                if "storage-account-name" not in action_params:
                    raise Exception(
                        'Remedy script requires "storage-account-name" and its "resource-group-name" and "subscription-id" to store auditing logs in --actionParams'
                    )
            elif server_type == DBTypes.MYSQL_FLEXIBLE:
                if "storage-account-name" not in action_params:
                    raise Exception(
                        'Remedy script requires "storage-account-name" and its "resource-group-name" and "subscription-id" to store auditing logs in --actionParams'
                    )
            elif server_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
                if "storage-account-name" not in action_params:
                    raise Exception(
                        'Remedy script requires "storage-account-name" and its "resource-group-name" and "subscription-id" to store auditing logs in --actionParams'
                    )
    except Exception as ex:
        import sys

        logging.info(ex)
        help_args = sys.argv[0:3]
        help_args.append("--help")
        if verbose:
            from .__main__ import main

            main(help_args)

        is_valid_action_params = False

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

    raise TypeError(f"cannot find client of type {server_type.value}")


def enable_auditing_sql_server(
    credential,
    action_params,
    subscriptions=["all"],
    resource_groups=["all"],
    regions=["all"],
    server_names=["all"],
    dry_run=True,
):
    server_type = DBTypes.SQL
    logging.info(server_type)
    logging.debug(action_params)
    logging.debug(subscriptions)
    logging.debug(resource_groups)
    logging.debug(regions)
    logging.debug(server_names)
    logging.debug(dry_run)
    if "storage-auth-method" not in action_params:
        action_params["storage-auth-method"] = "default"

    final_result = []
    try:
        package = SQLServerUtils
        server_actions_generator = SQLServerActionsGenerator(
            credential, subscriptions, resource_groups, regions, server_names
        )
        server_actions = server_actions_generator.generate()

        if server_actions != None and server_actions.__len__() > 0:
            server_client = None
            for server_action in server_actions:
                server_action.data["subscription_id"]
                server_action.data["resource_group_name"]
                server_action.data["regions"]
                server_action.data[f"{server_type.value}_server_name"]

                if "subscription-id" not in action_params:
                    action_params["subscription-id"] = server_action.data[
                        "subscription_id"
                    ]
                if "resource-group-name" not in action_params:
                    action_params["resource-group-name"] = server_action.data[
                        "resource_group_name"
                    ]

                server_client = get_server_client(
                    credential,
                    server_type,
                    server_action.data["subscription_id"],
                )
                server = package.get_server(
                    server_client,
                    server_action.data["resource_group_name"],
                    server_action.data[f"{server_type.value}_server_name"],
                )

                auditing_policy = package.get_auditing_policy(
                    server_client,
                    server_action.data["resource_group_name"],
                    server_action.data[f"{server_type.value}_server_name"],
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
                            setup_result = package.setup_auditing_with_storage_account(
                                client=server_client,
                                resource_group_name=server_action.data[
                                    "resource_group_name"
                                ],
                                sql_server_name=server_action.data[
                                    f"{server_type.value}_server_name"
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
                        else:
                            raise Exception(
                                "Unknown target for storing Auditing Logs")
                    except Exception as ex:
                        logging.error(ex, exc_info=True)
                        result.set_string_result("fail", str(ex))
                final_result.append(result.as_dict())
                package.close_client(server_client)
        elif len(server_names) > 0 and server_names != ["all"]:
            for server_name in server_names:
                result = AzureExecutionResult(
                    "",
                    server_name,
                    "",
                    "no-action",
                    "",
                    "",
                    dry_run,
                )
                result.set_string_result(
                    "fail",
                    f"Could not find {server_type.pretty_str()} Server {server_name}. Please check the parameters provided are correct.",
                )
                final_result.append(result.as_dict())
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
                f"Could not find {server_type.pretty_str()} Server(s). Please check the parameters provided are correct.",
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


def enable_auditing_mysql_flexible_server(
    credential,
    action_params,
    subscriptions=["all"],
    resource_groups=["all"],
    regions=["all"],
    server_names=["all"],
    dry_run=True,
):
    server_type = DBTypes.MYSQL_FLEXIBLE
    logging.info(server_type)
    logging.debug(action_params)
    logging.debug(subscriptions)
    logging.debug(resource_groups)
    logging.debug(regions)
    logging.debug(server_names)
    logging.debug(dry_run)
    final_result = []
    try:
        package = MySQLFlexibleServerUtils
        server_actions_generator = MySQLFlexibleServerActionsGenerator(
            credential, subscriptions, resource_groups, regions, server_names
        )

        server_actions = server_actions_generator.generate()

        if server_actions != None and server_actions.__len__() > 0:
            server_client = None
            for server_action in server_actions:
                server_action.data["subscription_id"]
                server_action.data["resource_group_name"]
                server_action.data["regions"]
                server_action.data[f"{server_type.value}_server_name"]
                if "subscription-id" not in action_params:
                    action_params["subscription-id"] = server_action.data[
                        "subscription_id"
                    ]
                if "resource-group-name" not in action_params:
                    action_params["resource-group-name"] = server_action.data[
                        "resource_group_name"
                    ]

                server_client = get_server_client(
                    credential,
                    server_type,
                    server_action.data["subscription_id"],
                )
                server = package.get_server(
                    server_client,
                    server_action.data["resource_group_name"],
                    server_action.data[f"{server_type.value}_server_name"],
                )

                # setup connections log
                set_audit_logs_result = AzureExecutionResult(
                    "", "", "", "", "", "")
                try:
                    prev_state = package.get_audit_logs_configuration(
                        mysql_client=server_client,
                        resource_group_name=server_action.data["resource_group_name"],
                        server_name=server_action.data[
                            f"{server_type.value}_server_name"
                        ],
                    )
                    set_audit_logs_result = AzureExecutionResult(
                        prev_state.get("id"),
                        prev_state.get("name"),
                        prev_state.get("type"),
                        "update",
                        "",
                        "",
                        dry_run,
                    )
                    if package.is_audit_log_enabled(prev_state):
                        set_audit_logs_result.set_string_result(
                            "dryrun" if dry_run else "no-action",
                            f"Auditing settings (audit_log_enabled) of {server_type.pretty_str()} Server are ON",
                        )
                    else:
                        if dry_run:
                            set_audit_logs_result.set_string_result(
                                "dryrun",
                                f"Could update auditing settings of {server_type.pretty_str()} Server",
                            )
                        else:
                            current_state = package.set_audit_logs_configuration_value(
                                prev_state, enabled=True
                            )
                            current_state = package.set_audit_logs_configuration(
                                mysql_client=server_client,
                                resource_group_name=server_action.data[
                                    "resource_group_name"
                                ],
                                server_name=server_action.data[
                                    f"{server_type.value}_server_name"
                                ],
                                audit_log_enabled_configuration=current_state,
                            )
                            set_audit_logs_result.set_dict_result(
                                "success",
                                prev_state,
                                current_state,
                            )
                except Exception as ex:
                    logging.error(ex, exc_info=True)
                    set_audit_logs_result.set_string_result("fail", str(ex))
                final_result.append(set_audit_logs_result.as_dict())

                set_audit_logs_events_result = AzureExecutionResult(
                    "", "", "", "", "", ""
                )
                try:
                    prev_state = package.get_audit_log_events_configuration(
                        mysql_client=server_client,
                        resource_group_name=server_action.data["resource_group_name"],
                        server_name=server_action.data[
                            f"{server_type.value}_server_name"
                        ],
                    )
                    set_audit_logs_events_result = AzureExecutionResult(
                        prev_state.get("id"),
                        prev_state.get("name"),
                        prev_state.get("type"),
                        "update",
                        "",
                        "",
                        dry_run,
                    )
                    if package.is_audit_events_has_connections(prev_state):
                        set_audit_logs_events_result.set_string_result(
                            "dryrun" if dry_run else "no-action",
                            f"Auditing settings (audit_log_events) of {server_type.pretty_str()} Server have CONNECTION and CONNECTION_V2",
                        )
                    else:
                        if dry_run:
                            set_audit_logs_events_result.set_string_result(
                                "dryrun",
                                f"Could update auditing settings of {server_type.pretty_str()} Server",
                            )
                        else:
                            current_state = (
                                package.set_audit_logs_events_configuration_value(
                                    prev_state, enabled=True
                                )
                            )
                            current_state = package.set_audit_log_events_configuration(
                                mysql_client=server_client,
                                resource_group_name=server_action.data[
                                    "resource_group_name"
                                ],
                                server_name=server_action.data[
                                    f"{server_type.value}_server_name"
                                ],
                                audit_log_events_configuration=current_state,
                            )
                            set_audit_logs_events_result.set_dict_result(
                                "success",
                                prev_state,
                                current_state,
                            )
                except Exception as ex:
                    logging.error(ex, exc_info=True)
                    set_audit_logs_events_result.set_string_result(
                        "fail", str(ex))
                final_result.append(set_audit_logs_events_result.as_dict())
                diagnostics_setup_result = AzureExecutionResult(
                    "", "", "", "", "", "")
                try:
                    # setup diagnostics setting
                    monitor_client = get_client(
                        credential,
                        "monitor_management",
                        dict(
                            {"subscription_id":
                                server_action.data["subscription_id"]}
                        ),
                    )
                    diagnostics_setting_name = f"{server.name}-diagnostic-setting"
                    diagnostics_setting_id = f'/subscriptions/{server_action.data["subscription_id"]}/resourcegroups/{server_action.data["resource_group_name"]}/providers/microsoft.dbformysql/flexibleservers/{server.name}/providers/microsoft.insights/diagnosticSettings/{diagnostics_setting_name}'
                    diagnostics_setup_result = AzureExecutionResult(
                        diagnostics_setting_id,
                        diagnostics_setting_name,
                        "Microsoft.Insights/diagnosticSettings",
                        "create",
                        "",
                        "",
                        dry_run,
                    )
                    diagnostic_setting = package.get_audit_diagnostics(
                        monitor_client,
                        server_action.data["subscription_id"],
                        server.id,
                    )
                    is_enabled = package.is_audit_enabled(diagnostic_setting)
                    if not is_enabled:
                        if dry_run:
                            diagnostics_setup_result.set_string_result(
                                "dryrun",
                                f"Could create audit diagnostic settings of {server_type.pretty_str()} Server {server.name}",
                            )
                        else:
                            from library.StorageAccount import get_storage_account

                            storage_account = get_storage_account(
                                credential=credential,
                                subscription_id=action_params["subscription-id"],
                                resource_group_name=action_params[
                                    "resource-group-name"
                                ],
                                storage_account_name=action_params[
                                    "storage-account-name"
                                ],
                            )
                            if storage_account:
                                diagnostics_settings = package.setup_audit_enabled(
                                    monitor_client,
                                    server_action.data["subscription_id"],
                                    server.id,
                                    storage_account.id,
                                    diagnostics_setting_name,
                                )
                                diagnostics_setup_result.set_dict_result(
                                    "success", None, diagnostics_settings
                                )
                            else:
                                diagnostics_setup_result.set_string_result(
                                    "fail",
                                    f"diagnostics sink target storage account {storage_account_id} not found",
                                )
                    else:
                        diagnostics_setup_result.set_string_result(
                            "dryrun" if dry_run else "no-action",
                            f"Found audit diagnostic settings of {server_type.pretty_str()} Server {server.name}",
                        )
                    monitor_client.close()
                except Exception as ex:
                    logging.error(ex, exc_info=True)
                    diagnostics_setup_result.set_string_result("fail", str(ex))
                final_result.append(diagnostics_setup_result.as_dict())
                package.close_client(server_client)
        elif len(server_names) > 0 and server_names != ["all"]:
            for server_name in server_names:
                result = AzureExecutionResult(
                    "",
                    server_name,
                    "",
                    "no-action",
                    "",
                    "",
                    dry_run,
                )
                result.set_string_result(
                    "fail",
                    f"Could not find {server_type.pretty_str()} Server {server_name}. Please check the parameters provided are correct.",
                )
                final_result.append(result.as_dict())
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
                f"Could not find {server_type.pretty_str()} Server(s). Please check the parameters provided are correct.",
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


def enable_auditing_postgre_sql_flexible_server(
    credential,
    action_params,
    subscriptions=["all"],
    resource_groups=["all"],
    regions=["all"],
    server_names=["all"],
    dry_run=True,
):
    server_type = DBTypes.POSTGRE_SQL_FLEXIBLE
    logging.info(server_type)
    logging.debug(action_params)
    logging.debug(subscriptions)
    logging.debug(resource_groups)
    logging.debug(regions)
    logging.debug(server_names)
    logging.debug(dry_run)
    final_result = []
    try:
        package = PostgreSQLFlexibleServerUtils
        server_actions_generator = PostgreSQLFlexibleServerActionsGenerator(
            credential, subscriptions, resource_groups, regions, server_names
        )

        server_actions = server_actions_generator.generate()

        if server_actions != None and server_actions.__len__() > 0:
            server_client = None
            for server_action in server_actions:
                server_action.data["subscription_id"]
                server_action.data["resource_group_name"]
                server_action.data["regions"]
                server_action.data[f"{server_type.value}_server_name"]
                if "subscription-id" not in action_params:
                    action_params["subscription-id"] = server_action.data[
                        "subscription_id"
                    ]
                if "resource-group-name" not in action_params:
                    action_params["resource-group-name"] = server_action.data[
                        "resource_group_name"
                    ]

                server_client = get_server_client(
                    credential,
                    server_type,
                    server_action.data["subscription_id"],
                )
                server = package.get_server(
                    server_client,
                    server_action.data["resource_group_name"],
                    server_action.data[f"{server_type.value}_server_name"],
                )

                diagnostics_setup_result = AzureExecutionResult(
                    "", "", "", "", "", "")
                try:
                    # setup diagnostics setting
                    monitor_client = get_client(
                        credential,
                        "monitor_management",
                        dict(
                            {"subscription_id":
                                server_action.data["subscription_id"]}
                        ),
                    )
                    diagnostics_setting_name = f"{server.name}-diagnostic-setting"
                    diagnostics_setting_id = f'/subscriptions/{server_action.data["subscription_id"]}/resourcegroups/{server_action.data["resource_group_name"]}/providers/microsoft.dbforpostgresql/flexibleservers/{server.name}/providers/microsoft.insights/diagnosticSettings/{diagnostics_setting_name}'
                    diagnostics_setup_result = AzureExecutionResult(
                        diagnostics_setting_id,
                        diagnostics_setting_name,
                        "Microsoft.Insights/diagnosticSettings",
                        "create",
                        "",
                        "",
                        dry_run,
                    )
                    diagnostic_setting = package.get_audit_diagnostics(
                        monitor_client,
                        server_action.data["subscription_id"],
                        server.id,
                    )
                    is_enabled = package.is_audit_enabled(diagnostic_setting)
                    if not is_enabled:
                        if dry_run:
                            diagnostics_setup_result.set_string_result(
                                "dryrun",
                                f"Could create audit diagnostic settings of {server_type.pretty_str()} Server {server.name}",
                            )
                        else:
                            from library.StorageAccount import get_storage_account

                            storage_account = get_storage_account(
                                credential=credential,
                                subscription_id=action_params["subscription-id"],
                                resource_group_name=action_params[
                                    "resource-group-name"
                                ],
                                storage_account_name=action_params[
                                    "storage-account-name"
                                ],
                            )
                            if storage_account:
                                diagnostics_settings = package.setup_audit_enabled(
                                    monitor_client,
                                    server_action.data["subscription_id"],
                                    server.id,
                                    storage_account.id,
                                    diagnostics_setting_name,
                                )
                                diagnostics_setup_result.set_dict_result(
                                    "success", None, diagnostics_settings
                                )
                            else:
                                diagnostics_setup_result.set_string_result(
                                    "fail",
                                    f"diagnostics sink target storage account {storage_account_id} not found",
                                )
                    else:
                        diagnostics_setup_result.set_string_result(
                            "dryrun" if dry_run else "no-action",
                            f"Found audit diagnostic settings of {server_type.pretty_str()} Server {server.name}",
                        )
                    monitor_client.close()
                except Exception as ex:
                    logging.error(ex, exc_info=True)
                    diagnostics_setup_result.set_string_result("fail", str(ex))
                final_result.append(diagnostics_setup_result.as_dict())
                package.close_client(server_client)
        elif len(server_names) > 0 and server_names != ["all"]:
            for server_name in server_names:
                result = AzureExecutionResult(
                    "",
                    server_name,
                    "",
                    "no-action",
                    "",
                    "",
                    dry_run,
                )
                result.set_string_result(
                    "fail",
                    f"Could not find {server_type.pretty_str()} Server {server_name}. Please check the parameters provided are correct.",
                )
                final_result.append(result.as_dict())
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
                f"Could not find {server_type.pretty_str()} Server(s). Please check the parameters provided are correct.",
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
            prev_state_json["executionType"]
            in ["sql-server", "mysql-server", "postgresql-server"]
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
                    package = SQLServerUtils
                    subscription_id = action["Asset"]["Id"].split("/")[2]
                    resource_group_name = action["Asset"]["Id"].split("/")[4]
                    sql_server_name = action["Asset"]["Id"].split("/")[8]
                    if action["ActionStatus"] == "success":
                        server_client = get_client(
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
                            result = package.setup_auditing_using_policy(
                                server_client=server_client,
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
                elif (
                    action["Asset"]["Type"]
                    == "Microsoft.DBforMySQL/flexibleServers/configurations"
                ):
                    package = MySQLFlexibleServerUtils
                    subscription_id = action["Asset"]["Id"].split("/")[2]
                    resource_group_name = action["Asset"]["Id"].split("/")[4]
                    mysql_server_name = action["Asset"]["Id"].split("/")[8]
                    if action["ActionStatus"] == "success":
                        server_client = get_client(
                            credential,
                            "mysql_flexible_server",
                            dict({"subscription_id": subscription_id}),
                        )
                        if action["Asset"]["Name"] == "audit_log_enabled":
                            try:
                                result = package.set_audit_logs_configuration(
                                    mysql_client=server_client,
                                    resource_group_name=resource_group_name,
                                    server_name=mysql_server_name,
                                    audit_log_enabled_configuration=action[
                                        "ExecutionResultData"
                                    ]["Result"]["current_state"],
                                )
                                new_action.set_dict_result(
                                    "success",
                                    action["ExecutionResultData"]["Result"][
                                        "current_state"
                                    ],
                                    result,
                                )
                            except Exception as ex:
                                logging.exception(ex)
                                new_action.set_string_result("fail", str(ex))
                            new_actions.append(new_action.as_dict())
                        elif action["Asset"]["Name"] == "audit_log_events":
                            try:
                                result = package.set_audit_log_events_configuration(
                                    mysql_client=server_client,
                                    resource_group_name=resource_group_name,
                                    server_name=mysql_server_name,
                                    audit_log_events_configuration=action[
                                        "ExecutionResultData"
                                    ]["Result"]["current_state"],
                                )
                                new_action.set_dict_result(
                                    "success",
                                    action["ExecutionResultData"]["Result"][
                                        "current_state"
                                    ],
                                    result,
                                )
                            except Exception as ex:
                                logging.exception(ex)
                                new_action.set_string_result("fail", str(ex))
                            new_actions.append(new_action.as_dict())
                        else:
                            pass
                    else:
                        pass
                elif action["Asset"]["Type"] == "Microsoft.Insights/diagnosticSettings":
                    package = MySQLFlexibleServerUtils
                    subscription_id = action["Asset"]["Id"].split("/")[2]
                    resource_group_name = action["Asset"]["Id"].split("/")[4]
                    mysql_server_name = action["Asset"]["Id"].split("/")[8]
                    mysql_server_id = "/".join(
                        [
                            action["Asset"]["Id"].split(mysql_server_name)[0],
                            mysql_server_name,
                        ]
                    )
                    if action["ActionStatus"] == "success":
                        monitor_client = get_client(
                            credential,
                            "monitor_management",
                            dict({"subscription_id": subscription_id}),
                        )
                        package.remove_audit_enabled(
                            monitor_client, mysql_server_id, action["Asset"]["Name"]
                        )
                        new_action.set_dict_result(
                            "success",
                            action["ExecutionResultData"]["Result"]["current_state"],
                            action["ExecutionResultData"]["Result"]["prev_state"],
                        )
                        new_actions.append(new_action.as_dict())
                else:
                    pass
    return new_actions
