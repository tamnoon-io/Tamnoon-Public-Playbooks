import json
import logging
import sys
import os


from azure.mgmt.loganalytics.models import Workspace


from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import get_client
from library.BlobStorage import get_new_analytics_logging_obj
from library.Subscriptions import get_subscriptions
from library.ResourceGroups import get_resource_groups
from library.LogAnalyticsWorkspace import get_logs_analytics_workspace
from library.StorageAccount import (
    get_storage_account,
    get_storage_accounts,
    get_diagnostic_setting,
    create_diagnostic_setting,
)


def validate_action_params(action_params) -> bool:
    """
    This method validates action params.
    Returns True for valid values, and False for invalid values.

    :param action_params: - (Required) values to validate.

    :return: bool
    """
    if "rollBack" in action_params:
        if "lastExecutionResultPath" not in action_params:
            raise Exception(
                "You are trying to execute roll back with no 'lastExecutionResultPath' parameter, the script have to know the previous saved state"
            )
    else:
        if "create-la-ws" in action_params:
            if "log-analytics-workspace-name" not in action_params:
                raise Exception(
                    "'create-la-ws' requires 'log-analytics-workspace-name'"
                )
    return True


def rollback_enable_storage_logging(
    credential,
    last_execution_result_path,
    dry_run=True,
) -> [dict]:
    """
    This method resets the modifications done by enable_storage_logging() method.

    :param credential: - (Required) Azure Credential.

    :param last_execution_result_path: - (Required) path to the file that has json result.

    :param dry_run: - (Optional) if False then performs actual operations on Cloud; default
    is True, where script will output the actions that can be performed by the
    script to rollback the result

    :return: [dict]
    """
    new_actions = []
    with open(last_execution_result_path, "r") as prev_state:
        prev_state_json = json.load(prev_state)

        if (
            prev_state_json["executionType"] == "blob-container"
            and prev_state_json["executionAction"]
            == "enable_log_analytics_logs_for_azure_storage_blobs"
        ):
            rollback_actions = serialize_rollback_actions(
                prev_state_json["executionResult"]
            )
            for action in rollback_actions:
                logging.debug(f"\n\t{action}")

                if (
                    action["Asset"]["Action"] == "create"
                    and action["ActionStatus"].lower() == "success"
                ):
                    # new resource was created. rollback action is delete new resource
                    if action["Asset"]["Type"] == "log_analytics_workspace":
                        subscription_id = action["Asset"]["Id"].split("/")[2]
                        resource_group_name = action["Asset"]["Id"].split("/")[4]
                        workspace_name = action["Asset"]["Name"]
                        if dry_run:
                            message = f"Dry run - Could delete log analytics workspace {workspace_name} from {resource_group_name} resource group"
                            logging.info(message)
                            action["ActionStatus"] = "dryrun"
                            action["ExecutionResultData"] = dict(
                                {"ResultType": "string", "Result": message}
                            )
                        else:
                            log_analytics_mgmt_client = get_client(
                                credential,
                                "log_analytics_management",
                                dict({"subscription_id": subscription_id}),
                            )
                            log_analytics_mgmt_client.workspaces.begin_delete(
                                workspace_name=workspace_name,
                                resource_group_name=resource_group_name,
                            ).result()
                            log_analytics_mgmt_client.close()
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
                            action["ActionStatus"] = "Success"
                            action["Asset"]["Action"] = "delete"
                    elif action["Asset"]["Type"] == "diagnostic_settings":
                        subscription_id = action["Asset"]["Id"].split("/")[2]
                        diagnostic_setting_name = action["Asset"]["Name"]
                        resource_group_name = action["Asset"]["Id"].split("/")[4]
                        storage_account_name = action["Asset"]["Id"].split("/")[8]
                        resource_uri = "/".join(action["Asset"]["Id"].split("/")[0:11])
                        if dry_run:
                            message = f"Dry run - Could delete diagnostic setting {diagnostic_setting_name} from {resource_group_name} resource group."
                            logging.info(message)
                            action["ActionStatus"] = "dryrun"
                            action["ExecutionResultData"] = dict(
                                {"ResultType": "string", "Result": message}
                            )
                        else:
                            monitor_management_client = get_client(
                                credential,
                                "monitor_management",
                                dict(
                                    {
                                        "subscription_id": subscription_id,
                                        "api_version": "2021-05-01-preview",
                                    }
                                ),
                            )
                            monitor_management_client.diagnostic_settings.delete(
                                name=diagnostic_setting_name,
                                resource_uri=resource_uri,
                            )
                            monitor_management_client.close()
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
                            action["ActionStatus"] = "Success"
                            action["Asset"]["Action"] = "delete"

                elif (
                    action["Asset"]["Action"] == "update"
                    and action["ActionStatus"].lower() == "success"
                ):
                    # existing resource was updated. rollback action is undo modifications
                    if action["Asset"]["Type"] == "diagnostic_settings":
                        subscription_id = action["Asset"]["Id"].split("/")[2]
                        diagnostic_setting_name = action["Asset"]["Name"]
                        resource_group_name = action["Asset"]["Id"].split("/")[4]
                        storage_account_name = action["Asset"]["Id"].split("/")[8]
                        resource_uri = "/".join(action["Asset"]["Id"].split("/")[0:11])
                        if dry_run:
                            message = f"Dry run - Could undo diagnostic setting {diagnostic_setting_name} in {resource_group_name} resource group."
                            logging.info(message)
                            action["ActionStatus"] = "dryrun"
                            action["ExecutionResultData"] = dict(
                                {"ResultType": "string", "Result": message}
                            )
                            action["ExecutionResultData"]["ResultType"] = "string"
                            action["ExecutionResultData"]["Result"] = message
                        else:
                            monitor_management_client = get_client(
                                credential,
                                "monitor_management",
                                dict(
                                    {
                                        "subscription_id": subscription_id,
                                        "api_version": "2021-05-01-preview",
                                    }
                                ),
                            )
                            diagnostics_setting = DiagnosticSettingsResource(
                                id=action["ExecutionResultData"]["Result"][
                                    "prev_state"
                                ]["id"],
                                storage_account_id=action["ExecutionResultData"][
                                    "Result"
                                ]["prev_state"]["storage_acccout_id"],
                                workspace_id=action["ExecutionResultData"]["Result"][
                                    "prev_state"
                                ]["workspace_id"],
                                logs=action["ExecutionResultData"]["Result"][
                                    "prev_state"
                                ]["logs"],
                                metrics=action["ExecutionResultData"]["Result"][
                                    "prev_state"
                                ]["metrics"],
                                log_analytics_destination_type=action[
                                    "ExecutionResultData"
                                ]["Result"]["prev_state"][
                                    "log_analytics_destination_type"
                                ],
                            )
                            monitor_management_client.diagnostic_settings.create_or_update(
                                name=diagnostics_setting_name,
                                resource_uri=resource_uri,
                                parameters=diagnostics_setting,
                                content_type="application/json",
                            )
                            monitor_management_client.close()
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
                            action["ActionStatus"] = "Success"
                            action["Asset"]["Action"] = "update"
                    elif action["Asset"]["Type"] == "blob_container":
                        storage_account_name = action["Asset"]["Id"]
                        if dry_run:
                            message = f"Dry run - Could undo storage account analytics logging setting of blob containers in {storage_account_name} storage account."
                            logging.info(message)
                            action["ActionStatus"] = "dryrun"
                            action["ExecutionResultData"] = dict(
                                {"ResultType": "string", "Result": message}
                            )
                        else:
                            blob_service_client = get_client(
                                credential,
                                "blob_service",
                                dict({"StorageAccountName": storage_account_name}),
                            )
                            blob_service_client.set_service_properties(
                                analytics_logging=action["ExecutionResultData"][
                                    "Result"
                                ]["prev_state"]["analytics_logging"]
                            )
                            blob_service_client.close()
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
                            action["ActionStatus"] = "Success"
                            action["Asset"]["Action"] = "update"

                new_actions.append(action)
        else:
            logging.error(
                f'{prev_state_json["executionType"]}:{prev_state_json["executionAction"]}'
            )
            raise Exception(
                "File does not contain result of enable_log_analytics_logs_for_azure_storage_blobs"
            )
    return new_actions


def new_action(subscription_id, resource_group, storage_account):
    return {
        "subscription_id": subscription_id,
        "resource_group_name": resource_group.name,
        "resource_group_region": resource_group.location,
        "storage_account_id": storage_account.id,
        "storage_account_region": storage_account.location,
        "diagnostic_setting_name": f"{resource_group.name}-diagnostic-setting",
    }


def enable_storage_logging(
    credential,
    action_params,
    subscriptions,
    resource_group_names,
    storage_accounts,
    regions,
    dry_run=True,
) -> [dict]:
    """
    This method enables the logging of operations of Blob Services in given Storage Accounts
    and sets the target Log Analytics Workspace.

    :param credential: - (Required) Azure Credential.

    :param action_params: (Required)
        for enabling logging -
            1. log-analytics-workspace-name - (Required) - name of log analytics workspace, where
            you want your storage account to direct its logs to
            2. create-la-ws - (Optional) - Boolean flag to create workspace with
            log-analytics-workspace-name, if it is not found in given subscription

        for rollback -
            1. rollBack - (Optional) - Boolean flag to sign if this is a rollback call (required the
            existing of state file)
            2. lastExecutionResultPath (Optional) - The path for the last execution that we want to
            roll-back from - if roll-back provided this parameter become mandatory

    :param regions: - (Optional) - used to find Storage Accounts by location and create Log Analytics
        Workspace.
            If provided, then logging is enabled in all given Storage Accounts in given
        Subscriptions which are found with any of the given regions. Same region is used to
        create Log Analytics Workspace, if required in given Subscriptions

    :param subscriptions: - (Optional) - list of Subscription ids.

    :param resource_group_names: - (Optional) - list of Resource Group names

    :param storage_accounts: - (Optional) - list of Storage Account names

    :param dry_run: - (Optional) if False then performs actual operations on Cloud; default
        is True, where script will output the actions that can be performed by the
        script to remedy the problem.

    :return: [dict]
    """

    final_result = []
    for storage_account_name in storage_accounts:
        result = {
            "Asset": {
                "Id": "",
                "Name": storage_account_name,
                "Type": "assetId",
                "Action": "no-action",
                "CloudAccountId": "",
                "CloudProvider": "azure",
                "Region": regions,
            },
            "ExecutionResultData": {"ResultType": "list", "Result": []},
        }

        actions = []

        log_analytics_workspace_name = action_params["log-analytics-workspace-name"]
        create_la_ws = "create-la-ws" in action_params and action_params["create-la-ws"]
        is_all_subscriptions = (
            subscriptions.__len__() == 1 and subscriptions[0] == "all"
        )

        found_subscriptions = list(
            map(
                lambda subscription: subscription.subscription_id,
                list(
                    filter(
                        lambda subscription: is_all_subscriptions
                        or subscriptions.__contains__(subscription.subscription_id),
                        get_subscriptions(credential),
                    )
                ),
            )
        )
        if is_all_subscriptions:
            subscriptions = found_subscriptions

        is_all_regions = regions.__len__() == 1 and regions[0] == "all"

        is_all_storage_accounts = storage_account_name == "all"

        try:
            storage_account_found = False
            # loop on subscriptions
            for subscription_id in subscriptions:
                if not is_all_storage_accounts and storage_account_found:
                    break
                if not found_subscriptions.__contains__(subscription_id):
                    # if subscription is not found, then skip this iteration
                    err_msg = f"subscription {subscription_id} not found"
                    logging.info(err_msg)
                    result["ExecutionResultData"]["Result"].append(
                        dict(
                            {
                                "Asset": {
                                    "Id": subscription_id,
                                    "Name": "",
                                    "Type": "subscription",
                                    "Action": "no-action",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": "",
                                },
                                "ActionStatus": "dryrun" if dry_run else "skip",
                                "ErrorMessage": err_msg,
                            }
                        )
                    )
                    continue
                logging.debug(f"subscription {subscription_id} found")
                resource_groups = get_resource_groups(
                    credential,
                    subscription_id,
                    resource_group_names=resource_group_names,
                    locations=regions,
                )
                for resource_group in resource_groups:
                    if not is_all_storage_accounts and storage_account_found:
                        break

                    storage_accounts = list(
                        get_storage_accounts(
                            credential,
                            subscription_id,
                            resource_group.name,
                        )
                    )
                    for storage_account in storage_accounts:
                        storage_account_found = is_all_storage_accounts or (
                            storage_account.name == storage_account_name
                            and (
                                is_all_regions
                                or regions.__contains__(storage_account.location)
                            )
                        )
                        if not is_all_storage_accounts and not storage_account_found:
                            logging.debug(
                                f"storage account {storage_account_name} not found in resource group {resource_group.name}"
                            )
                            continue
                        else:
                            actions.append(
                                new_action(
                                    subscription_id, resource_group, storage_account
                                )
                            )

            if not is_all_storage_accounts and not storage_account_found:
                message = f"{'Dry run - s' if dry_run else 'S'}torage account {storage_account_name} not found"
                logging.info(message)
                result["ExecutionResultData"]["Result"].append(
                    dict(
                        {
                            "Asset": {
                                "Id": "",
                                "Name": storage_account_name,
                                "Type": "storage_account",
                                "Action": "no-action",
                                "CloudAccountId": "",
                                "CloudProvider": "azure",
                                "Region": regions,
                            },
                            "ActionStatus": "dryrun" if dry_run else "skip",
                            "ExecutionResultData": {
                                "ResultType": "string",
                                "Result": message,
                            },
                        }
                    )
                )
        except Exception as ex:
            logging.exception(ex)
            result["ErrorMessage"] = ex.__str__()
            result["ActionStatus"] = "Fail"
            return result

        if actions.__len__() == 0:
            result["ErrorMessage"] = "Resources not found"
            result["ActionStatus"] = "Fail"
            return result

        try:
            if dry_run:
                logging.info(
                    "#################### This is a Dry Run ###########################"
                )
                result["ActionStatus"] = "dryrun"

            remedy_failed_because = ""
            for action in actions:
                logging.debug(f"action\n\t{action}")
                subscription_id = action["subscription_id"]
                resource_group_name = action["resource_group_name"]
                resource_group_region = action["resource_group_region"]
                storage_account_id = action["storage_account_id"]
                storage_account_region = action["storage_account_region"]
                diagnostics_setting_name = action["diagnostic_setting_name"]

                result["ExecutionResultData"]["Result"].append(
                    dict(
                        {
                            "Asset": {
                                "Id": storage_account_id,
                                "Name": storage_account.name,
                                "Type": "storage_account",
                                "Action": "no-action",
                                "CloudAccountId": "",
                                "CloudProvider": "azure",
                                "Region": storage_account_region,
                            },
                            "ActionStatus": "dryrun" if dry_run else "Success",
                            "ExecutionResultData": {
                                "ResultType": "list",
                                "Result": [],
                            },
                        }
                    )
                )
                storage_result_index = (
                    result["ExecutionResultData"]["Result"].__len__() - 1
                )

                logging.debug(f"storage account {storage_account.name} found")
                # 1
                workspace = get_logs_analytics_workspace(
                    credential,
                    subscription_id,
                    log_analytics_workspace_name,
                    resource_group_region,
                )
                prev_workspace = None
                if workspace == None:
                    if create_la_ws:
                        if dry_run:
                            err_msg = "Dry run - blob storage log analytics workspace could be created"
                            logging.info(err_msg)
                            result["ExecutionResultData"]["Result"][
                                storage_result_index
                            ]["ExecutionResultData"]["Result"].append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": "",
                                            "Name": log_analytics_workspace_name,
                                            "Type": "log_analytics_workspace",
                                            "Action": "no-action",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": resource_group_region,
                                        },
                                        "ActionStatus": "dryrun",
                                        "ErrorMessage": err_msg,
                                    }
                                )
                            )
                        else:
                            logging.info(
                                "create_la_ws is set. Creating log analytics workspace..."
                            )
                            #
                            prev_workspace = workspace
                            log_analytics_mgmt_client = get_client(
                                credential,
                                "log_analytics_management",
                                dict({"subscription_id": subscription_id}),
                            )

                            workspace = log_analytics_mgmt_client.workspaces.begin_create_or_update(
                                resource_group_name=resource_group_name,
                                workspace_name=log_analytics_workspace_name,
                                parameters=Workspace(location=resource_group_region),
                            ).result()
                    else:
                        err_msg = ""
                        if dry_run:
                            message = "Dry run - blob storage log analytics workspace could be created"
                            logging.info(message)
                            result["ExecutionResultData"]["Result"][
                                storage_result_index
                            ]["ExecutionResultData"]["Result"].append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": "",
                                            "Name": log_analytics_workspace_name,
                                            "Type": "log_analytics_workspace",
                                            "Action": "create",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": resource_group_region,
                                        },
                                        "ActionStatus": "dryrun",
                                        "ExecutionResultData": {
                                            "ResultType": "string",
                                            "Result": message,
                                        },
                                    }
                                )
                            )
                        else:
                            err_msg = "blob storage log analytics workspace not found."
                            logging.info(err_msg)
                            la_ws_result = dict(
                                {
                                    "Asset": {
                                        "Id": "",
                                        "Name": log_analytics_workspace_name,
                                        "Action": "no-action",
                                        "Type": "log_analytics_workspace",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": resource_group_region,
                                    },
                                    "ActionStatus": "Fail",
                                    "ErrorMessage": err_msg,
                                }
                            )
                            result["ExecutionResultData"]["Result"][
                                storage_result_index
                            ]["ExecutionResultData"]["Result"].append(la_ws_result)
                            if remedy_failed_because == "":
                                remedy_failed_because = err_msg

                        # continue
                else:
                    prev_workspace = workspace
                # 2.1 if no log analytics workspace, then no diagnostic setting
                if workspace == None:
                    message = f"{'Dry run - c' if dry_run else 'C'}ould not create Diagnostics Setting {diagnostics_setting_name} because Log Analytics Workspace {log_analytics_workspace_name} was not found"
                    logging.info(message)
                    result["ExecutionResultData"]["Result"][storage_result_index][
                        "ExecutionResultData"
                    ]["Result"].append(
                        dict(
                            {
                                "Asset": {
                                    "Id": "",
                                    "Name": diagnostics_setting_name,
                                    "Type": "diagnostic_settings",
                                    "Action": "create" if create_la_ws else "no-action",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": resource_group_region,
                                },
                                "ActionStatus": "dryrun" if dry_run else "Fail",
                                "ErrorMessage": message,
                            }
                        )
                    )
                    message_2 = f"{'Dry run - c' if dry_run else 'C'}ould not modify logging settings of blob storage"
                    logging.info(message_2)
                    result["ExecutionResultData"]["Result"][storage_result_index][
                        "ExecutionResultData"
                    ]["Result"].append(
                        dict(
                            {
                                "Asset": {
                                    "Id": storage_account.name,
                                    "Name": "",
                                    "Type": "blob_container",
                                    "Action": "update",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": storage_account_region,
                                },
                                "ActionStatus": "dryrun" if dry_run else "Fail",
                                "ExecutionResultData": {
                                    "ResultType": "string",
                                    "Result": message_2,
                                },
                            }
                        )
                    )
                    if remedy_failed_because == "":
                        remedy_failed_because = message + " " + message_2
                    continue
                else:
                    log_result = None
                    if prev_workspace != None:
                        log_result = dict(
                            {
                                "Asset": {
                                    "Id": workspace.id,
                                    "Name": log_analytics_workspace_name,
                                    "Type": "log_analytics_workspace",
                                    "Action": "no-action",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": resource_group_region,
                                },
                                "ActionStatus": "dryrun" if dry_run else "Success",
                                "ExecutionResultData": {
                                    "ResultType": "string",
                                    "Result": f"Log Analytics Workspace {log_analytics_workspace_name} found",
                                },
                            }
                        )
                        logging.info(
                            "blob storage log analytics workspace settings found successfully"
                        )
                    else:
                        log_result = dict(
                            {
                                "Asset": {
                                    "Id": workspace.id,
                                    "Name": log_analytics_workspace_name,
                                    "Type": "log_analytics_workspace",
                                    "Action": "create",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": resource_group_region,
                                },
                                "ActionStatus": "Success",
                                "ExecutionResultData": {
                                    "ResultType": "object",
                                    "Result": {
                                        "prev_state": prev_workspace,
                                        "current_state": workspace.as_dict(),
                                    },
                                },
                            }
                        )
                        logging.info(
                            "blob storage log analytics workspace settings created successfully"
                        )
                    result["ExecutionResultData"]["Result"][storage_result_index][
                        "ExecutionResultData"
                    ]["Result"].append(log_result)

                workspace_id = workspace.id

                storage_acccout_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Storage/storageAccounts/{storage_account.name}"
                resource_uri = f"{storage_acccout_id}/blobServices/default"

                # 2.2
                diagnostics_settings = get_diagnostic_setting(
                    credential,
                    subscription_id=subscription_id,
                    resource_uri=resource_uri,
                    diagnostics_setting_name=diagnostics_setting_name,
                )
                prev_diagnostics_settings = None
                if dry_run:
                    if diagnostics_settings != None:
                        message = "Dry run - diagnostics setting found. Could update the setting."
                        logging.info(message)
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": diagnostics_settings.id,
                                        "Name": diagnostics_setting_name,
                                        "Type": "diagnostic_settings",
                                        "Action": "create",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": resource_group_region,
                                    },
                                    "ActionStatus": "dryrun",
                                    "ExecutionResultData": {
                                        "ResultType": "string",
                                        "Result": message,
                                    },
                                }
                            )
                        )
                    else:
                        message = "Dry run - could create diagnostics setting"
                        logging.info(message)
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": "",
                                        "Name": diagnostics_setting_name,
                                        "Type": "diagnostic_settings",
                                        "Action": "create",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": resource_group_region,
                                    },
                                    "ActionStatus": "dryrun",
                                    "ExecutionResultData": {
                                        "ResultType": "string",
                                        "Result": message,
                                    },
                                }
                            )
                        )
                else:
                    logging.info(
                        f"subscription_id={subscription_id},diagnostics_setting_name={diagnostics_setting_name},resource_uri={workspace_id},workspace_id={workspace_id}"
                    )

                    # 2.2
                    ex = None
                    if diagnostics_settings == None:
                        prev_diagnostics_settings = diagnostics_settings
                        [diagnostics_settings, ex] = create_diagnostic_setting(
                            credential,
                            subscription_id=subscription_id,
                            diagnostics_setting_name=diagnostics_setting_name,
                            resource_uri=resource_uri,
                            workspace_id=workspace_id,
                            storage_acccout_id=storage_account_id,
                            resolve_noregisteredproviderfound_error=True,
                        )
                    if diagnostics_settings != None:
                        result["ActionStatus"] = "Success"
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ActionStatus"
                        ] = "Success"
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": diagnostics_settings.id,
                                        "Name": diagnostics_setting_name,
                                        "Type": "diagnostic_settings",
                                        "Action": "update"
                                        if prev_diagnostics_settings != None
                                        else "create",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": resource_group_region,
                                    },
                                    "ActionStatus": "Success",
                                    "ExecutionResultData": {
                                        "ResultType": "object",
                                        "Result": {
                                            "prev_state": prev_diagnostics_settings.as_dict()
                                            if prev_diagnostics_settings != None
                                            else None,
                                            "current_state": diagnostics_settings.as_dict(),
                                        },
                                    },
                                }
                            )
                        )
                        #
                        blob_service_client = get_client(
                            credential,
                            "blob_service",
                            dict({"StorageAccountName": storage_account.name}),
                        )
                        service_properties = (
                            blob_service_client.get_service_properties()
                        )

                        if dry_run:
                            message = (
                                "Dry run - can modify logging settings of blob storage"
                            )
                            logging.info(message)
                            result["ExecutionResultData"]["Result"][
                                storage_result_index
                            ]["ExecutionResultData"]["Result"].append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": storage_account.name,
                                            "Name": "",
                                            "Type": "blob_container",
                                            "Action": "update",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": storage_account_region,
                                        },
                                        "ActionStatus": "dryrun",
                                        "ExecutionResultData": {
                                            "ResultType": "string",
                                            "Result": message,
                                        },
                                    }
                                )
                            )
                        else:
                            # 3
                            blob_service_client.set_service_properties(
                                analytics_logging=get_new_analytics_logging_obj()
                            )
                            result["ExecutionResultData"]["Result"][
                                storage_result_index
                            ]["ExecutionResultData"]["Result"].append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": storage_account.name,
                                            "Name": "",
                                            "Type": "blob_container",
                                            "Action": "update",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": storage_account_region,
                                        },
                                        "ActionStatus": "Success",
                                        "ExecutionResultData": {
                                            "ResultType": "object",
                                            "Result": {
                                                "prev_state": {
                                                    "analytics_logging": service_properties.get(
                                                        "analytics_logging"
                                                    ).as_dict(),
                                                },
                                                "current_state": {
                                                    "analytics_logging": blob_service_client.get_service_properties()
                                                    .get("analytics_logging")
                                                    .as_dict(),
                                                },
                                            },
                                        },
                                    }
                                )
                            )
                        if blob_service_client != None:
                            blob_service_client.close()
                    elif ex != None:
                        err_msg = f"Could {'' if dry_run else 'not '}create diagnostic setting because {ex}"
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": "",
                                        "Name": diagnostics_setting_name,
                                        "Type": "diagnostic_settings",
                                        "Action": "create",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": resource_group_region,
                                    },
                                    "ActionStatus": "dryrun" if dry_run else "Fail",
                                    "ErrorMessage": err_msg,
                                }
                            )
                        )
                        message = "can modify logging settings of blob storage"
                        logging.info(message)
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.name,
                                        "Name": "",
                                        "Type": "blob_container",
                                        "Action": "update",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": storage_account_region,
                                    },
                                    "ActionStatus": "dryrun" if dry_run else "Fail",
                                    "ExecutionResultData": {
                                        "ResultType": "string",
                                        "Result": message,
                                    },
                                }
                            )
                        )
                        if remedy_failed_because == "":
                            remedy_failed_because = err_msg
                    else:
                        err_msg = f"Could {'' if dry_run else 'not '}create diagnostic setting due to unknown reason"
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": "",
                                        "Name": diagnostics_setting_name,
                                        "Type": "diagnostic_settings",
                                        "Action": "create",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": resource_group_region,
                                    },
                                    "ActionStatus": "dryrun" if dry_run else "Fail",
                                    "ErrorMessage": err_msg,
                                }
                            )
                        )
                        message = f"Could {'' if dry_run else 'not '}modify logging settings of blob storage"
                        logging.info(message)
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.name,
                                        "Name": "",
                                        "Type": "blob_container",
                                        "Action": "update",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": storage_account_region,
                                    },
                                    "ActionStatus": "dryrun" if dry_run else "Fail",
                                    "ExecutionResultData": {
                                        "ResultType": "string",
                                        "Result": message,
                                    },
                                }
                            )
                        )
                        if remedy_failed_because == "":
                            remedy_failed_because = err_msg

                if (
                    result["ExecutionResultData"]["Result"][storage_result_index][
                        "Asset"
                    ]["Type"]
                    != "blob_container"
                ):
                    if (
                        dry_run
                        and result["ExecutionResultData"]["Result"][
                            storage_result_index - 1
                        ]["ExecutionResultData"]["ResultType"]
                        == "list"
                    ):
                        last_index = (
                            result["ExecutionResultData"]["Result"][
                                storage_result_index - 1
                            ]["ExecutionResultData"]["Result"].__len__()
                            - 1
                        )
                        last_result = result["ExecutionResultData"]["Result"][
                            storage_result_index - 1
                        ]["ExecutionResultData"]["Result"][last_index]
                        if "ErrorMessage" in last_result:
                            remedy_failed_because = last_result["ErrorMessage"]

                    if remedy_failed_because != "":
                        err_msg = f"could {'' if dry_run else 'not '}modify logging settings of blob storage because {remedy_failed_because}"
                        logging.error(err_msg)
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.name,
                                        "Name": "",
                                        "Type": "blob_container",
                                        "Action": "update" if not dry_run else "dryRun",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": storage_account_region,
                                    },
                                    "ActionStatus": "dryrun",
                                    "ErrorMessage": {
                                        "ResultType": "string",
                                        "Result": err_msg,
                                    },
                                }
                            )
                        )
                    else:
                        message = f"could {'' if dry_run else 'not '}modify logging settings of blob storage"
                        logging.info(message)
                        result["ExecutionResultData"]["Result"][storage_result_index][
                            "ExecutionResultData"
                        ]["Result"].append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.name,
                                        "Name": "",
                                        "Type": "blob_container",
                                        "Action": "update",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": storage_account_region,
                                    },
                                    "ActionStatus": "dryrun",
                                    "ExecutionResultData": {
                                        "ResultType": "string",
                                        "Result": message,
                                    },
                                }
                            )
                        )
            if dry_run:
                result["ActionStatus"] = "dryrun"
            elif remedy_failed_because == "":
                result["ActionStatus"] = "Success"
            else:
                result["ActionStatus"] = "Fail"
                result["ErrorMessage"] = remedy_failed_because

        except Exception as ex:
            logging.exception(ex)
            result["ErrorMessage"] = ex.__str__()
            result["ActionStatus"] = "Fail"
        final_result.append(result)
    return final_result
