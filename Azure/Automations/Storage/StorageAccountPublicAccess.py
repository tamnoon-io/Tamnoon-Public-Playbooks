import json
import logging
import sys
import os


from azure.core.exceptions import HttpResponseError


from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import get_client, setup_session, remove_empty_from_list
from library.Subscriptions import get_subscriptions
from library.ResourceGroups import get_resource_groups
from library.StorageAccount import get_storage_accounts
from library.BlobStorage import get_access_key


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
        if "anonymous-access-level" not in action_params or (
            action_params["anonymous-access-level"] != "container"
            and action_params["anonymous-access-level"] != "blob"
            and action_params["anonymous-access-level"] != "none"
        ):
            raise Exception(
                "'anonymous-access-level' is required for this remedy. Values are 'container' or 'blob'"
            )

    return True


def is_keep_blob_storage_container_remedy_action(
    remedy_action_data, excluded_storage_containers
):
    """
    This method returns True if storage_account_name.blob_container_name is not found
    in excluded_storage_containers.
    Otherwise returns False.

    :param remedy_action_data: - (Required) dictionary containing storage_account_name
        and blob_container_name.
    :param excluded_storage_containers: - (Required) list of "storage_account_name.blob_container_name"
        that are to be excluded.

    :return: bool
    """
    if excluded_storage_containers.__len__() > 0:
        for excluded_storage_container in excluded_storage_containers:
            if (
                excluded_storage_container
                == f"{remedy_action_data['storage_account_name']}.{remedy_action_data['blob_container_name']}"
            ):
                return False
    return True


def create_subscription_actions(
    credential,
    subscription_ids=["all"],
    resource_group_names=["all"],
    storage_account_names=["all"],
    regions=["all"],
    blob_container_names=["all"],
):
    """
    This method prepares list of remedy_action_data with respect to given list of
    subscription_ids. List will have all remedy_action_data of all subscriptions
    if subscription_ids are not provided or are empty

    :param credential: - (Required) Azure credentials

    :param subscription_ids: - (Optional) list of Subscription ids

    :param resource_group_names: - (Optional) list of Resource Group names

    :param regions: - (Optional) list of Azure supported locations

    :param storage_account_names: - (Optional) list of Storage Account names

    :param blob_container_names: - (Optional) list of Blob Storage Container names

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
        blob_container_name
        region
    :return: [dict]
    """
    # assert storage_account_names.__len__() > 0, logging.info("storage accounts not found")
    # assert subscription_ids.__len__() > 0, logging.info("subscription ids not found")
    subscriptions = get_subscriptions(credential)
    results = []
    if subscription_ids.__len__() == 1 and subscription_ids[0] == "all":
        for subscription in subscriptions:
            logging.debug(f"{subscription.subscription_id}")
            results.extend(
                create_resource_group_actions(
                    credential,
                    subscription.subscription_id,
                    resource_group_names,
                    storage_account_names,
                    regions,
                    blob_container_names,
                )
            )
    else:
        for subscription_id in subscription_ids:
            for subscription in subscriptions:
                if subscription.subscription_id == subscription_id:
                    logging.debug(f"{subscription.subscription_id}   {subscription_id}")
                    results.extend(
                        create_resource_group_actions(
                            credential,
                            subscription_id,
                            resource_group_names,
                            storage_account_names,
                            regions,
                            blob_container_names,
                        )
                    )

    return results


def create_resource_group_actions(
    credential,
    subscription_id,
    resource_group_names=["all"],
    storage_account_names=["all"],
    regions=["all"],
    blob_container_names=["all"],
):
    """
    This method prepares list of remedy_action_data with respect to given list of
    resource_group_names. List will have all remedy_action_data of all Resource
    Groups in subscription_id if resource_group_names are not provided or are empty.

    :param credential: - (Required) Azure credentials

    :param subscription_id: - (Required) Subscription id

    :param resource_group_names: - (Optional) list of Resource Group names

    :param storage_account_names: - (Optional) list of Storage Account names

    :param regions: - (Optional) list of Azure supported locations

    :param blob_container_names: - (Optional) list of Blob Storage Container names

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
        blob_container_name
        region
    :return: [dict]
    """
    resource_groups = get_resource_groups(credential, subscription_id)
    # assert resource_groups.__len__() > 0, logging.info("resource groups not found")
    # assert storage_account_names.__len__() > 0, logging.info("storage accounts not found")

    results = []
    if resource_group_names.__len__() == 1 and resource_group_names[0] == "all":
        for resource_group in resource_groups:
            logging.debug(f"{resource_group.name}")
            results.extend(
                create_storage_account_actions(
                    credential,
                    subscription_id,
                    resource_group.name,
                    storage_account_names,
                    regions,
                    blob_container_names,
                )
            )
    else:
        for resource_group_name in resource_group_names:
            for resource_group in resource_groups:
                if resource_group.name == resource_group_name:
                    logging.debug(f"{resource_group.name}   {resource_group_name}")
                    results.extend(
                        create_storage_account_actions(
                            credential,
                            subscription_id,
                            resource_group_name,
                            storage_account_names,
                            regions,
                            blob_container_names,
                        )
                    )
    return results


def create_storage_account_actions(
    credential,
    subscription_id,
    resource_group_name,
    storage_account_names=["all"],
    regions=["all"],
    blob_containers=["all"],
):
    """
    This method prepares list of remedy_action_data with respect to given list of
    storage_account_names. List will have all remedy_action_data of all Storage
    Accounts in given subscription_id and resource_group_name if storage_account_names
    are not provided or are empty.

    :param credential: - (Required) Azure credentials

    :param subscription_id: - (Required) Subscription id

    :param resource_group_name: - (Required) Resource Group name

    :param storage_account_names: - (Optional) list of Storage Account names

    :param regions: - (Optional) list of Azure supported locations

    :param blob_container_names: - (Optional) list of Blob Storage Container names

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
        blob_container_name
        region
    :return: [dict]
    """

    result = []
    storage_accounts = get_storage_accounts(
        credential, subscription_id, resource_group_name
    )
    is_all_regions = regions.__len__() == 1 and regions[0] == "all"

    if storage_account_names.__len__() == 1 and storage_account_names[0] == "all":
        for storage_account in storage_accounts:
            if is_all_regions or regions.__contains__(storage_account.location):
                actions = create_blob_container_actions(
                    credential,
                    subscription_id,
                    resource_group_name,
                    storage_account.name,
                    storage_account.location,
                    blob_containers,
                )
                result.extend(actions)
    else:
        for storage_account_name in storage_account_names:
            for storage_account in storage_accounts:
                if (
                    is_all_regions or regions.__contains__(storage_account.location)
                ) and storage_account.name == storage_account_name:
                    logging.debug(
                        f"{storage_account.name}   {storage_account_name}         {resource_group_name}"
                    )
                    if storage_account.name == storage_account_name:
                        result.extend(
                            create_blob_container_actions(
                                credential,
                                subscription_id,
                                resource_group_name,
                                storage_account_name,
                                storage_account.location,
                                blob_containers,
                            )
                        )
    return result


def create_blob_container_actions(
    credential,
    subscription_id,
    resource_group_name,
    storage_account_name,
    region,
    blob_container_names=["all"],
):
    """
    This method prepares list of remedy_action_data with respect to given list of
    blob_container_names. List will have all remedy_action_data of all Blob Containers
    in given subscription_id and resource_group_name  and storage_account_name if
    blob_container_names are not provided or are empty.

    :param credential: - (Required) Azure credentials

    :param subscription_id: - (Required) Subscription id

    :param resource_group_name: - (Required) Resource Group name

    :param storage_account_name: - (Required) Storage Account name

    :param region: - (Optional) Storage Account location

    :param blob_container_names: - (Optional) list of Blob Storage Container names

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
        blob_container_name
        region

    :return: [dict]
    """

    result = []
    try:
        blob_client = get_client(
            credential,
            "blob_service",
            dict({"StorageAccountName": storage_account_name}),
        )
        containers = list(blob_client.list_containers(name_starts_with=""))
        if containers == None:
            blob_client.close()
            return result

        if blob_container_names.__len__() == 1 and blob_container_names[0] == "all":
            for container in containers:
                result.append(
                    dict(
                        {
                            "subscription_id": subscription_id,
                            "resource_group_name": resource_group_name,
                            "storage_account_name": storage_account_name,
                            "blob_container_name": container.name,
                            "region": region,
                        }
                    )
                )
        else:
            for container in containers:
                name_found = False
                for blob_container_name in blob_container_names:
                    name_found = blob_container_name == container.name
                    if name_found:
                        break
                if name_found:
                    result.append(
                        dict(
                            {
                                "subscription_id": subscription_id,
                                "resource_group_name": resource_group_name,
                                "storage_account_name": storage_account_name,
                                "blob_container_name": container.name,
                                "region": region,
                            }
                        )
                    )
        blob_client.close()
    except HttpResponseError as err:
        logging.error(
            f"Following error occurred in {subscription_id}/{resource_group_name}/{storage_account_name}. Which implies user does not have permission to list blob containers. Please check storage account's Access Control (IAM) or check that your ip address is allowed access to the storage account Networking -> Firewalls and virtual networks."
        )
        logging.error(err)
    except Exception as ex:
        logging.error(
            f"Following error occurred. Which implies error in getting blob container name in {subscription_id}/{resource_group_name}/{storage_account_name}. Please check storage account's Access Control (IAM) or check that your ip address is allowed access to the storage account Networking -> Firewalls and virtual networks."
        )
        logging.error(ex)
    return result


def remedy(credential, remedy_actions_data, access_level, is_dry_run=True):
    """
    This method executes the remedy remove_public_access_storage_containers on
    remedy_action_data and sets the anonymous access level of blob storage containers.
    to the value provided.

    :param credential: - (Required) Azure Credential.

    :param remedy_actions_data: - (Required) a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
        blob_container_name
        region

    :param access_level: - (Required) possible values are "container", "blob", "none". Here,
        "none" access_level means that anonymous access level is to be denied and
        access is to be kept Private.

    :param is_dry_run: - (Optional) if False then performs actual operations on Cloud; default
        is True, where script will output the actions that can be performed by the
        script to remedy the problem.

    :return: [dict]
    """

    if access_level == "none":
        access_level = None

    NO_PUBLIC_ACCESS = None
    result = []

    for remedy_action_data in remedy_actions_data:
        client = get_client(
            credential,
            "storage_management",
            dict({"subscription_id": remedy_action_data["subscription_id"]}),
        )
        storage_accounts = client.storage_accounts.list_by_resource_group(
            resource_group_name=remedy_action_data["resource_group_name"],
        )

        for storage_account in storage_accounts:
            if storage_account.name != remedy_action_data["storage_account_name"]:
                continue

            if storage_account.allow_blob_public_access:
                try:
                    access_key = get_access_key(
                        credential,
                        remedy_action_data["subscription_id"],
                        remedy_action_data["resource_group_name"],
                        remedy_action_data["storage_account_name"],
                    )
                    blob_service_client = get_client(
                        setup_session(
                            "shared-key",
                            dict(
                                {
                                    "StorageAccountName": remedy_action_data[
                                        "storage_account_name"
                                    ],
                                    "accessKey": access_key,
                                }
                            ),
                        ),
                        "blob_service",
                        dict(
                            {
                                "StorageAccountName": remedy_action_data[
                                    "storage_account_name"
                                ]
                            }
                        ),
                    )
                    # initializing blob container client
                    blob_container = blob_service_client.get_container_client(
                        container=remedy_action_data["blob_container_name"]
                    )

                    if (
                        blob_container.get_container_properties()["public_access"]
                        == NO_PUBLIC_ACCESS
                    ):
                        message = f"{blob_container.container_name} blob container has disallowed anonymous access. No further actions are needed"
                        logging.info(message)
                        result.append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.id,
                                        "Name": blob_container.container_name,
                                        "Type": "blob_container",
                                        "Action": "no-action",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": remedy_action_data["region"],
                                    },
                                    "ActionStatus": "Success"
                                    if not is_dry_run
                                    else "dryrun",
                                    "ExecutionResultData": {
                                        "ResultType": "string",
                                        "Result": message,
                                    },
                                }
                            )
                        )
                    else:
                        container_str = f"{blob_container.account_name}:{blob_container.container_name}"

                        policy = blob_container.get_container_access_policy()

                        concurrent_signed_identifier = dict()
                        for identifier in policy["signed_identifiers"]:
                            concurrent_signed_identifier[
                                identifier.id
                            ] = identifier.access_policy.permission

                        if policy["public_access"] != access_level:
                            if not is_dry_run:
                                blob_container.set_container_access_policy(
                                    public_access=access_level,
                                    signed_identifiers=concurrent_signed_identifier,
                                )
                                message = f"Changed access level of blob container {container_str} to {access_level}"
                                logging.info(message)

                                result.append(
                                    dict(
                                        {
                                            "Asset": {
                                                "Id": storage_account.id,
                                                "Name": blob_container.container_name,
                                                "Type": "blob_container",
                                                "Action": "update",
                                                "CloudAccountId": "",
                                                "CloudProvider": "azure",
                                                "Region": remedy_action_data["region"],
                                            },
                                            "ActionStatus": "Success",
                                            "ExecutionResultData": {
                                                "ResultType": "object",
                                                "Result": {
                                                    "prev_state": {
                                                        "policy": policy,
                                                    },
                                                    "current_state": {
                                                        "policy": {
                                                            "public_access": access_level,
                                                            "signed_identifiers": concurrent_signed_identifier,
                                                        }
                                                    },
                                                },
                                            },
                                        }
                                    )
                                )
                                # result[asset]['prev_state'] = {"pubic_access":policy['public_access'], 'signed_identifiers':concurrent_signed_identifier}
                            else:
                                message = f"Dry run - could change access level of blob container {container_str} to {access_level}"
                                logging.info(message)
                                result.append(
                                    dict(
                                        {
                                            "Asset": {
                                                "Id": storage_account.id,
                                                "Name": blob_container.container_name,
                                                "Type": "blob_container",
                                                "Action": "no-action",
                                                "CloudAccountId": "",
                                                "CloudProvider": "azure",
                                                "Region": remedy_action_data["region"],
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
                            message = (
                                f"access level is safe ({policy['public_access']})"
                            )
                            logging.info(message)
                            result.append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": storage_account.id,
                                            "Name": blob_container.container_name,
                                            "Type": "blob_container",
                                            "Action": "no-action",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": remedy_action_data["region"],
                                        },
                                        "ActionStatus": "Success"
                                        if not is_dry_run
                                        else "dryrun",
                                        "ExecutionResultData": {
                                            "ResultType": "object"
                                            if not is_dry_run
                                            else "string",
                                            "Result": {
                                                "prev_state": {
                                                    "policy": policy,
                                                },
                                                "current_state": {
                                                    "policy": policy,
                                                },
                                            }
                                            if not is_dry_run
                                            else f"Dry run - {message}",
                                        },
                                    }
                                )
                            )
                except HttpResponseError as err:
                    if (
                        err.reason
                        == "This request is not authorized to perform this operation using this permission."
                    ):
                        err_msg = f"the user must have an Azure role assigned that includes the Azure RBAC action [Microsoft.Storage/storageAccounts/listkeys/action](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal)"
                        logging.error(
                            f"Following error occurred in {remedy_action_data['subscription_id']}/{remedy_action_data['resource_group_name']}/{remedy_action_data['storage_account_name']}/{remedy_action_data['blob_container_name']}. Which implies {err_msg}"
                        )
                        logging.error(err, exc_info=True)
                        result.append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.id,
                                        "Name": remedy_action_data[
                                            "blob_container_name"
                                        ],
                                        "Type": "blob_container",
                                        "Action": "no-action",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": remedy_action_data["region"],
                                    },
                                    "ActionStatus": "Fail",
                                    "ErrorMessage": err_msg,
                                }
                            )
                        )
                    else:
                        err_msg = f"User does not have permission to access blob container or modify blob container's access level. To resolve this, please check your login credentials OR check storage account's Access Control (IAM) OR check that your ip address is allowed access to the storage account Networking -> Firewalls and virtual networks."
                        logging.error(
                            f"Following error occurred in {remedy_action_data['subscription_id']}/{remedy_action_data['resource_group_name']}/{remedy_action_data['storage_account_name']}/{remedy_action_data['blob_container_name']}. Which implies {err_msg}"
                        )
                        logging.error(err, exc_info=True)
                        result.append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": storage_account.id,
                                        "Name": remedy_action_data[
                                            "blob_container_name"
                                        ],
                                        "Type": "blob_container",
                                        "Action": "no-action",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": remedy_action_data["region"],
                                    },
                                    "ActionStatus": "Fail",
                                    "ErrorMessage": err_msg,
                                }
                            )
                        )
                except Exception as ex:
                    err_msg = f"Error updating blob container's access level. To resolve this, please check your login credentials OR check storage account's Access Control (IAM) OR check that your ip address is allowed access to the storage account Networking -> Firewalls and virtual networks."
                    logging.error(
                        f"Following error occurred in {remedy_action_data['subscription_id']}/{remedy_action_data['resource_group_name']}/{remedy_action_data['storage_account_name']}/{remedy_action_data['blob_container_name']}. Which implies {err_msg}"
                    )
                    logging.error(ex, exc_info=True)
                    result.append(
                        dict(
                            {
                                "Asset": {
                                    "Id": storage_account.id,
                                    "Name": remedy_action_data["blob_container_name"],
                                    "Type": "blob_container",
                                    "Action": "no-action",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": remedy_action_data["region"],
                                },
                                "ActionStatus": "Fail",
                                "ErrorMessage": err_msg,
                            }
                        )
                    )
            else:
                message = f"{storage_account.name} storage account has disallowed anonymous access. No further actions are needed"
                logging.info(message)
                result.append(
                    dict(
                        {
                            "Asset": {
                                "Id": storage_account.id,
                                "Name": storage_account.name,
                                "Type": "storage_account",
                                "Action": "no-action",
                                "CloudAccountId": "",
                                "CloudProvider": "azure",
                                "Region": remedy_action_data["region"],
                            },
                            "ActionStatus": "dryrun" if is_dry_run else "Success",
                            "ExecutionResultData": {
                                "ResultType": "string",
                                "Result": message,
                            },
                        }
                    )
                )
    return result


def rollback_public_access(
    credential,
    last_execution_result_path,
    dry_run=True,
):
    """
    This method resets the modifications done by remove_public_access() method.

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
            == "remove_public_access_storage_containers"
        ):
            rollback_actions = serialize_rollback_actions(
                prev_state_json["executionResult"]
            )
            for action in rollback_actions:
                if action["Asset"]["Type"] == "blob_container":
                    if action["ActionStatus"].lower() == "success":
                        if action["Asset"]["Action"] == "update":
                            if dry_run or action["ActionStatus"] == "dryrun":
                                message = f"Dry run - Could reset access level of {action['Asset']['Name']}"
                                logging.info(message)
                                action["ActionStatus"] = "dryrun"
                                action["ExecutionResultData"] = dict(
                                    {"ResultType": "string", "Result": message}
                                )
                            else:
                                subscription_id = action["Asset"]["Id"].split("/")[2]
                                resource_group_name = action["Asset"]["Id"].split("/")[
                                    4
                                ]
                                storage_account_name = action["Asset"]["Id"].split("/")[
                                    8
                                ]
                                blob_container_name = action["Asset"]["Name"]
                                access_key = get_access_key(
                                    credential,
                                    subscription_id,
                                    resource_group_name,
                                    storage_account_name,
                                )
                                blob_service_client = get_client(
                                    setup_session(
                                        "shared-key",
                                        dict(
                                            {
                                                "StorageAccountName": storage_account_name,
                                                "accessKey": access_key,
                                            }
                                        ),
                                    ),
                                    "blob_service",
                                    dict({"StorageAccountName": storage_account_name}),
                                )
                                # initializing blob container client
                                blob_container = (
                                    blob_service_client.get_container_client(
                                        container=blob_container_name
                                    )
                                )
                                access_level = action["ExecutionResultData"]["Result"][
                                    "prev_state"
                                ]["policy"]["public_access"]
                                signed_identifiers = dict(
                                    action["ExecutionResultData"]["Result"][
                                        "prev_state"
                                    ]["policy"]["signed_identifiers"]
                                )
                                blob_container.set_container_access_policy(
                                    public_access=access_level,
                                    signed_identifiers=signed_identifiers,
                                )
                                container_str = f"{blob_container.account_name}:{blob_container.container_name}"
                                message = f"Changed access level of blob container {container_str} to {access_level}"
                                logging.info(message)
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
            print(
                f'{prev_state_json["executionType"]}:{prev_state_json["executionAction"]}'
            )
            raise Exception(
                "File does not contain result of enable_log_analytics_logs_for_azure_storage_blobs"
            )

    return new_actions


def remove_public_access(
    credential,
    action_params,
    subscriptions=["all"],
    resource_groups=["all"],
    storage_accounts=["all"],
    blob_containers=["all"],
    regions=["all"],
    is_dry_run=True,
):
    """
    This method restricts anonymous access level of Blob Storage Containers.

    :param credential: - (Required) Azure Credential.

    :param action_params: - (Required) dictionary value necessary to perform this script.

    :param subscriptions: - (Optional) - list of subscription ids, if not given, remedy will search
        blob containers in all subscriptions.

    :param resource_groups: - (Optional) - list of resouce group names, if not given, remedy will
        search blob containers in all resource groups in listed subscriptions.

    :param storage_accounts: - (Optional) - list of storage account names, if not given, remedy will
        search blob containers in all storage accounts in listed resource groups

    :param regions: - (Optional) - list of Azure supported locations, default is ['all']

    :param blob_containers: - (Optional) - list of blob container names, if not given, remedy will
        configure all blob containers.

    :param action_params:
        for removing anonymous public access -
            1. anonymous-access-level - (Required) - access level of blob containers will be set to this value.
                User can provide either "container" or "blob" or "none", where "none" access level means Private.
            2. exclude-storage-containers - (Optional) - list of Blob Container names in Storage Accounts. When
                given, remedy will configure all the Blob Containers available in the Storage Account except
                those provided with this option.
                Please note that to exclude a Blob Container, it should be mentioned with its
                storage account name, separated by dot.
                Example, "storage_account_1.blob_container_1"

        for rollback -
            1. rollBack - (Optional) - Boolean flag to sign if this is a rollback call (required the
                existing of state file)
            2. lastExecutionResultPath (Optional) - The path for the last execution that we want to
                roll-back from - if roll-back provided this parameter become mandatory

    :param is_dry_run: - (Optional) if False then performs actual operations on Cloud; default
        is True, where script will output the actions that can be performed by the
        script to remedy the problem.

    :return: [dict]
    """
    result = []
    # tenant, subscriptions, resource_groups, storage_accounts, blob_containers

    remedy_actions_data = create_subscription_actions(
        credential,
        subscriptions,
        resource_groups,
        storage_accounts,
        regions,
        blob_containers,
    )

    if "exclude-storage-containers" in action_params:
        remedy_actions_data = filter(
            lambda remedy_action_data: is_keep_blob_storage_container_remedy_action(
                remedy_action_data, action_params["exclude-storage-containers"]
            ),
            remedy_actions_data,
        )

    remedy_actions_data = remove_empty_from_list(remedy_actions_data)
    if remedy_actions_data.__len__() > 0:
        result = remedy(
            credential,
            remedy_actions_data,
            action_params["anonymous-access-level"],
            is_dry_run,
        )
    else:
        message = f"{'Dry run - ' if is_dry_run else ''}storage account(s) not found"
        logging.info(message)
        if is_dry_run:
            result.append(
                dict(
                    {
                        "Asset": {
                            "Id": "",
                            "Name": "",
                            "Type": "storage_account",
                            "CloudAccountId": "",
                            "Action": "no-action",
                            "CloudProvider": "azure",
                            "Region": "",
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
            result.append(
                dict(
                    {
                        "Asset": {
                            "Id": "",
                            "Name": "",
                            "Type": "storage_account",
                            "CloudAccountId": "",
                            "Action": "no-action",
                            "CloudProvider": "azure",
                            "Region": "",
                        },
                        "ActionStatus": "Fail",
                        "ErrorMessage": message,
                    }
                )
            )

    return result
