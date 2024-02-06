import json
import logging
import sys
import os


from azure.identity import DefaultAzureCredential
from azure.mgmt.storage.models import (
    StorageAccountUpdateParameters,
    NetworkRuleSet,
    DefaultAction,
)


from library.Utils.utils import get_client, setup_session, remove_empty_from_list
from library.Utils.rollback import serialize_rollback_actions
from library.Subscriptions import get_subscriptions
from library.ResourceGroups import get_resource_groups
from library.StorageAccount import (
    get_storage_accounts,
    get_storage_account,
    populate_ip_rules,
    populate_vnet_rules,
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
        if "access-level" not in action_params or not [
            "enabled-from-all-networks",
            "enabled-from-selected-virtual-networks-and-ip-addresses",
            "disabled",
        ].__contains__(action_params["access-level"]):
            raise Exception(
                f'access-level is required field. It can have any one of the following values. \n "enabled-from-all-networks", "enabled-from-selected-virtual-networks-and-ip-addresses", "disabled".'
            )
        if "vnets" in action_params:
            for vnet_index, vnet in enumerate(action_params["vnets"]):
                if "name" not in vnet:
                    raise Exception(
                        f"virtual netowrk 'name' is required field in vnets array at index {vnet_index}"
                    )
                if "allow" not in vnet:
                    raise Exception(
                        f"'allow' (true/false) is required field in vnets array at index {vnet_index}"
                    )
            allowed_vnets = list(
                map(
                    lambda vnet: vnet["name"],
                    list(filter(lambda vnet: vnet["allow"], action_params["vnets"])),
                )
            )
            not_allowed_vnets = list(
                map(
                    lambda vnet: vnet["name"],
                    list(
                        filter(lambda vnet: not vnet["allow"], action_params["vnets"])
                    ),
                )
            )
            for allowed_vnet in allowed_vnets:
                for not_allowed_vnet in not_allowed_vnets:
                    if allowed_vnet == not_allowed_vnet:
                        raise Exception(
                            f"Cannot allow and disallow same vnet {not_allowed_vnet}"
                        )

        if "ip" in action_params:
            for ip_index, ip in enumerate(action_params["ip"]):
                if "value" not in ip:
                    raise Exception(
                        f"ip address or CIDR range 'value' is required field in ip array at index {ip_index}"
                    )
                if "allow" not in ip:
                    raise Exception(
                        f"'allow' (true/false) is required field in ip array at index {ip_index}"
                    )
            allowed_ips = list(
                map(
                    lambda ip: ip["value"],
                    list(filter(lambda ip: ip["allow"], action_params["ip"])),
                )
            )
            not_allowed_ips = list(
                map(
                    lambda ip: ip["value"],
                    list(filter(lambda ip: not ip["allow"], action_params["ip"])),
                )
            )
            for allowed_ip in allowed_ips:
                for not_allowed_ip in not_allowed_ips:
                    if allowed_ip == not_allowed_ip:
                        raise Exception(
                            f"Cannot allow and disallow same ip {not_allowed_ip}"
                        )

    return True


def create_subscription_actions(
    credential,
    subscription_ids=["all"],
    resource_group_names=["all"],
    storage_account_names=["all"],
    regions=["all"],
):
    """
    This method prepares list of remedy_action_data with respect to given list of
    subscription_ids. List will have all remedy_action_data of all subscriptions
    if subscription_ids are not provided or are empty

    :param credential: - (Required) Azure credentials

    :param subscription_ids: - (Optional) list of Subscription ids

    :param resource_group_names: - (Optional) list of Resource Group names

    :param storage_account_names: - (Optional) list of Storage Account names

    :param regions: - (Optional) list of Azure supported locations

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
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
                        )
                    )
    return results


def create_resource_group_actions(
    credential,
    subscription_id,
    resource_group_names=["all"],
    storage_account_names=["all"],
    regions=["all"],
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

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
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
                        )
                    )

    return results


def create_storage_account_actions(
    credential,
    subscription_id,
    resource_group_name,
    storage_account_names=["all"],
    regions=["all"],
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

    returns remedy_actions_data, a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name
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
                result.append(
                    dict(
                        {
                            "subscription_id": subscription_id,
                            "resource_group_name": resource_group_name,
                            "storage_account_name": storage_account.name,
                        }
                    )
                )
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
                        result.append(
                            dict(
                                {
                                    "subscription_id": subscription_id,
                                    "resource_group_name": resource_group_name,
                                    "storage_account_name": storage_account.name,
                                }
                            )
                        )
    return result


def remedy(
    credential,
    remedy_actions_data,
    access_level,
    allowed_vnets,
    not_allowed_vnets,
    allowed_ip_address_or_range,
    not_allowed_ip_address_or_range,
    is_dry_run=True,
):
    """
    This method executes the remedy remove_public_access_storage_containers on
    remedy_action_data and sets the anonymous access level of blob storage containers
    to the value provided.

    :param credential: - (Required) Azure Credential.

    :param remedy_actions_data: - (Required) a list of dictionary containing
        subscription_id
        resource_group_name
        storage_account_name

    :param access_level: (Required) - value can be only on of enabled-from-all-networks,
        enabled-from-selected-virtual-networks-and-ip-addresses or disabled.

    :param allowed_vnets: - (Required) list of virtual network names which are allowed
        access to the storage accounts.

    :param not_allowed_vnets: - (Required) list of virtual network names which are not
        allowed access to the storage accounts.

    :param allowed_ip_address_or_range: - (Required) list of ip address or CIDR ranges
        which are allowed access to the storage accounts.

    :param not_allowed_ip_address_or_range: - (Required) list of ip address or CIDR ranges
        which are not allowed access to the storage accounts.

    :param is_dry_run: - (Optional) if False then performs actual operations on Cloud; default
        is True, where script will output the actions that can be performed by the
        script to remedy the problem.

    :return: [dict]
    """
    results = []
    for remedy_action_data in remedy_actions_data:
        client = get_client(
            credential=credential,
            client_type="storage_management",
            client_params=dict(
                {"subscription_id": remedy_action_data["subscription_id"]}
            ),
        )
        storage_account = get_storage_account(
            credential=credential,
            subscription_id=remedy_action_data["subscription_id"],
            resource_group_name=remedy_action_data["resource_group_name"],
            storage_account_name=remedy_action_data["storage_account_name"],
        )
        prev_state = client.storage_accounts.get_properties(
            resource_group_name=remedy_action_data["resource_group_name"],
            account_name=remedy_action_data["storage_account_name"],
        )

        network_rule_set = prev_state.network_rule_set

        ip_rules = None
        vnet_rules = None
        default_action = None
        public_network_access = None
        if access_level == "enabled-from-all-networks":
            public_network_access = "Enabled"
            default_action = DefaultAction.ALLOW
            ip_rules = list([])
            vnet_rules = list([])
        elif access_level == "disabled":
            public_network_access = "Disabled"
            default_action = DefaultAction.DENY
            ip_rules = list([])
            vnet_rules = list([])
        elif access_level == "enabled-from-selected-virtual-networks-and-ip-addresses":
            public_network_access = "Enabled"
            default_action = DefaultAction.DENY
            ip_rules = populate_ip_rules(
                list(network_rule_set.ip_rules),
                allowed_ip_address_or_range,
                not_allowed_ip_address_or_range,
            )
            # vnet rules
            vnet_rules = populate_vnet_rules(
                credential,
                list(network_rule_set.virtual_network_rules),
                allowed_vnets,
                not_allowed_vnets,
                remedy_action_data["subscription_id"],
                remedy_action_data["resource_group_name"],
            )

        if is_dry_run:
            message = "Network access is optimal"
            if access_level == "enabled-from-all-networks":
                message = "Could enable public network access from all networks"
            elif access_level == "disabled":
                message = "Could disable public network access from all networks"
            elif (
                access_level
                == "enabled-from-selected-virtual-networks-and-ip-addresses"
            ):
                could_update_ip_rules = ip_rules.__len__() > 0 and (
                    allowed_ip_address_or_range.__len__() > 0
                    or not_allowed_ip_address_or_range.__len__() > 0
                )
                could_update_vnet_rules = vnet_rules.__len__() > 0 and (
                    allowed_vnets.__len__() > 0 or not_allowed_vnets.__len__() > 0
                )
                if could_update_ip_rules and could_update_vnet_rules:
                    message = f"Could enable public network access from selected networks by updating ip rules and vnet rules"
                elif could_update_ip_rules:
                    message = f"Could enable public network access from selected networks by updating ip rules"
                elif could_update_vnet_rules:
                    message = f"Could enable public network access from selected networks by updating vnet rules"
            results.append(
                dict(
                    {
                        "Asset": {
                            "Id": storage_account.id,
                            "Name": storage_account.name,
                            "Type": "storage_account",
                            "Action": "update",
                            "CloudAccountId": "",
                            "CloudProvider": "azure",
                            "Region": storage_account.location,
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
            public_network_access_parameters = StorageAccountUpdateParameters(
                network_rule_set=NetworkRuleSet(
                    default_action=default_action,
                    virtual_network_rules=vnet_rules,
                    ip_rules=ip_rules,
                ),
                public_network_access=public_network_access,
            )

            result = client.storage_accounts.update(
                resource_group_name=remedy_action_data["resource_group_name"],
                account_name=remedy_action_data["storage_account_name"],
                parameters=public_network_access_parameters,
            )

            results.append(
                dict(
                    {
                        "Asset": {
                            "Id": storage_account.id,
                            "Name": storage_account.name,
                            "Type": "storage_account",
                            "Action": "update",
                            "CloudAccountId": "",
                            "CloudProvider": "azure",
                            "Region": storage_account.location,
                        },
                        "ActionStatus": "Success",
                        "ExecutionResultData": {
                            "ResultType": "object",
                            "Result": {
                                "current_state": {
                                    "network_security_rules": result.as_dict()[
                                        "network_rule_set"
                                    ],
                                    "public_network_access": result.as_dict()[
                                        "public_network_access"
                                    ],
                                },
                                "prev_state": {
                                    "network_security_rules": prev_state.network_rule_set.as_dict(),
                                    "public_network_access": prev_state.public_network_access,
                                },
                            },
                        },
                    }
                )
            )
        client.close()
    return results


def restrict_network_access(
    credential,
    action_params,
    subscription_ids=["all"],
    resource_group_names=["all"],
    storage_account_names=["all"],
    regions=["all"],
    exclude_storage_account_names=[],
    dry_run=True,
):
    """
    This method restricts the network access to the storage accounts.

    :param credential: - (Required) Azure Credential.

    :param action_params: - (Required) dictionary value necessary to perform this script.
        for restrict netowrk access -
            access_level - (Required) - value can be only on of enabled-from-all-networks,
            enabled-from-selected-virtual-networks-and-ip-addresses and disabled.
                1. enabled-from-all-networks - any network can access containers of storage accounts. Does not need
                    any additional action params

                    example:

                        --actionParams '{"access-level": "enabled-from-all-networks"}'


                2. enabled-from-selected-virtual-networks-and-ip-addresses  -   Some selected networks can access
                    containers of storage accounts.
                        For this access_level, you need following additional access params

                    1. vnets - (Optional) - list of dictionary of virtual network name and boolean value allow.
                        Example, [{"name": "virtual-network-1", "allow": true}, {"name": "virtual-network-2", "allow": false}]
                    2. ip - (Optional) - list of dictionary of ip address or CIDR range value and boolean value allow.
                        Example, [{"value":"117.0.0.0/24","allow":true}, {"value":"117.100.0.0/24","allow":false}]

                        example:

                            --actionParams '{"access-level": "enabled-from-selected-virtual-networks-and-ip-addresses", "vnets":[{"name":"vnet1","allow":true},{"name":"vnet2","allow":false}],"ip":[{"value":"117.0.0.0/24","allow":true}]}'


                3. disabled - no network can access containers of storage accounts. Does not need
                    any additional action params

                    example:

                        --actionParams '{"access-level": "disabled"}'

        for rollback -
            1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the
            existing of state file)
            2. lastExecutionResultPath (Required) - The path for the last execution that we want to
            roll-back from

    :param subscription_ids: - (Optional) - list of Subscription ids. If not given, remedy will configure all
    the Subscriptions available in the Tenant

    :param resource_group_names: - (Optional) - list of Resource Group names. When given, remedy will configure
    only specified Resource Groups, otherwise all Resource Groups available in the Subscription.

    :param storage_account_names: - (Optional) - list of Storage Account names. If not given, remedy will configure
    all the Storage Accounts available in the Resource Group.

    :param regions: - (Optional) - list of Azure supported regions. If given, remedy will configure
    the Storage Accounts if its location is any of the given regions.

    :param exclude_storage_account_names: - (Optional) - list of Storage Account names. When given, remedy will configure
    all the Storage Accounts except those provided with this option.

    :param dry_run: - (Optional) if False then performs actual operations on Cloud; default
    is True, where script will output the actions that can be performed by the
    script to remedy the problem.

    :return: [dict]
    """
    remedy_actions_data = create_subscription_actions(
        credential,
        subscription_ids=subscription_ids,
        resource_group_names=resource_group_names,
        storage_account_names=storage_account_names,
        regions=regions,
    )

    pop_indices = []
    for exclude_storage_account_name in exclude_storage_account_names:
        for index, remedy_action_data in enumerate(remedy_actions_data):
            if (
                remedy_actions_data["storage_account_name"]
                == exclude_storage_account_name
            ):
                pop_indices.append(index)
    pop_indices.sort()
    pop_indices.reverse()
    for index in pop_indices:
        remedy_actions_data.pop(index)

    remedy_actions_data = remove_empty_from_list(remedy_actions_data)

    result = []
    if remedy_actions_data.__len__() > 0:
        if "ip" not in action_params:
            action_params["ip"] = []
        if "vnets" not in action_params:
            action_params["vnets"] = []

        result = remedy(
            credential,
            remedy_actions_data,
            access_level=action_params["access-level"],
            allowed_vnets=list(
                map(
                    lambda vnet: vnet["name"],
                    list(filter(lambda vnet: vnet["allow"], action_params["vnets"])),
                )
            ),
            not_allowed_vnets=list(
                map(
                    lambda vnet: vnet["name"],
                    list(
                        filter(lambda vnet: not vnet["allow"], action_params["vnets"])
                    ),
                )
            ),
            allowed_ip_address_or_range=list(
                map(
                    lambda ip: ip["value"],
                    list(filter(lambda ip: ip["allow"], action_params["ip"])),
                )
            ),
            not_allowed_ip_address_or_range=list(
                map(
                    lambda ip: ip["value"],
                    list(filter(lambda ip: not ip["allow"], action_params["ip"])),
                )
            ),
            is_dry_run=dry_run,
        )
    else:
        message = f"{'Dry run - ' if dry_run else ''}storage account(s) not found"
        logging.info(message)
        if dry_run:
            result.append(
                dict(
                    {
                        "Asset": {
                            "Id": "",
                            "Name": "",
                            "Type": "storage_account",
                            "CloudAccountId": "",
                            "Action": "update",
                            "CloudProvider": "azure",
                            "Region": "",
                        },
                        "ActionStatus": "dryrun",
                        "ErrorMessage": message,
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
                            "Action": "update",
                            "CloudProvider": "azure",
                            "Region": "",
                        },
                        "ActionStatus": "Fail",
                        "ErrorMessage": message,
                    }
                )
            )

    return result


def rollback_restrict_network_access(
    credential,
    last_execution_result_path,
    dry_run=True,
):
    """
    This method resets the modifications done by restrict_network_access() method.

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
            prev_state_json["executionType"] == "storage-account"
            and prev_state_json["executionAction"] == "remove_public_network_access"
        ):
            rollback_actions = serialize_rollback_actions(
                prev_state_json["executionResult"]
            )
            for action in rollback_actions:
                if action["Asset"]["Type"] == "storage_account":
                    if action["ActionStatus"].lower() == "success":
                        if action["Asset"]["Action"] == "update":
                            if dry_run or action["ActionStatus"] == "dryrun":
                                message = f"Dry run - Could update Virtual Network or IP or IP CIDR range access rules of {action['Asset']['Name']}"
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
                                client = get_client(
                                    credential=credential,
                                    client_type="storage_management",
                                    client_params=dict(
                                        {"subscription_id": subscription_id}
                                    ),
                                )
                                storage_account = get_storage_account(
                                    credential=credential,
                                    subscription_id=subscription_id,
                                    resource_group_name=resource_group_name,
                                    storage_account_name=storage_account_name,
                                )
                                public_network_access_parameters = (
                                    StorageAccountUpdateParameters(
                                        network_rule_set=NetworkRuleSet(
                                            bypass=action["ExecutionResultData"][
                                                "Result"
                                            ]["prev_state"]["network_security_rules"][
                                                "bypass"
                                            ],
                                            default_action=action[
                                                "ExecutionResultData"
                                            ]["Result"]["prev_state"][
                                                "network_security_rules"
                                            ][
                                                "default_action"
                                            ],
                                            virtual_network_rules=action[
                                                "ExecutionResultData"
                                            ]["Result"]["prev_state"][
                                                "network_security_rules"
                                            ][
                                                "virtual_network_rules"
                                            ],
                                            ip_rules=action["ExecutionResultData"][
                                                "Result"
                                            ]["prev_state"]["network_security_rules"][
                                                "ip_rules"
                                            ],
                                        ),
                                        public_network_access=action[
                                            "ExecutionResultData"
                                        ]["Result"]["prev_state"][
                                            "public_network_access"
                                        ],
                                    )
                                )

                                result = client.storage_accounts.update(
                                    resource_group_name=resource_group_name,
                                    account_name=storage_account_name,
                                    parameters=public_network_access_parameters,
                                )

                                message = f"Changed network access rules of storage account {storage_account_name}"
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
            logging.error(
                f'{prev_state_json["executionType"]}:{prev_state_json["executionAction"]}'
            )
            raise Exception(
                "File does not contain result of remove_public_network_access"
            )

    return new_actions
