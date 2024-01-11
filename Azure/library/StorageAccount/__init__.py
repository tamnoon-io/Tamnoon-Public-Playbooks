from azure.mgmt.storage.models import StorageAccount
from azure.mgmt.monitor.models import DiagnosticSettingsResource
from ..Utils.utils import get_client
import logging


def get_diagnostic_setting_properties() -> dict:
    """
    This method returns default diagnostic setting properties of enabled diagnostic setting.

    :return: dict
    """
    return {
        "logs": [
            {
                "category": None,
                "categoryGroup": "audit",
                "enabled": False,
                "retentionPolicy": {"days": 0, "enabled": False},
            },
            {
                "category": None,
                "categoryGroup": "allLogs",
                "enabled": True,
                "retentionPolicy": {"days": 0, "enabled": False},
            },
        ],
        "metrics": [
            {
                "enabled": False,
                "retentionPolicy": {"days": 0, "enabled": False},
                "category": "Transaction",
            }
        ],
        # "workspaceId": "/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>/providers/Microsoft.OperationalInsights/workspaces/<storage-account-name>-logs-analytics",
        "logAnalyticsDestinationType": None,
    }


def get_diagnostic_setting() -> dict:
    """
    This method returns default diagnostics setting of enabled diagnostic setting.

    :return: dict
    """
    return {
        # "id": "/subscriptions/<subscription-id>>/resourceGroups/<resource-group-name>/providers/Microsoft.Storage/storageAccounts/<storage-account-name>/blobServices/default/providers/microsoft.insights/diagnosticSettings/<storage-account-name>-diagnostics",
        # "name": "<storage-account-name>-diagnostics",
        "properties": get_diagnostic_setting_properties()
    }


def get_storage_account(
    credential, subscription_id, resource_group_name, storage_account_name
) -> StorageAccount:
    """
    This method returns Storage Account with given Subscription id, Resource Group name and Storage Account name.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription.

    resource_group_name - (Required) name of Resource Group.

    storage_account_name - (Required) name of Storage Account.

    :return: azure.mgmt.storage.models.StorageAccount
    """
    try:
        client = get_client(
            credential, "storage_management", dict({"subscription_id": subscription_id})
        )
        storage_accounts = client.storage_accounts.list_by_resource_group(
            resource_group_name=resource_group_name
        )
        found = None
        for storage_account in storage_accounts:
            if storage_account.name == storage_account_name:
                found = storage_account
                break
        client.close()
        return found
    except Exception as ex:
        logging.exception(ex)
        return None


def get_storage_accounts(
    credential, subscription_id, resource_group_name
) -> StorageAccount:
    """
    This method returns Storage Account with given Subscription id, Resource Group name and Storage Account name.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription.

    resource_group_name - (Required) name of Resource Group.

    :return: [azure.mgmt.storage.models.StorageAccount]
    """
    try:
        client = get_client(
            credential, "storage_management", dict({"subscription_id": subscription_id})
        )
        storage_accounts = client.storage_accounts.list_by_resource_group(
            resource_group_name=resource_group_name
        )
        client.close()
        return storage_accounts
    except Exception as ex:
        logging.exception(ex)
        return None


def get_diagnostic_setting(
    credential,
    subscription_id,
    resource_uri,
    diagnostics_setting_name,
    resolve_noregisteredproviderfound_error=True,
) -> DiagnosticSettingsResource:
    """
    This method finds Diagnostic Setting of Storage Account.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription.

    resource_uri - (Required) Resource uri of Storage Account blob services.

    diagnostics_setting_name - (Required) name of Diagnostic Setting.

    :return: azure.mgmt.storage.models.DiagnosticSettingsResource
    """
    from azure.core.exceptions import HttpResponseError

    monitor_management_client = None
    try:
        # find existing diagnostic
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
        existing_diagnostics = monitor_management_client.diagnostic_settings.get(
            resource_uri=resource_uri, name=diagnostics_setting_name
        )
        # compare existing with ideal policy
        monitor_management_client.close()
        return existing_diagnostics
    except HttpResponseError as err:
        logging.error(f"HttpResponseError\n\t{err}")
        if (
            err.error.code == "NoRegisteredProviderFound"
            and resolve_noregisteredproviderfound_error
        ):
            from ..ResourceProvider import register_resource_provider

            STORAGE_PROVIDER_NAMESPACE = "Microsoft.Storage"
            if register_resource_provider(
                credential,
                subscription_id=subscription_id,
                resource_provider_namespace=STORAGE_PROVIDER_NAMESPACE,
            ):
                return get_diagnostic_setting(
                    credential,
                    subscription_id=subscription_id,
                    resource_uri=resource_uri,
                    diagnostics_setting_name=diagnostics_setting_name,
                    resolve_noregisteredproviderfound_error=False,
                )
    except Exception as ex:
        logging.exception(ex)
    return None


def create_diagnostic_setting(
    credential,
    subscription_id,
    workspace_id,
    resource_uri,
    diagnostics_setting_name,
    storage_acccout_id,
    resolve_noregisteredproviderfound_error=True,
) -> [DiagnosticSettingsResource, Exception]:
    """
    This method creates Diagnostic Setting of Storage Account.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription.

    workspace_id - (Required) id of Log Analytics Workspace.

    resource_uri - (Required)  Resource uri of Storage Account blob services.

    diagnostics_setting_name - (Required) name of Diagnostic Setting.

    storage_acccout_id - (Required) Resource uri of Storage Account

    resolve_noregisteredproviderfound_error - (Optional) specify whether to register if a
        resource provider is found to be not registered

    :return: [azure.mgmt.storage.models.DiagnosticSettingsResource, Exception]
    """
    from azure.core.exceptions import HttpResponseError

    try:
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
        diagnostics_setting_parameters = DiagnosticSettingsResource(
            storage_account_id=storage_acccout_id,
            workspace_id=workspace_id,
            logs=get_diagnostic_setting_properties()["logs"],
            metrics=get_diagnostic_setting_properties()["metrics"],
            log_analytics_destination_type="dedicated",
            # log_analytics_destination_type=None,
        )
        diagnostics_setting = (
            monitor_management_client.diagnostic_settings.create_or_update(
                resource_uri=resource_uri,
                name=diagnostics_setting_name,
                parameters=diagnostics_setting_parameters,
                content_type="application/json",
            )
        )
        monitor_management_client.close()
        return [diagnostics_setting, None]
    except HttpResponseError as err:
        logging.error(f"Exception\n\t{err}\n")
        if (
            err.error.code == "NoRegisteredProviderFound"
            and resolve_noregisteredproviderfound_error
        ):
            from ..ResourceProvider import register_resource_provider

            STORAGE_PROVIDER_NAMESPACE = "Microsoft.Storage"
            if register_resource_provider(
                credential,
                subscription_id=subscription_id,
                resource_provider_namespace=STORAGE_PROVIDER_NAMESPACE,
                force=resolve_noregisteredproviderfound_error,
            ):
                return create_diagnostic_setting(
                    credential,
                    subscription_id=subscription_id,
                    workspace_id=workspace_id,
                    resource_uri=resource_uri,
                    diagnostics_setting_name=diagnostics_setting_name,
                    storage_acccout_id=storage_acccout_id,
                    resolve_noregisteredproviderfound_error=False,
                )
        return [None, err]
    except Exception as ex:
        logging.exception(ex)
        return [None, ex]
    return [None, None]


def populate_ip_rules(
    ip_rules, allowed_ip_address_or_range, not_allowed_ip_address_or_range
):
    """
    prepares list of dictionary of IP rules, which will update existing ip_rules by adding
    ip_address_or_range from allowed_ip_address_or_range if it does not exists; and by
    removing ip_address_or_range from not_allowed_ip_address_or_range if it exists.

    :param ip_rules: - (Required) list of IPRule.

    :param allowed_ip_address_or_range: - (Required) list of IP address or CIDR range to be
    included in the result.

    :param not_allowed_ip_address_or_range: - (Required) list of IP address or CIDR range not
    to be included in the result.

    :return: [IPRule]. list of IPRule,
    """
    # IP rules
    allowed_ip_rules_to_pop = []
    pop_ip_rules_indices = []

    # check existing IP rules
    for ip_index, ip in enumerate(ip_rules):
        rule_found = False
        # check existing allowed IP rules
        for allowed_ip_index, allowed_ip in enumerate(allowed_ip_address_or_range):
            if ip.ip_address_or_range == allowed_ip:
                if ip.action == "Allow":
                    # expected rule exists
                    logging.debug(f"{allowed_ip} range found. no change needed")
                else:
                    # expected IP exists, but access is not allowed. set action = "Allow"
                    logging.debug(
                        f"{allowed_ip} range found. wrong rule {ip.action}. updating"
                    )
                    ip_rules[ip_index].action = "Allow"
                # because rule exists, we do not have to create new rule.
                # hence, remove it from allowed_ip_address_or_range
                allowed_ip_rules_to_pop.append(allowed_ip_index)
                rule_found = True

        if not rule_found:
            # check existing not allowed IP rules
            for not_allowed_ip_index, not_allowed_ip in enumerate(
                not_allowed_ip_address_or_range
            ):
                if ip.ip_address_or_range == not_allowed_ip:
                    # because denied IP rule exists, we remove it from ip_rules.
                    pop_ip_rules_indices.append(ip_index)

    allowed_ip_rules_to_pop.reverse()
    for index in allowed_ip_rules_to_pop:
        logging.debug(
            f"removing item at {index} index from {allowed_ip_address_or_range}"
        )
        allowed_ip_address_or_range.pop(index)

    pop_ip_rules_indices.reverse()
    for index in pop_ip_rules_indices:
        logging.debug(f"removing item at {index} index from {pop_ip_rules_indices}")
        ip_rules.pop(index)

    # create new allowed ip_address_or_range rule
    for ip_rule in allowed_ip_address_or_range:
        rule = dict({"value": ip_rule, "action": "Allow"})
        logging.debug(f"allow ip new rule::  {rule}")
        ip_rules.append(rule)

    return ip_rules


def populate_vnet_rules(
    credential,
    vnet_rules,
    allowed_vnets,
    not_allowed_vnets,
    subscription_id,
    resource_group_name,
):
    """
    prepares list of dictionary of Virtual Network rules, which will update existing
    vnet_rules by adding virtual network rule from allowed_vnets if it does not exists;
    and by removing virtul network rule from not_allowed_vnets if it exists.

    :param vnet_rules: - (Required) list of VirtualNetworkRule.

    :param allowed_vnets: - (Required) list of names of Virtual Networks to be included
    in the result.

    :param not_allowed_vnets: - (Required) list names of Virtual Networks not to be
    included in the result.

    :param subscription_id: (Required) Subscription id of VirtualNetworkRule.

    :param resource_group_name: (Required) Resource Group name of VirtualNetworkRule

    :return: [VirtualNetworkRule]. list of VirtualNetworkRule,
    """
    from ..Network import get_vnet_default_subnet_ids
    from azure.mgmt.storage.models import (
        VirtualNetworkRule,
    )

    pop_allowed_indices = []
    pop_not_allowed_indices = []
    pop_vnet_rule_indices = []
    # check existing vnet rules
    for index, rule in enumerate(vnet_rules):
        rule_found = False
        # check existing allowed vnet rules

        for allowed_vnet_index, allowed_vnet in enumerate(allowed_vnets):
            if rule.virtual_network_resource_id.split("/")[8] == allowed_vnet:
                if rule.action == "Allow":
                    # expected rule exists
                    logging.debug(
                        f"{rule.virtual_network_resource_id} allowed vnet found. no change needed"
                    )

                else:
                    # expected vnet exists, but access is not allowed. set action = "Allow"
                    logging.debug(
                        f"{rule.virtual_network_resource_id} vnet found. wrong rule {rule.action}. updating"
                    )
                    vnet_rules[index].action = "Allow"
                # because rule exists, we do not have to create new rule.
                # hence, remove it from allowed_vnets
                pop_allowed_indices.append(allowed_vnet_index)
                rule_found = True

        if not rule_found:
            # check existing not allowed vnet rules
            for not_allowed_vnet_index, not_allowed_vnet in enumerate(
                not_allowed_vnets
            ):
                if rule.virtual_network_resource_id.split("/")[8] == not_allowed_vnet:
                    # because denied vnet rule exists, we remove it from vnet_rules.
                    pop_vnet_rule_indices.append(index)

    pop_allowed_indices.reverse()
    for index in pop_allowed_indices:
        allowed_vnets.pop(index)

    pop_vnet_rule_indices.reverse()
    for index in pop_vnet_rule_indices:
        logging.debug(f"removing vnet rule {vnet_rules[index]}")
        vnet_rules.pop(index)

    # find vnet resource ids
    allow_vnet_subnet_resource_ids = get_vnet_default_subnet_ids(
        credential,
        subscription_id,
        resource_group_name,
        allowed_vnets,
    )

    # add rules to single list
    vnet_rules.extend(
        list(
            map(
                lambda vnet_subnet_resource_id: VirtualNetworkRule(
                    virtual_network_resource_id=vnet_subnet_resource_id,
                    action="Allow",
                ),
                allow_vnet_subnet_resource_ids,
            )
        )
    )
    return vnet_rules
