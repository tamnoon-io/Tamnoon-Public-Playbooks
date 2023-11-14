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
