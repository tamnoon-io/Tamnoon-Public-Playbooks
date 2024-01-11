def get_new_analytics_logging_obj():
    from azure.storage.blob import BlobAnalyticsLogging, RetentionPolicy

    return BlobAnalyticsLogging(
        version="1.0",
        delete=True,
        read=True,
        write=True,
        retention_policy=RetentionPolicy(enabled=True, days=1),
    )


def get_access_key(
    credential, subscription_id, resource_group_name, storage_account_name
):
    # needs to have RBAC role storage Account Contributor for the whole subscription
    from ..Utils.utils import get_client

    storage_client = get_client(
        credential, "storage_management", dict({"subscription_id": subscription_id})
    )

    storage_keys = storage_client.storage_accounts.list_keys(
        resource_group_name, storage_account_name
    )
    storage_keys = {v.key_name: v.value for v in storage_keys.keys}
    return storage_keys["key1"]
