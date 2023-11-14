import logging
from ..Utils.utils import get_client


def register_resource_provider(
    credential, subscription_id, resource_provider_namespace
) -> bool:
    """
    This method registers a Resource Provider with given name in subscription with given id.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription to register Resource Provider in it.

    resource_provider_namespace -(Required) Resource Provider Namespace. For example, Microsoft.Storage

    :return: bool
    """

    resource_client = get_client(
        credential, "resource_management", dict({"subscription_id": subscription_id})
    )
    # List the available resource providers
    providers = resource_client.providers.list()

    storage_provider_registered = False
    for provider in providers:
        storage_provider_registered = (
            storage_provider_registered
            or provider.namespace == resource_provider_namespace
        )
        if storage_provider_registered:
            break

    if not storage_provider_registered:
        # Register the resource provider
        registration_result = resource_client.providers.register(
            resource_provider_namespace=resource_provider_namespace
        )
        logging.info(registration_result.registration_state)
        storage_provider_registered = True

    return storage_provider_registered
