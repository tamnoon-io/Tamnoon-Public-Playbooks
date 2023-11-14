from azure.mgmt.resource.resources.models import ResourceGroup
import logging
from ..Utils.utils import get_client


def get_resource_groups(credential, subscription_id, locations=None) -> ResourceGroup:
    """
    This method finds Resource Groups in given Subscritpion id.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription to find Resource Group in it.

    locations - (Optional) location of Resource Group.

    :return: [azure.mgmt.resource.resources.models.ResourceGroup]
    """

    RESOURCE_GROUP_TYPE = "Microsoft.Resources/resourceGroups"
    try:
        resource_client = get_client(
            credential,
            "resource_management",
            dict({"subscription_id": subscription_id}),
        )
        if locations == None:
            return resource_client.resource_groups.list()
        else:
            resource_groups = []
            for resource in resource_client.resource_groups.list():
                if (
                    resource.type == RESOURCE_GROUP_TYPE
                    and not locations == None
                    or locations.__contains__(resource.location)
                ):
                    resource_groups.append(resource)
            resource_client.close()
            return resource_groups
    except Exception as e:
        logging.error(e)
    return []
