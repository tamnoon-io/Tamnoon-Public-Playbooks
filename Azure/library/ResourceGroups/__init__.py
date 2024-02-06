from azure.mgmt.resource.resources.models import ResourceGroup
import logging
from ..Utils.utils import get_client


def get_resource_groups(
    credential, subscription_id, resource_group_names=["all"], locations=["all"]
) -> ResourceGroup:
    """
    This method finds Resource Groups in given Subscritpion id.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription to find Resource Group in it.

    resource_group_names - (Optional) names of Resource Groups to find.

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
        is_all_resource_groups = (
            resource_group_names.__len__() == 1 and resource_group_names[0] == "all"
        )
        is_all_locations = locations.__len__() == 1 and locations[0] == "all"
        resource_groups_list = list(resource_client.resource_groups.list())
        resource_groups = list(
            filter(
                lambda resource: (
                    is_all_locations or locations.__contains__(resource.location)
                )
                and (
                    is_all_resource_groups
                    or resource_group_names.__contains__(resource.name)
                ),
                resource_groups_list,
            )
        )
        return resource_groups
    except Exception as e:
        logging.error(e)
    return []
