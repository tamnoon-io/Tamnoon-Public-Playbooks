from ..Utils.utils import get_client


def find_or_create_vnet_and_subnet(
    credential,
    subscription_id,
    location,
    resource_group_name,
    virtual_network_name,
    subnet_name,
):
    """
    finds or creates virtual network and its default subnet.

    :param credential: - (Required) Azure Credential.

    :param subscription_id: - (Required) Subscription id of virtual network

    :param location: - (Required) Region location of virtual network

    :param resource_group_name: - (Required) Resource Group name of virtual network

    :param virtual_network_name: - (Required) name of virtual network

    :param subnet_name: - (Required) name of subnet of virtual network

    :return: string. A fully qualified resource id of subnet
    """
    network_client = get_client(
        credential, "network_management", dict({"subscription_id": subscription_id})
    )

    vnet = network_client.virtual_networks.create_or_update(
        resource_group_name=resource_group_name,
        virtual_network_name=virtual_network_name,
        parameters={
            "location": location,
            "address_space": {"address_prefixes": ["10.0.0.0/16"]},
        },
    )
    # Create Subnet
    subnet_info = network_client.subnets.create_or_update(
        resource_group_name=resource_group_name,
        virtual_network_name=virtual_network_name,
        subnet_name=subnet_name,
        subnet_parameters=dict({"address_prefix": "10.0.0.0/24"}),
    ).result()
    return f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/virtualNetworks/{virtual_network_name}/subnets/{subnet_name}"


def get_vnet_ids(credential, subscription_id, resource_group_name, vnet_names_list):
    """
    finds list of virtual network resource ids.

    :param credential: - (Required) Azure Credential.

    :param subscription_id: - (Required) Subscription id of virtual network

    :param resource_group_name: - (Required) Resource Group name of virtual network

    :param vnet_names_list: - (Required) list of names of virtual network

    :return: [[string], [string]].
        first item is list of fully qualified resource ids of found virtual networks,
        second item is list of virtual network names that do not exists
    """

    network_client = get_client(
        credential, "network_management", dict({"subscription_id": subscription_id})
    )
    vnet_list = network_client.virtual_networks.list(
        resource_group_name=resource_group_name,
    )

    found_vnet_ids = []
    not_found_vnet_ids = []
    for vnet_name in vnet_names_list:
        not_found_vnet_ids.append(vnet_name)
        index = not_found_vnet_ids.__len__()
        for vnet in vnet_list:
            if vnet.name == vnet_name:
                found_vnet_ids.append(vnet.id)
                not_found_vnet_ids.pop(index - 1)

    network_client.close()
    return [found_vnet_ids, not_found_vnet_ids]


def get_vnet_default_subnet_ids(
    credential, subscription_id, resource_group_name, vnet_names_list
):
    """
    finds list of resource ids of default subnets of virtual networks.

    :param credential: - (Required) Azure Credential.

    :param subscription_id: - (Required) Subscription id of virtual network

    :param resource_group_name: - (Required) Resource Group name of virtual network

    :param vnet_names_list: - (Required) list of names of virtual network

    :return: [string].
        list of fully qualified resource ids of subnet of virtual networks,
    """
    network_client = get_client(
        credential, "network_management", dict({"subscription_id": subscription_id})
    )
    vnet_list = list(
        # if not wrapped in list(), the iterator returned by network_client.virtual_networks.list
        # takes time to get all data and some virtual network resource ids may not be processed.
        network_client.virtual_networks.list(
            resource_group_name=resource_group_name,
        )
    )

    found_subnets = []
    not_found_subnets = []
    for vnet_name in vnet_names_list:
        # TODO: get all subnet ids
        found = False
        for vnet in vnet_list:
            if vnet.name == vnet_name:
                subnet_id = vnet.subnets[0].id if vnet.subnets.__len__() > 0 else ""
                found_subnets.append(subnet_id)
                found = True

        if not found:
            not_found_subnets.append(vnet_name)

    network_client.close()
    return found_subnets
