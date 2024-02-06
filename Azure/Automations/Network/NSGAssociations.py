import sys
import os
import datetime
import time
import logging
import json
import argparse
from enum import Enum

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.mgmt.subscription import SubscriptionClient


from library.Utils import utils as utils


class NSGAssociationType(Enum):
    NSG = "network_security_group"
    VNET = "virtual_network"
    SUBNET = "subnet"
    NETWORK_INTERFACE = "network_interface"


class NSGAssociation:
    __data = None
    __association_resource_type = None

    def __init__(
        self,
        association_id,
        association_resource_type,
        resource_group_name,
        resource_name,
        resource_type,
    ):
        self.__association_resource_type = association_resource_type
        self.__data = dict(
            {
                self.__association_resource_type.value + "_id": association_id,
                "resource_group_name": resource_group_name,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "associations": [],
            }
        )

    def append(self, item):
        self.__data["associations"].append(item)

    def extend(self, items):
        self.__data["associations"].extend(items)

    def as_dict(self):
        associations = []
        if self.__data["associations"].__len__() > 0:
            for i in self.__data["associations"]:
                associations.append(i.as_dict())
            if self.__association_resource_type == NSGAssociationType.SUBNET:
                return dict(
                    {
                        self.__association_resource_type.value
                        + "_id": self.__data[
                            self.__association_resource_type.value + "_id"
                        ],
                        NSGAssociationType.VNET.value
                        + "_id": self.__data[
                            self.__association_resource_type.value + "_id"
                        ].split("/subnets")[0],
                        "resource_group_name": self.__data["resource_group_name"],
                        "resource_name": self.__data["resource_name"],
                        "resource_type": self.__data["resource_type"],
                        "associations": associations,
                    }
                )
            else:
                return dict(
                    {
                        self.__association_resource_type.value
                        + "_id": self.__data[
                            self.__association_resource_type.value + "_id"
                        ],
                        "resource_group_name": self.__data["resource_group_name"],
                        "resource_name": self.__data["resource_name"],
                        "resource_type": self.__data["resource_type"],
                        "associations": associations,
                    }
                )

    def print(self, depth=0):
        print("")
        tabs = ""
        i = 0
        while i < depth:
            tabs = tabs + "\t|"
            i = i + 1

        if self.__association_resource_type == NSGAssociationType.SUBNET:
            print(
                f'{tabs}{NSGAssociationType.VNET.value}_id :\t {self.__data[self.__association_resource_type.value + "_id"].split("/subnets")[0]}'
            )
        print(
            f'{tabs}{self.__association_resource_type.value}_id :\t {self.__data[self.__association_resource_type.value + "_id"]}'
        )
        print(f'{tabs}resource_group_name :\t {self.__data["resource_group_name"]}')
        print(f'{tabs}resource_name :\t {self.__data["resource_name"]}')
        print(f'{tabs}resource_type :\t {self.__data["resource_type"]}')
        if self.__data["associations"].__len__() > 0:
            for i in self.__data["associations"]:
                i.print(depth + 1)
        print("--")


class NSGAssociations:
    subscription_id = ""

    credential = None

    resource_client = None
    network_client = None
    cosmos_client = None
    compute_client = None
    storage_client = None

    resource_groups = None
    locations = None
    virtual_networks = None
    network_security_groups = None
    added_resource_list = None
    data = None

    status = "IDLE"  # "SUCCESS" "FAIL" "LOADING"
    RESOURCE_NSG = "Microsoft.Network/networkSecurityGroups"
    RESOURCE_TYPE_VM = "Microsoft.Compute/virtualMachines"

    SERVICE_TYPES = {
        "STORAGE": "Microsoft.Storage",
        "SQL": "Microsoft.SQLServer",
        "COSMOS": "Microsoft.CosmosDb",
    }

    def __init__(self, params):
        self.subscription_id = params.subscription
        self.credential = DefaultAzureCredential()
        self.added_resource_list = []

        self.subscription_client = SubscriptionClient(self.credential)
        self.resource_client = ResourceManagementClient(
            self.credential, self.subscription_id
        )
        self.network_client = NetworkManagementClient(
            self.credential, self.subscription_id
        )
        self.cosmos_client = CosmosDBManagementClient(
            self.credential, self.subscription_id
        )
        self.compute_client = ComputeManagementClient(
            self.credential, self.subscription_id
        )
        self.storage_client = StorageManagementClient(
            self.credential, self.subscription_id
        )

        # self.resources = self.list_all_resources()
        self.resource_groups = self.list_resource_groups(
            params.resourceGroups.split(",")
            if params.resourceGroups != None
            else ["all"]
        )
        self.locations = self.list_locations(
            params.regions.split(",") if params.regions != None else ["all"]
        )
        self.network_security_groups = self.list_nsgs(
            params.assetIds.split(",") if params.assetIds != None else ["all"]
        )

        self.virtual_networks = self.list_virtual_networks()

        self.data = []

    def __del__(self):
        self.network_client.close()
        self.cosmos_client.close()
        self.compute_client.close()
        self.storage_client.close()
        self.resource_client.close()

        del self.resource_groups
        del self.virtual_networks

        del self.network_client
        del self.cosmos_client
        del self.compute_client
        del self.storage_client

        del self.credential
        del self.subscription_id

    # def list_all_resources(self):
    #     return list(self.resource_client.resources.list())

    def list_resource_groups(self, resource_group_names=["all"]):
        is_all_resource_groups = (
            resource_group_names.__len__() == 1 and resource_group_names[0] == "all"
        )
        try:
            resource_groups_list = list(self.resource_client.resource_groups.list())
            resource_groups = list(
                filter(
                    lambda resource: (
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

    def has_resourcergroup_name(self, resource_group_name):
        found = False
        for resource_group in self.resource_groups:
            if resource_group.name == resource_group_name:
                found = True
                break
        return found

    def list_nsgs(self, nsg_names=["all"]):
        security_groups = []
        is_all_sgs = nsg_names.__len__() == 1 and nsg_names[0] == "all"
        try:
            resource_list = list(self.resource_client.resources.list())
            for resource in resource_list:
                if (
                    resource.id != None
                    and resource.type == self.RESOURCE_NSG
                    and (is_all_sgs or resource.name in nsg_names)
                ):
                    res_group = resource.id.lstrip("/").split("/")[3]
                    print(
                        "nsg resource details : "
                        + res_group
                        + "  : "
                        + resource.location
                    )
                    if (
                        self.has_resourcergroup_name(res_group)
                        and resource.location in self.locations
                    ):
                        security_groups.append(resource.id)
        except Exception as e:
            logging.error(e)

        return security_groups

    def list_locations(self, locations=["all"]):
        temp_locations = []
        is_all_locations = locations.__len__() == 1 and locations[0] == "all"
        try:
            resource_list = list(self.resource_client.resources.list())
            for resource in resource_list:
                if resource.location not in temp_locations:
                    if is_all_locations:
                        temp_locations.append(resource.location)
                    elif resource.location in locations:
                        temp_locations.append(resource.location)
        except Exception as e:
            logging.error(e)
        return temp_locations

    def list_private_endpoints(self, resource_group_name):
        private_endpoints = self.network_client.private_endpoints.list(
            resource_group_name
        )
        return private_endpoints

    def list_cosmos_db(self, resource_group_name):
        cosmos_db_list = list(
            self.cosmos_client.database_accounts.list_by_resource_group(
                resource_group_name
            )
        )
        # for cosmos_db in cosmos_db_list:
        #     print(cosmos_db.name)
        #     print(cosmos_db)
        #     for rule in cosmos_db.virtual_network_rules:
        #         print(rule.id)
        return cosmos_db_list

    def list_virtual_machines(self, resource_group_name):
        vm_list = list(self.compute_client.virtual_machines.list(resource_group_name))
        # Print the virtual machine names
        # print("\nvm")
        # for vm in vm_list:
        #     print(vm.name)
        #     print(vm.as_dict().keys())
        #     print(vm.network_profile.as_dict().keys())
        #     print("network_interfaces")
        #     for item in list(vm.network_profile.network_interfaces):
        #         print(item.id)
        return vm_list

    def list_storage_accounts(self, resource_group_name=None):
        if resource_group_name == None:
            return list(self.storage_client.storage_accounts.list())
        return list(
            self.storage_client.storage_accounts.list_by_resource_group(
                resource_group_name=resource_group_name
            )
        )

    def list_storage_account_properties(
        self, resource_group_name, storage_account_name
    ):
        properties = self.storage_client.storage_accounts.get_properties(
            resource_group_name=resource_group_name,
            account_name=storage_account_name,
        )
        return properties

    def list_virtual_networks(self):
        vnet_list = list(self.network_client.virtual_networks.list_all())
        # for vnet in vnet_list:
        #     print(vnet.name)
        #     print(vnet.as_dict().keys())
        return vnet_list

    def list_associated_services_of_vnet_subnet(self, virtual_network):
        services_list = []
        for subnet in virtual_network.subnets:
            # print(f"{virtual_network.name} -> {subnet.name}")
            if subnet.service_endpoints:
                for service_endpoint in subnet.service_endpoints:
                    services_list.append(service_endpoint)
                    # print(service_endpoint)
                    # print()
                # print()
        # print()

        return services_list

    def get_network_interfaces(self, resource_group_name, network_interface_name):
        network_interface = self.network_client.network_interfaces.get(
            resource_group_name=resource_group_name,
            network_interface_name=network_interface_name,
        )

        # print(f"network_interface Name: {network_interface.name}")
        # print(f"network_interface ID: {network_interface.id}")
        # print(f"network_interface Location: {network_interface.location}")

        return network_interface

    def get_virtual_machine(self, resource_group_name, virtual_machine_name):
        virtual_machine = self.compute_client.virtual_machines.get(
            resource_group_name, virtual_machine_name
        )
        return virtual_machine

    def get_virtual_machine_scale_set(self, resource_group_name, vmss_name):
        vmss = self.compute_client.virtual_machine_scale_sets.get(
            resource_group_name, vmss_name
        )
        return vmss

    def __subnet__storage_service_endpoint(self, subnet_id, service_endpoint):
        for account in self.list_storage_accounts():
            resource_group_name = account.id.split("/")[4]
            properties = self.list_storage_account_properties(
                resource_group_name, account.name
            )
            for vnet_rule in properties.network_rule_set.virtual_network_rules:
                if (
                    vnet_rule.virtual_network_resource_id != None
                    and vnet_rule.virtual_network_resource_id.lower()
                    == subnet_id.lower()
                ):
                    vnet_name = vnet_rule.virtual_network_resource_id.split("/")[8]
                    subnet_name = vnet_rule.virtual_network_resource_id.split("/")[10]
                    resource_group_name = vnet_rule.virtual_network_resource_id.split(
                        "/"
                    )[4]
                    # print(f"{vnet_name}:{subnet_name}")
                    return NSGAssociation(
                        subnet_id,
                        NSGAssociationType.SUBNET,
                        resource_group_name,
                        account.name,
                        account.type,
                    )
        return NSGAssociation(
            subnet_id, NSGAssociationType.SUBNET, "", "", service_endpoint.service
        )

    def add_resource_if_new(self, resourceId):
        is_new = True
        if resourceId in self.added_resource_list:
            return False
        self.added_resource_list.append(resourceId)
        return is_new

    def __subnet__network_interfaces(self, subnet_id, ip_configuration):
        resource_group_name = ip_configuration.id.split("/")[4]
        connection_type = ip_configuration.id.split("/")[7]
        connection_name = ip_configuration.id.split("/")[8]
        temp = NSGAssociation(
            subnet_id,
            NSGAssociationType.SUBNET,
            resource_group_name,
            connection_name,
            connection_type,
        )
        if connection_type == "networkInterfaces":
            network_interface = self.get_network_interfaces(
                resource_group_name,
                connection_name,
            )
            if network_interface != None and network_interface.virtual_machine:
                vm_name = network_interface.virtual_machine.id.split(
                    self.RESOURCE_TYPE_VM
                )[1].replace("/", "")
                is_in_location = network_interface.location == None or (
                    network_interface.location in self.locations
                )
                if (
                    is_in_location
                    and self.add_resource_if_new(network_interface.virtual_machine.id)
                    == True
                ):
                    temp.append(
                        NSGAssociation(
                            subnet_id,
                            NSGAssociationType.SUBNET,
                            resource_group_name,
                            vm_name,
                            self.RESOURCE_TYPE_VM,
                        )
                    )
            else:
                # network interface not associated with virtual machines
                pass
        return temp

    def __subnet__service_endpoints(self, subnet_id, service_endpoint):
        result = NSGAssociation(
            subnet_id, NSGAssociationType.SUBNET, "", "Service Endpoint", ""
        )
        if self.SERVICE_TYPES["STORAGE"] == service_endpoint.service:
            result.append(
                self.__subnet__storage_service_endpoint(subnet_id, service_endpoint)
            )
        # if self.SERVICE_TYPES["SQL"] == service_endpoint.service:
        #     pass
        # if self.SERVICE_TYPES["COSMOS"] == service_endpoint.service:
        #     pass
        # if service_endpoint
        return result

    def __network_interface__virtual_machine(
        self, resource_group_name, network_interface_id
    ):
        result = []
        vm_list = self.list_virtual_machines(resource_group_name)
        for vm in vm_list:
            for ni in vm.network_profile.network_interfaces:
                if ni.id == network_interface_id:
                    result.append(
                        NSGAssociation(
                            network_interface_id,
                            NSGAssociationType.NETWORK_INTERFACE,
                            resource_group_name,
                            vm.name,
                            vm.type,
                        )
                    )
        return result

    def __network_interface__cosmos_db(self, resource_group_name, network_interface_id):
        result = []
        cosmos_db_list = self.list_cosmos_db(resource_group_name)

        for account in cosmos_db_list:
            if account.private_endpoint_connections != None:
                for private_endpoint_resource_group in self.resource_groups:
                    private_endpoints_list = list(
                        self.list_private_endpoints(
                            private_endpoint_resource_group.name,
                        )
                    )
                    # TODO: find network interface here
                    for private_endpoint in private_endpoints_list:
                        for endpoint in account.private_endpoint_connections:
                            if private_endpoint.id == endpoint.private_endpoint.id:
                                for ni in private_endpoint.network_interfaces:
                                    if ni.id == network_interface_id:
                                        result.append(
                                            NSGAssociation(
                                                network_interface_id,
                                                NSGAssociationType.NETWORK_INTERFACE,
                                                resource_group_name,
                                                account.name,
                                                account.type,
                                            )
                                        )
        return result

    def _subnet(
        self,
        resource_group_name,
        subnet_id,
    ):
        result = []
        for virtual_network in self.virtual_networks:
            if subnet_id.__contains__(virtual_network.id):
                for subnet in virtual_network.subnets:
                    if subnet_id == subnet.id:
                        if subnet.ip_configurations != None:
                            for ip_configuration in subnet.ip_configurations:
                                result.append(
                                    self.__subnet__network_interfaces(
                                        subnet_id, ip_configuration
                                    )
                                )
                        else:
                            # ip_configration is None
                            pass
                        if subnet.service_endpoints != None:
                            for service_endpoint in subnet.service_endpoints:
                                result.append(
                                    self.__subnet__service_endpoints(
                                        subnet_id, service_endpoint
                                    )
                                )
                        else:
                            # service_endpoints is None
                            pass
                    else:
                        # subnet id not matched
                        pass
            else:
                # subnet's vnet not matched
                pass
        return result

    def _network_interface(self, resource_group_name, network_interface_id):
        result = []
        for resource_group in self.resource_groups:
            result.extend(
                self.__network_interface__virtual_machine(
                    resource_group.name, network_interface_id
                )
            )
            result.extend(
                self.__network_interface__cosmos_db(
                    resource_group.name, network_interface_id
                )
            )

        return result

    def populate(self):
        for resource_group in self.resource_groups:
            resource_group_name = resource_group.name
            network_security_groups = list(
                self.network_client.network_security_groups.list(resource_group_name)
            )

            for network_security_group in network_security_groups:
                result = []
                resource_group_name = network_security_group.id.lstrip("/").split("/")[
                    3
                ]
                if network_security_group.id not in self.network_security_groups:
                    continue
                if network_security_group.subnets != None:
                    for subnet in network_security_group.subnets:
                        result.extend(
                            self._subnet(
                                resource_group_name,
                                subnet.id,
                            )
                        )
                if network_security_group.network_interfaces != None:
                    for network_interface in network_security_group.network_interfaces:
                        result.extend(
                            self._network_interface(
                                resource_group_name,
                                network_interface.id,
                            )
                        )

                if result.__len__() > 0:
                    nsg = NSGAssociation(
                        network_security_group.id,
                        NSGAssociationType.NSG,
                        resource_group_name,
                        network_security_group.name,
                        network_security_group.type,
                    )
                    nsg.extend(result)
                    self.data.append(nsg)

        for item in self.data:
            item.print()

    def save(self):
        with open(
            f"./nsg-associations-{self.subscription_id}-{str(time.time())}.json", "w"
        ) as f:
            value = []
            for i in self.data:
                value.append(i.as_dict())
            json.dump(value, f, ensure_ascii=False, indent=4)

    def as_dict(self):
        value = []
        for i in self.data:
            value.append(i.as_dict())
        return value
