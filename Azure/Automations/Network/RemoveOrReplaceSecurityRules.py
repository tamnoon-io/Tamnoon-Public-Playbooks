import sys
import os
import datetime
import logging
import json


from azure.identity import DefaultAzureCredential


from library.Network import is_network_security_group_busy
from library.ResourceGroups import get_resource_groups
from library.Utils.rollback import serialize_rollback_actions
from library.Utils.utils import get_client


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
        direction = "Direction" in action_params
        source_address_prefix = (
            "SourceAddressPrefix" in action_params
            and action_params["SourceAddressPrefix"].__len__() > 0
        )
        source_port_range = (
            "SourcePortRange" in action_params
            and action_params["SourcePortRange"].__len__() > 0
        )
        destination_address_prefix = (
            "DestinationAddressPrefix" in action_params
            and action_params["DestinationAddressPrefix"].__len__() > 0
        )
        destination_port_range = (
            "DestinationPortRange" in action_params
            and action_params["DestinationPortRange"].__len__() > 0
        )

        if not direction or action_params["Direction"].lower() == "inbound":
            if not source_address_prefix:
                raise Exception(
                    "'SourceAddressPrefix' is required, with optional 'SourcePortRange'"
                )
            if source_port_range and not source_address_prefix:
                raise Exception("'SourcePortRange' requires 'SourceAddressPrefix'")

        if direction and action_params["Direction"].lower() == "outbound":
            if not destination_address_prefix:
                raise Exception(
                    "'DestinationAddressPrefix' is required, with optional 'DestinationPortRange"
                )
            if destination_port_range and not destination_address_prefix:
                raise Exception(
                    "'DestinationPortRange' requires 'DestinationAddressPrefix'"
                )
    return True


def is_match_security_rule_with_active_params_with_asg(
    security_rule, application_security_groups_list
):
    """
    This method checks source or destination application security groups of a
    security rule are found in application security groups list.
    Returns True for match found, and False for match not found.

    :param security_rule: - (Required) instance of SecurityRule.

    :param application_security_groups_list: - (Required) list of Application Security Groups.

    :return: bool
    """

    source_application_security_groups = False
    logging.debug(security_rule.name)
    if (
        security_rule.source_application_security_groups != None
        and security_rule.source_application_security_groups.__len__() > 0
    ):
        for source_asg in security_rule.source_application_security_groups:
            logging.debug(source_asg.id.split("/")[8])
            for asg in application_security_groups_list:
                source_application_security_groups = (
                    source_application_security_groups or asg.id == source_asg.id
                )
                if source_application_security_groups:
                    break

    destination_application_security_groups = False
    if (
        security_rule.destination_application_security_groups != None
        and security_rule.destination_application_security_groups.__len__() > 0
    ):
        for destination_asg in security_rule.destination_application_security_groups:
            logging.debug(destination_asg.id.split("/")[8])
            for asg in application_security_groups_list:
                destination_application_security_groups = (
                    destination_application_security_groups or asg.id == source_asg.id
                )
                if destination_application_security_groups:
                    break

    result = [
        source_application_security_groups or destination_application_security_groups,
        source_application_security_groups,
        destination_application_security_groups,
    ]
    return result


def is_match_security_rule_with_action_params(
    security_rule, application_security_groups_list, action_params
):
    """
    This method checks security_rule matches the described values in action_params.

    Returns True for match found, and False for match not found.

    :param security_rule: - (Required) instance of SecurityRule.

    :param application_security_groups_list: - (Required) list of Application Security Groups.

    :param action_params: (Required) action params of remedy

    :return: [bool, bool, bool] - first bool value is result as a whole. second and third
    values denotes application security group match found in source or destination respectively
    """

    is_asg_match = is_match_security_rule_with_active_params_with_asg(
        security_rule, application_security_groups_list
    )

    name = "Name" not in action_params or action_params["Name"] == security_rule.name
    access = action_params["Access"] == security_rule.access
    direction = action_params["Direction"] == security_rule.direction
    protocol = action_params["Protocol"] == security_rule.protocol
    inbound = action_params["Direction"].lower() == "inbound"
    outbound = action_params["Direction"].lower() == "outbound"

    source_address_prefixes = (
        not inbound
        or (
            (
                security_rule.source_address_prefix != None
                and action_params["SourceAddressPrefix"].__contains__(
                    security_rule.source_address_prefix
                )
            )
            or (
                security_rule.source_address_prefixes.__len__() > 0
                and action_params["SourceAddressPrefix"].__len__() > 0
                and (
                    list(
                        filter(
                            lambda prefix: action_params[
                                "SourceAddressPrefix"
                            ].__contains__(prefix),
                            security_rule.source_address_prefixes,
                        )
                    ).__len__()
                    == security_rule.source_address_prefixes.__len__()
                    or list(
                        filter(
                            lambda prefix: security_rule.source_address_prefixes.__contains__(
                                prefix
                            ),
                            action_params["SourceAddressPrefix"],
                        )
                    ).__len__()
                    == action_params["SourceAddressPrefix"].__len__()
                )
            )
        )
        or is_asg_match[1]
    )
    source_port_ranges = not inbound or (
        not "SourcePortRange" in action_params
        or (
            security_rule.source_port_range != None
            and action_params["SourcePortRange"].__contains__(
                security_rule.source_port_range
            )
        )
        or (
            security_rule.source_port_range.__len__() > 0
            and action_params["SourcePortRange"].__len__() > 0
            and (
                list(
                    filter(
                        lambda range: action_params["SourcePortRange"].__contains__(
                            range
                        ),
                        security_rule.source_port_ranges,
                    )
                ).__len__()
                == security_rule.source_port_ranges.__len__()
                or list(
                    filter(
                        lambda range: security_rule.source_port_ranges.__contains__(
                            range
                        ),
                        action_params["SourcePortRange"],
                    )
                ).__len__()
                == action_params["SourcePortRange"].__len__()
            )
        )
    )

    destination_address_prefixes = (
        not outbound
        or (
            (
                security_rule.destination_address_prefix != None
                and action_params["DestinationAddressPrefix"].__contains__(
                    security_rule.destination_address_prefix
                )
            )
            or (
                security_rule.destination_address_prefixes.__len__() > 0
                and action_params["DestinationAddressPrefix"].__len__() > 0
                and (
                    list(
                        filter(
                            lambda prefix: action_params[
                                "DestinationAddressPrefix"
                            ].__contains__(prefix),
                            security_rule.destination_address_prefixes,
                        )
                    ).__len__()
                    == security_rule.destination_address_prefixes.__len__()
                    or list(
                        filter(
                            lambda prefix: security_rule.destination_address_prefixes.__contains__(
                                prefix
                            ),
                            action_params["DestinationAddressPrefix"],
                        )
                    ).__len__()
                    == action_params["DestinationAddressPrefix"].__len__()
                )
            )
        )
        or is_asg_match[2]
    )
    destination_port_ranges = not outbound or (
        not "DestinationPortRange" in action_params
        or (
            security_rule.destination_port_range != None
            and action_params["DestinationPortRange"].__contains__(
                security_rule.destination_port_range
            )
        )
        or (
            action_params["DestinationPortRange"].__len__() > 0
            and security_rule.destination_port_ranges.__len__() > 0
            and (
                list(
                    filter(
                        lambda range: action_params[
                            "DestinationPortRange"
                        ].__contains__(range),
                        security_rule.destination_port_ranges,
                    )
                ).__len__()
                == security_rule.destination_port_ranges.__len__()
                or list(
                    filter(
                        lambda range: security_rule.destination_port_ranges.__contains__(
                            range
                        ),
                        action_params["DestinationPortRange"],
                    )
                ).__len__()
                == action_params["DestinationPortRange"].__len__()
            )
        )
    )
    logging.debug(name)
    logging.debug(access)
    logging.debug(direction)
    logging.debug(protocol)
    logging.debug(f"{source_address_prefixes} {is_asg_match[1]}")
    logging.debug(source_port_ranges)
    logging.debug(f"{destination_address_prefixes} {is_asg_match[2]}")
    logging.debug(destination_port_ranges)

    # if (
    #     security_rule.source_application_security_groups != None
    #     and security_rule.source_application_security_groups.__len__() > 0
    #     or security_rule.destination_application_security_groups != None
    #     and security_rule.destination_application_security_groups.__len__() > 0
    # ):
    #     logging.warning("implementation for Application Security Groups is in progress")
    #     return False

    is_asg_match[0] = (
        name
        and access
        and direction
        and protocol
        and source_address_prefixes
        and source_port_ranges
        and destination_address_prefixes
        and destination_port_ranges
    )
    return is_asg_match


def remove_security_rules_from_nsg(
    network_security_group, application_security_groups_list, action_params
):
    """
    This method removes the security_rules of network_security_group that match the
    described values in action_params.

    :param network_security_group: - (Required) instance of Network Security Group.

    :param application_security_groups_list: - (Required) list of Application Security Groups.

    :param action_params: (Required) action params of remedy

    :return: [Network Security Group, bool] - first value is updated Network Security Group
    with security rules removed from it. second value is bool that indicates returned Network
    Security Group is altered(True) or not(False).
    """
    found = False
    pop_security_rule_indices = []
    try:
        if validate_action_params(action_params):
            for security_rule_index, security_rule in enumerate(
                network_security_group.security_rules
            ):
                if is_match_security_rule_with_action_params(
                    security_rule, application_security_groups_list, action_params
                )[0]:
                    logging.debug(f"can remove")
                    found = True
                    pop_security_rule_indices.append(security_rule_index)
                else:
                    logging.debug(f"cannot remove")
    except Exception as ex:
        logging.debug(f"cannot remove")
        logging.exception(ex)

    pop_security_rule_indices.reverse()
    for index in pop_security_rule_indices:
        logging.debug(f"removing {network_security_group.security_rules[index].name}")
        network_security_group.security_rules.pop(index)

    return (network_security_group, found)


def replace_security_rules_from_nsg(
    network_security_group, application_security_groups_list, action_params
):
    """
    This method replaces the security_rules of network_security_group that match the
    described values in action_params, with corresponding values in action_params.

    :param network_security_group: - (Required) instance of Network Security Group.

    :param application_security_groups_list: - (Required) list of Application Security Groups.

    :param action_params: (Required) action params of remedy

    :return: [Network Security Group, bool] - first value is updated Network Security Group
    with security rules replaced in it. second value is bool that indicates returned Network
    Security Group is altered(True) or not(False).
    """

    found = False
    try:
        if validate_action_params(action_params):
            for security_rule_index, security_rule in enumerate(
                network_security_group.security_rules
            ):
                is_asg_match = is_match_security_rule_with_action_params(
                    security_rule, application_security_groups_list, action_params
                )
                if is_asg_match[0]:
                    inbound = action_params["Direction"].lower() == "inbound"
                    outbound = action_params["Direction"].lower() == "outbound"

                    logging.debug(f"can replace")
                    if (
                        "ReplaceName" in action_params
                        and action_params["ReplaceName"] != None
                        and action_params["ReplaceName"] != ""
                        and action_params["ReplaceName"] != 0
                    ):
                        security_rule.name = action_params["ReplaceName"]
                    else:
                        security_rule.name = security_rule.name + "TamnoonReplacement"
                    if (
                        "ReplacePriority" in action_params
                        and action_params["ReplacePriority"] != None
                        and action_params["ReplacePriority"] != ""
                        and action_params["ReplacePriority"] != 0
                        and action_params["ReplacePriority"] != security_rule.priority
                    ):
                        security_rule.priority = action_params["ReplacePriority"]
                    if (
                        "ReplaceDescription" in action_params
                        and action_params["ReplaceDescription"] != None
                        and action_params["ReplaceDescription"] != ""
                        and action_params["ReplaceDescription"] != 0
                        and action_params["ReplaceDescription"]
                        != security_rule.description
                    ):
                        security_rule.description = action_params["ReplaceDescription"]
                    else:
                        security_rule.description = f"Replacement Rule by Tamnoon. Set on date {datetime.datetime.now().ctime()}"

                    if (
                        "ReplaceSourceAddressPrefix" in action_params
                        and action_params["ReplaceSourceAddressPrefix"] != None
                        and action_params["ReplaceSourceAddressPrefix"] != ""
                        and action_params["ReplaceSourceAddressPrefix"] != 0
                    ):
                        if is_asg_match[1]:
                            security_rule.source_application_security_groups = []

                        source_asg_changed = False
                        for source_address_prefix in action_params[
                            "ReplaceSourceAddressPrefix"
                        ]:
                            for asg in application_security_groups_list:
                                if source_address_prefix == asg.name:
                                    if not source_asg_changed:
                                        source_asg_changed = True
                                        security_rule.source_application_security_groups = (
                                            []
                                        )
                                    security_rule.source_application_security_groups.append(
                                        dict({"id": asg.id})
                                    )
                        if source_asg_changed:
                            security_rule.source_address_prefix = None
                            security_rule.source_address_prefixes = []
                        elif action_params["ReplaceSourceAddressPrefix"].__len__() > 1:
                            security_rule.source_address_prefix = None
                            security_rule.source_address_prefixes = action_params[
                                "ReplaceSourceAddressPrefix"
                            ]
                            security_rule.source_application_security_groups = []
                        elif action_params["ReplaceSourceAddressPrefix"].__len__() == 1:
                            security_rule.source_application_security_groups = []
                            security_rule.source_address_prefixes = []
                            security_rule.source_address_prefix = ",".join(
                                action_params["ReplaceSourceAddressPrefix"]
                            )
                        if action_params["ReplaceSourceAddressPrefix"].__len__() >= 1:
                            logging.info(
                                f"changing security_rule.source_address_prefix {action_params['ReplaceSourceAddressPrefix']} {security_rule.source_address_prefix} {security_rule.source_address_prefixes} {security_rule.source_application_security_groups}"
                            )
                    # if (
                    #     "ReplaceSourcePortRange" in action_params
                    #     and action_params["ReplaceSourcePortRange"] != None
                    #     and action_params["ReplaceSourcePortRange"] != ""
                    #     and action_params["ReplaceSourcePortRange"] != 0
                    #     and action_params["ReplaceSourcePortRange"]
                    #     != security_rule.source_port_range
                    # ):
                    #     security_rule.source_port_range = action_params[
                    #         "ReplaceSourcePortRange"
                    #     ]
                    if (
                        "ReplaceDestinationAddressPrefix" in action_params
                        and action_params["ReplaceDestinationAddressPrefix"] != None
                        and action_params["ReplaceDestinationAddressPrefix"] != ""
                        and action_params["ReplaceDestinationAddressPrefix"] != 0
                    ):
                        if is_asg_match[2]:
                            security_rule.destination_application_security_groups = []

                        destination_asg_changed = False
                        for destination_address_prefix in action_params[
                            "ReplaceDestinationAddressPrefix"
                        ]:
                            for asg in application_security_groups_list:
                                if destination_address_prefix == asg.name:
                                    if not destination_asg_changed:
                                        destination_asg_changed = True
                                        security_rule.destination_application_security_groups = (
                                            []
                                        )
                                    security_rule.destination_application_security_groups.append(
                                        dict({"id": asg.id})
                                    )
                        if destination_asg_changed:
                            security_rule.destination_address_prefix = None
                            security_rule.destination_address_prefixes = []
                        elif (
                            action_params["ReplaceDestinationAddressPrefix"].__len__()
                            > 1
                        ):
                            security_rule.destination_address_prefix = None
                            security_rule.destination_address_prefixes = action_params[
                                "ReplaceDestinationAddressPrefix"
                            ]
                            security_rule.destination_application_security_groups = []
                        elif (
                            action_params["ReplaceDestinationAddressPrefix"].__len__()
                            == 1
                        ):
                            security_rule.destination_application_security_groups = []
                            security_rule.destination_address_prefixes = []
                            security_rule.destination_address_prefix = ",".join(
                                action_params["ReplaceDestinationAddressPrefix"]
                            )
                        if (
                            action_params["ReplaceDestinationAddressPrefix"].__len__()
                            >= 1
                        ):
                            logging.info(
                                f"changing security_rule.destination_address_prefix {security_rule.destination_address_prefix} {security_rule.destination_address_prefixes} {security_rule.destination_application_security_groups}"
                            )
                    # if (
                    #     "ReplaceDestinationPortRange" in action_params
                    #     and action_params["ReplaceDestinationPortRange"] != None
                    #     and action_params["ReplaceDestinationPortRange"] != ""
                    #     and action_params["ReplaceDestinationPortRange"] != 0
                    #     and action_params["ReplaceDestinationPortRange"]
                    #     != security_rule.destination_port_range
                    # ):
                    #     security_rule.destination_port_range = action_params[
                    #         "ReplaceDestinationPortRange"
                    #     ]

                    found = True
                    network_security_group.security_rules[
                        security_rule_index
                    ] = security_rule
                else:
                    logging.debug(f"cannot replace")

    except Exception as ex:
        logging.debug(f"cannot replace")
        logging.exception(ex)

    return (network_security_group, found)


def remove_or_replace_security_rules_from_nsgs(
    credential,
    subscription_id,
    resource_group_names=['all'],
    regions=['all'],
    vnets=['all'],
    network_security_group_names=['all'],
    action_params=dict(),
    is_dry_run=True,
):
    """
    This method handles the removing or replacing the security_rules of network_security_groups
    that match the described values in action_params.

    :param credential: - (Required) Azure Credential.

    :param subscription_id: - (Required) Subscription id.

    :param resource_group_names: - (Required) list of Resource Groups names.

    :param regions: - (Required) list of Locations supported by Azure Resources.

    :param vnets: - (Required) list of Virtual Networks.

    :param network_security_group_names: - (Required) list of names of Network Security Groups to limit remedy onto.

    :param action_params: (Required) action params of remedy. action_params include following:
        - Name - Name of the secuirity rule. Optional.
        - Direction - "Inbound" or "Outbound". Default is "Inbound".
        - Access - "Allow"ed or "Deny"ed. Default is “Allow”.
        - Protocol - TCP, UDP, ICMP, Any. For matching "Any" protocol, use "*".
        - SourceAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group. Mandatory if Direction is "Inbound" or not specificied. Otherwise, when not specified, and when rule is outbound we match on anything
        - SourcePortRange - list of numeric (22) or ranges (80-81), optional, if not specied we match on anything
        - DestinationAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group. Mandatory if Direction is "Outbound". Otherwise, if not specified, we match on anything
        - DestinationPortRange - list of numeric (22) or ranges (80-81), optional, if not specied we match on anything
        - replace - true/false, default is false. When true, remedy will replace the security rules details as mentioned below.

        If you want to replace security rules, then following information is also required:
        - ReplaceName - string, optional, if not specified and replacement is True, the replacement name will be the original rule's name + "TamnoonReplacement"
        - ReplacePriority - numeric, optional. If not specified, same as original rule
        - ReplaceDescription optional, string, if not specified the description in the replaced rule is "Replacement Rule by Tamnoon. Set on date <todays date>"
        - ReplaceSourceAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group. Mandatory if replacing Inbound rules. Otherwise same as original rule.
        - replaceDestinationAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group. Mandatory if Direction is "Outbound" and Replace is True. Otherwise if not specified, same as original rule

        Note - Port range is kept as it is when replacing the Security Rules


    :param is_dry_run: (Optional) A flag to sign if this is a dry run execution

    :return: [dict] - first value is updated Network Security Group
    with security rules removed from it. second value is bool that indicates returned Network
    Security Group is altered(True) or not(False).
    """

    if "Protocol" not in action_params:
        action_params["Protocol"] = "*"
    if "Access" not in action_params:
        action_params["Access"] = "Allow"
    if "Direction" not in action_params:
        action_params["Direction"] = "Inbound"
    action = (
        "remove"
        if "Replace" not in action_params or not action_params["Replace"]
        else "replace"
    )
    result = []
    resource_groups = []
    use_all_regions = regions.__len__() == 1 and regions[0].lower() == "all"
    use_all_resource_groups = (
        resource_group_names.__len__() == 1 and resource_group_names[0].lower() == "all"
    )
    use_all_vnets = vnets.__len__() == 1 and vnets[0].lower() == "all"
    use_all_network_security_groups = (
        network_security_group_names.__len__() == 1
        and network_security_group_names[0].lower() == "all"
    )

    resource_groups = get_resource_groups(
        credential,
        subscription_id,
        locations=regions,
        resource_group_names=resource_group_names,
    )

    vnet_list = None
    for resource_group in resource_groups:
        network_client = get_client(
            credential,
            "network_management",
            dict({"subscription_id": subscription_id}),
        )
        vnet_list = list(network_client.virtual_networks.list_all())
        pop_vnet_indices = []
        for vnet_index, vnet in enumerate(vnet_list):
            if not use_all_vnets and not vnets.__contains__(vnet.name):
                pop_vnet_indices.append(vnet_index)
                logging.debug(f"removing vnet {vnet.name}")

        pop_vnet_indices.sort()
        pop_vnet_indices.reverse()
        for index in pop_vnet_indices:
            vnet_list.pop(index)

        # Get a list of all the resources that are using the NSG
        network_security_groups_list = list(
            filter(
                lambda network_security_group: (
                    use_all_regions
                    or regions.__contains__(network_security_group.location)
                )
                and (
                    use_all_network_security_groups
                    or network_security_group_names.__contains__(
                        network_security_group.name
                    )
                ),
                list(network_client.network_security_groups.list(resource_group.name)),
            )
        )

        if not use_all_vnets:
            pop_nsg_indices = []
            for vnet in vnet_list:
                for subnet in vnet.subnets:
                    subnet_nsg = subnet.network_security_group
                    if subnet_nsg is not None:
                        for nsg_index, nsg in enumerate(network_security_groups_list):
                            if nsg.id.lower() == subnet_nsg.id.lower():
                                pop_nsg_indices.append(nsg_index)
                                logging.debug(f"removing nsg {nsg.name}")
            pop_nsg_indices.sort()
            pop_nsg_indices.reverse()
            for index in pop_nsg_indices:
                network_security_groups_list.pop(index)

        application_security_groups_list = list(
            network_client.application_security_groups.list(resource_group.name)
        )
        application_security_groups_list = list(
            filter(
                lambda asg: (
                    "SourceAddressPrefix" in action_params
                    and action_params["SourceAddressPrefix"].__contains__(asg.name)
                )
                or (
                    "DestinationAddressPrefix" in action_params
                    and action_params["DestinationAddressPrefix"].__contains__(asg.name)
                )
                or (
                    "ReplaceSourceAddressPrefix" in action_params
                    and action_params["ReplaceSourceAddressPrefix"].__contains__(
                        asg.name
                    )
                )
                or (
                    "ReplaceDestinationAddressPrefix" in action_params
                    and action_params["ReplaceDestinationAddressPrefix"].__contains__(
                        asg.name
                    )
                ),
                application_security_groups_list,
            )
        )

        found = False
        logging.debug((found, network_security_groups_list.__len__()))
        for network_security_group_index, network_security_group in enumerate(
            network_security_groups_list
        ):
            found = True
            logging.info(
                f"The NSG {network_security_group.name}({network_security_group.location}) found in assets {network_security_group_names} and regions {regions}"
            )
            # network_interfaces_found,
            # subnets_found,
            [
                is_busy,
                security_rules_found,
                __1,
                __2,
            ] = is_network_security_group_busy(network_security_group)
            if is_busy:
                logging.info(
                    f"The NSG {network_security_group.name}({network_security_group.location}) is associated with a resource that is in use."
                )

                old_security_rules = list(
                    map(
                        lambda rule: rule.as_dict(),
                        list(network_security_group.security_rules),
                    )
                )
                if security_rules_found:
                    logging.info(
                        f"can do action {action} in {network_security_group.location}"
                    )
                    can_remove_or_replace = False
                    if action == "replace":
                        (
                            network_security_group,
                            can_remove_or_replace,
                        ) = replace_security_rules_from_nsg(
                            network_security_group,
                            application_security_groups_list,
                            action_params,
                        )
                    else:
                        (
                            network_security_group,
                            can_remove_or_replace,
                        ) = remove_security_rules_from_nsg(
                            network_security_group,
                            application_security_groups_list,
                            action_params,
                        )

                    if can_remove_or_replace:
                        if is_dry_run:
                            message = f"Dry run - Could update Security Rules in Network Security Group {network_security_group.name} ({network_security_group.location})"
                            logging.info(message)
                            result.append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": network_security_group.id,
                                            "Name": network_security_group.name,
                                            "Type": "network_security_group",
                                            "Action": "update",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": network_security_group.location,
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
                            new_state = network_client.network_security_groups.begin_create_or_update(
                                resource_group.name,
                                network_security_group.name,
                                network_security_group,
                            ).result()

                            result.append(
                                dict(
                                    {
                                        "Asset": {
                                            "Id": new_state.id,
                                            "Name": network_security_group.name,
                                            "Type": "network_security_group",
                                            "Action": "update",
                                            "CloudAccountId": "",
                                            "CloudProvider": "azure",
                                            "Region": new_state.location,
                                        },
                                        "ActionStatus": "Success"
                                        if not is_dry_run
                                        else "dryrun",
                                        "ExecutionResultData": {
                                            "ResultType": "object",
                                            "Result": {
                                                "prev_state": {
                                                    "security_rules": old_security_rules
                                                },
                                                "current_state": {
                                                    "security_rules": list(
                                                        map(
                                                            lambda rule: rule.as_dict(),
                                                            list(
                                                                new_state.security_rules
                                                            ),
                                                        )
                                                    )
                                                },
                                            },
                                        },
                                    }
                                )
                            )
                    else:
                        message = f"Could not find matching security rules in the NSG"
                        logging.info(message)
                        result.append(
                            dict(
                                {
                                    "Asset": {
                                        "Id": network_security_group.id,
                                        "Name": network_security_group.name,
                                        "Type": "network_security_group",
                                        "Action": "update",
                                        "CloudAccountId": "",
                                        "CloudProvider": "azure",
                                        "Region": network_security_group.location,
                                    },
                                    "ActionStatus": "Fail"
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
                    message = f"Could not find matching security rules in the NSG"
                    result.append(
                        dict(
                            {
                                "Asset": {
                                    "Id": network_security_group.id,
                                    "Name": network_security_group.name,
                                    "Type": "network_security_group",
                                    "Action": "update",
                                    "CloudAccountId": "",
                                    "CloudProvider": "azure",
                                    "Region": network_security_group.location,
                                },
                                "ActionStatus": "Fail" if not is_dry_run else "dryrun",
                                "ExecutionResultData": {
                                    "ResultType": "string",
                                    "Result": message,
                                },
                            }
                        )
                    )
            else:
                message = f"The NSG {network_security_group.name} is not associated with any resources."
                logging.info(message)
                result.append(
                    dict(
                        {
                            "Asset": {
                                "Id": network_security_group.id,
                                "Name": network_security_group.name,
                                "Type": "network_security_group",
                                "Action": "no-action",
                                "CloudAccountId": "",
                                "CloudProvider": "azure",
                                "Region": network_security_group.location,
                            },
                            "ActionStatus": "Fail" if not is_dry_run else "dryrun",
                            "ExecutionResultData": {
                                "ResultType": "string",
                                "Result": message,
                            },
                        }
                    )
                )
    return result


def rollback_remove_or_replace_security_rules_from_nsgs(
    credential,
    last_execution_result_path,
    dry_run=True,
) -> [dict]:
    """
    This method resets the modifications done by remove_or_replace_security_rules_from_nsgs() method.

    credential - (Required) Azure Credential.

    last_execution_result_path - (Required) path to the file that has json result.

    dry_run - (Optional) if False then performs actual operations on Cloud; default
    is True, where script will output the actions that can be performed by the
    script to rollback the result

    :return: [dict]
    """
    new_actions = []
    with open(last_execution_result_path, "r") as prev_state:
        prev_state_json = json.load(prev_state)

        if (
            prev_state_json["executionType"] == "network-security-group"
            and prev_state_json["executionAction"] == "remove_or_replace_security_rules"
        ):
            rollback_actions = serialize_rollback_actions(
                prev_state_json["executionResult"]
            )
            for action in rollback_actions:
                logging.debug(f"\n\t{action}")
                if (
                    action["Asset"]["Action"] == "update"
                    and action["ActionStatus"].lower() == "success"
                ):
                    # new resource was created. rollback action is delete new resource
                    if action["Asset"]["Type"] == "network_security_group":
                        subscription_id = action["Asset"]["Id"].split("/")[2]
                        resource_group_name = action["Asset"]["Id"].split("/")[4]
                        network_security_group_name = action["Asset"]["Name"]
                        region = action["Asset"]["Region"]
                        if dry_run:
                            message = f"Dry run - Could update Security Rules in Network Security Group {network_security_group_name} ({region})"
                            logging.info(message)
                            action["ActionStatus"] = "dryrun"
                            action["ExecutionResultData"] = dict(
                                {"ResultType": "string", "Result": message}
                            )
                        else:
                            network_client = get_client(
                                credential,
                                "network_management",
                                dict({"subscription_id": subscription_id}),
                            )

                            # Get a list of all the resources that are using the NSG
                            network_security_group = (
                                network_client.network_security_groups.get(
                                    resource_group_name, network_security_group_name
                                )
                            )
                            while network_security_group.security_rules.__len__() > 0:
                                network_security_group.security_rules.pop(0)

                            for security_rule_index, security_rule in enumerate(
                                action["ExecutionResultData"]["Result"]["prev_state"][
                                    "security_rules"
                                ]
                            ):
                                network_security_group.security_rules.append(
                                    security_rule
                                )
                            # return
                            network_client.network_security_groups.begin_create_or_update(
                                resource_group_name,
                                network_security_group_name,
                                network_security_group,
                            ).result()
                            network_client.close()
                            (
                                action["ExecutionResultData"]["Result"]["prev_state"],
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                            ) = (
                                action["ExecutionResultData"]["Result"][
                                    "current_state"
                                ],
                                action["ExecutionResultData"]["Result"]["prev_state"],
                            )
                            action["ActionStatus"] = "Success"
                            action["Asset"]["Action"] = "update"
            new_actions.append(action)
    return new_actions
