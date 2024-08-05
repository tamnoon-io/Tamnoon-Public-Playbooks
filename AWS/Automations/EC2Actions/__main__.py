"""
module EC2Action.EC2Helper
"""

import json
import logging
import sys
import os
from datetime import datetime
from argparse import (
    ArgumentParser,
    _ArgumentGroup,
    RawTextHelpFormatter,
)
from typing import Callable, Union
from Automations.CloudWatchActions import GetAllFlowlogs
from library.EC2 import (
    EC2Helper, LoadBalancersHelper, SecurityGroupHelper,
    SnapshotHelper, SubnetHelper, VPCHelper
)
from library.EC2.types import (
    EC2Types, EC2TypeActions, SnapshotTypeActions,
    SecurityGroupTypeActions, SubnetTypeActions, VPCTypeActions
)
import Automations.Utils.utils as utils

try:
    from Automations.EC2Actions import help_jsons_data
except ModuleNotFoundError as ex:
    help_jsons_data = {}
ec2_get_imdsv1_usage_readme_data = (
    help_jsons_data.ec2_get_imdsv1_usage_readme_data
    if hasattr(help_jsons_data, "ec2_get_imdsv1_usage_readme_data")
    else dict()
)
ec2_enforce_imdsv2_readme_data = (
    help_jsons_data.ec2_enforce_imdsv2_readme_data
    if hasattr(help_jsons_data, "ec2_enforce_imdsv2_readme_data")
    else dict()
)
ec2_find_load_balancers_readme_data = (
    help_jsons_data.ec2_find_load_balancers_readme_data
    if hasattr(help_jsons_data, "ec2_find_load_balancers_readme_data")
    else dict()
)
snapshot_delete_readme_data = (
    help_jsons_data.snapshot_delete_readme_data
    if hasattr(help_jsons_data, "snapshot_delete_readme_data")
    else dict()
)
snapshot_ls_readme_data = (
    help_jsons_data.snapshot_ls_readme_data
    if hasattr(help_jsons_data, "snapshot_ls_readme_data")
    else dict()
)
snapshot_encrypt_readme_data = (
    help_jsons_data.snapshot_encrypt_readme_data
    if hasattr(help_jsons_data, "snapshot_encrypt_readme_data")
    else dict()
)
security_group_delete_readme_data = (
    help_jsons_data.security_group_delete_readme_data
    if hasattr(help_jsons_data, "security_group_delete_readme_data")
    else dict()
)
security_group_clean_unused_sg_readme_data = (
    help_jsons_data.security_group_clean_unused_sg_readme_data
    if hasattr(help_jsons_data, "security_group_clean_unused_sg_readme_data")
    else dict()
)
security_group_get_all_flow_logs_readme_data = (
    help_jsons_data.security_group_get_all_flow_logs_readme_data
    if hasattr(help_jsons_data, "security_group_get_all_flow_logs_readme_data")
    else dict()
)
security_group_get_usage_readme_data = (
    help_jsons_data.security_group_get_usage_readme_data
    if hasattr(help_jsons_data, "security_group_get_usage_readme_data")
    else dict()
)
security_group_remove_or_replace_rules_readme_data = (
    help_jsons_data.security_group_remove_or_replace_rules_readme_data
    if hasattr(help_jsons_data, "security_group_remove_or_replace_rules_readme_data")
    else dict()
)
vpc_create_flow_log_readme_data = (
    help_jsons_data.vpc_create_flow_log_readme_data
    if hasattr(help_jsons_data, "vpc_create_flow_log_readme_data")
    else dict()
)
subnet_disable_public_ip_assignment_readme_data = (
    help_jsons_data.subnet_disable_public_ip_assignment_readme_data
    if hasattr(help_jsons_data, "subnet_disable_public_ip_assignment_readme_data")
    else dict()
)
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


def _snapshot_delete_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
    This function is wrapper for AWS.library.SnapshotHelper.do_snapshot_delete,
    which is called over all asset_ids.

    :param session: boto3 session
    :param asset_ids: list of asset ids
    :param dry_run: Boolean flag to mark if this is dry run or not
    :param *action_params: unused variable. If found, this will be freed from memory
    :param *output_directory: unused variable. If found, this will be freed from memory
    :return:
    """
    del action_params  # remove unused parameters
    del output_directory  # remove unused parameters
    resource = session.resource("ec2")
    for asset_id in asset_ids:
        logging.info(
            "Going to execute - %s for asset type - %s asset - %s",
            SnapshotTypeActions.DELETE.value,
            EC2Types.SNAPSHOT.value,
            asset_id
        )
        SnapshotHelper.do_snapshot_delete(
            resource=resource,
            asset_id=asset_id,
            dry_run=dry_run
        )
    return {}


def _snapshot_list_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory
):
    """
    This function is wrapper for AWS.library.SnapshotHelper.do_snapshot_ls.

    :param session: boto3 session
    :param dry_run: unused variable. If found, this will be freed from memory
    :param asset_ids: unused variable. If found, this will be freed from memory
    :param action_params: unused variable. If found, this will be freed from memory
    :param output_directory: unused variable. If found, this will be freed from memory
    :return:
    """
    del dry_run  # remove unused parameters
    del asset_ids  # remove unused parameters
    del action_params  # remove unused parameters
    del output_directory  # remove unused parameters
    SnapshotHelper.do_snapshot_ls(session=session)
    return {}


def _snapshot_encrypt_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
    This function is wrapper for AWS.library.SnapshotHelper.do_snapshot_encrypt.

    :param session: boto3 session
    :param dry_run: Boolean flag to mark if this is dry run or not
    :param asset_ids: list of asset ids
    :param output_directory: unused variables. If found, this will be freed from memory
    :return:
    """
    del output_directory  # remove unused parameters

    kms_key_id = (
        action_params["kmsKeyId"]
        if action_params and "kmsKeyId" in action_params
        else None
    )
    for asset_id in asset_ids:
        logging.info(
            "Going to execute - %s for asset type - %s asset - %s",
            SnapshotTypeActions.ENCRYPT.value,
            EC2Types.SNAPSHOT.value,
            asset_id
        )
        SnapshotHelper.do_snapshot_encrypt(
            session=session,
            asset_id=asset_id,
            dry_run=dry_run,
            kms_key_id=kms_key_id,
        )
    return {}


def _sg_clean_unused_sg_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is wrapper for AWS.library.SecurityGroupHelper.clean_unused_sg.
s
        :param session: boto3 session
        :param asset_ids: list of asset ids list of asset ids
        :param dry_run: Boolean flag to mark if this is dry run or not
        :param action_params: action params of automation
        :param output_directory: unused variables. If found, this will be freed from memory
        :return:
    """
    del output_directory  # remove unused parameters
    if not action_params or "statePath" not in action_params:
        raise KeyError(
            "statePath have to delivered in case of Security Group cleanup \
                - to be able to roll back "
        )
    state_path = action_params["statePath"]
    is_roll_back = (
        action_params["rollBack"] if "rollBack" in action_params else None
    )
    only_defualts = (
        action_params["onlyDefaults"] if "onlyDefaults" in action_params else False
    )
    sg_to_rb = (
        action_params["sgTorollBack"] if "sgTorollBack" in action_params else "All"
    )
    action_type = (
        action_params["actionType"] if "actionType" in action_params else "Clean"
    )
    tag_deletion = (
        action_params["deletionTag"] if "deletionTag" in action_params else None
    )

    SecurityGroupHelper.clean_unused_sg(
        is_rollback=is_roll_back,
        aws_session=session,
        region=session.region_name,
        only_defaults=only_defualts,
        is_dry_run=dry_run,
        state_path=state_path,
        sg_to_rb=sg_to_rb,
        asset_ids=asset_ids,
        tag_deletion=tag_deletion,
        action_type=action_type,
    )


def _sg_delete_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory
):
    """
        This function is wrapper for AWS.library.SecurityGroupHelper.do_sg_delete.

        :param session: boto3 session
        :param asset_ids: list of asset ids
        :param dry_run: Boolean flag to mark if this is dry run or not
        :param action_params: unused variables. If found, this will be freed from memory
        :param output_directory: unused variables. If found, this will be freed from memory
        :return:
    """
    del action_params  # remove unused parameters
    del output_directory  # remove unused parameters
    resource = session.resource("ec2")
    for asset_id in asset_ids:
        logging.info(
            "Going to execute - %s for asset type - %s asset - %s",
            EC2Types.SG.value,
            SecurityGroupTypeActions.DELETE.value,
            asset_id
        )
        SecurityGroupHelper.do_sg_delete(
            resource=resource, asset_id=asset_id, dry_run=dry_run)
    return {}


def _sg_get_usage_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory
):
    """
        This function is wrapper for AWS.Automations.CloudWatchActions.GetAllFlowlogs.get_sg_usage.

        :param session: boto3 session
        :param dry_run: unused variables. If found, this will be freed from memory
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory: unused variables. If found, this will be freed from memory
        :return:
    """
    del dry_run  # remove unused parameters
    del output_directory  # remove unused parameters
    only_defaults = (
        action_params["onlyDefaults"]
        if action_params and "onlyDefaults" in action_params
        else False
    )
    allgroups = GetAllFlowlogs.get_sgs(session, [session.region_name])
    is_all_security_groups = asset_ids == ["all"]
    interesting_asset_ids = [
        sg["GroupId"]
        for reg in allgroups.keys()
        for sg in allgroups[reg]
        if len(
            [
                1
                for x in sg["SGRules"]
                if (is_all_security_groups or x["GroupId"] in asset_ids)
            ]
        )
        > 0
    ]

    result = SecurityGroupHelper.get_sg_usage(
        session=session,
        output_result=dict(),
        only_defaults=only_defaults,
        asset_ids=interesting_asset_ids,
    )
    if asset_ids is not None and asset_ids != ["all"]:
        for asset_id in asset_ids:
            if asset_id not in interesting_asset_ids:
                result[asset_id] = "sg not found in region"
    return result


def _sg_get_all_flow_logs_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is wrapper for AWS.Automations.CloudWatchActions.GetAllFlowlogs.get_sgs.

        :param session: boto3 session
        :param dry_run: unused variables. If found, this will be freed from memory
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory:
        :return:
    """
    del dry_run  # remove unused parameters
    if not output_directory:
        output_directory = os.getcwd()
    if asset_ids is None:
        logging.error(
            "assetIds (comma separated security groups IDs or all) are required"
        )
        exit(0)
    exclude_private_ips_from_source = (
        action_params["excludePrivateIPsFromSource"].lower() == "true"
        if action_params is None and "excludePrivateIPsFromSource" in action_params
        else True
    )
    hoursback = (
        action_params["hoursback"]
        if action_params is None and "hoursback" in action_params
        else GetAllFlowlogs.NUMBER_OF_HOURS_BACK
    )
    exclude_src_ports = (
        action_params["exclude_src_ports"]
        if action_params is None and "exclude_src_ports" in action_params
        else False
    )
    allgroups = GetAllFlowlogs.get_sgs(session, [session.region_name])
    is_all_security_groups = asset_ids == ["all"]
    if is_all_security_groups:
        interestinggroups = [
            sg["GroupId"]
            for reg in allgroups.keys()
            for sg in allgroups[reg]
            if len(
                [
                    1
                    for x in sg["SGRules"]
                    if (is_all_security_groups or x["GroupId"] in asset_ids)
                    and x["IsEgress"] is False
                    and x.get("CidrIpv4") == "0.0.0.0/0"
                    and not (
                        x.get("IpProtocol") == "tcp" and x.get(
                            "FromPort") == 443
                    )
                ]
            )
            > 0
        ]
    else:
        interestinggroups = [x for x in asset_ids if x.find("sg-") == 0]
    rop = GetAllFlowlogs.regionhandler(
        session=session,
        output_directory=output_directory,
        hoursback=hoursback,
        exclude_private_ips_from_source=exclude_private_ips_from_source,
        allgroups=allgroups,
        interestinggroups=interestinggroups,
        exclude_src_ports=exclude_src_ports,
    )
    if not is_all_security_groups:
        for sg in asset_ids:
            if sg not in interestinggroups:
                sgop = dict()
                sgop[sg] = f"No sg was found for investigating by ID {sg}"
                logging.info(sgop[sg])
                rop.append(sgop)
    return rop


def _remove_or_replace_rules_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is wrapper for AWS.library.SecurityGroupHelper.\
            do_remove_or_replace_security_rules
        and its rollback function AWS.library.SecurityGroupHelper.\
            do_rollback_remove_or_replace_security_rules.

        :param session: boto3 session
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory: unused variables. If found, this will be freed from memory
        :return:
    """
    del output_directory  # remove unused parameters
    action_params = utils.Params(action_params)

    if hasattr(action_params, "rollBack") and action_params.rollBack:
        return SecurityGroupHelper.do_rollback_remove_or_replace_security_rules(
            session=session,
            dry_run=dry_run,
            state_path=action_params.statePath
        )
    return SecurityGroupHelper.do_remove_or_replace_security_rules(
        session=session,
        dry_run=dry_run,
        asset_ids=asset_ids,
        replace=bool(action_params.replace),
        old_cidrs=action_params.oldCidrs,
        new_cidrs=action_params.newCidrs,
        ports=action_params.Ports,
        ip_prot=action_params.IpProt,
        allprivate=action_params.allprivate
    )


def _vpc_create_flow_log_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is the implementation for security group actions
        :param session: boto3 session
        :param dry_run: Boolean flag to mark if this is dry run or not
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory:
        :return:
    """
    if not output_directory:
        output_directory = os.getcwd()

    log_group_name = None

    deliver_logs_permission_arn = action_params["DeliverLogsPermissionArn"]

    if not action_params or "DeliverLogsPermissionArn" not in action_params:
        log_error = (
            "Can't create a vpc flow log, missing required configuration \
                param - DeliverLogsPermissionArn\n"
            "The ARN of the IAM role that allows Amazon EC2 to publish flow \
                logs to a CloudWatch Logs log group in your account."
        )
        logging.error(log_error)
        return {
            "error": log_error
        }

    logging.info("Going to execute - VPC  - %s",
                 VPCTypeActions.CREATE_FLOW_LOG.value)
    # check regions
    if len(asset_ids) == 1 and asset_ids[0] == "all":
        list_of_vpcs = VPCHelper.get_vpcs_in_region(session)
        if not list_of_vpcs:
            list_of_vpcs = []
        for asset_id in list_of_vpcs:
            if not "LogGroupName" in action_params:
                log_group_name = f"Vpc_FlowLog_{asset_id}"
            else:
                log_group_name = action_params["LogGroupName"]
            VPCHelper.do_create_flow_log(
                session=session,
                asset_id=asset_id,
                dry_run=dry_run,
                log_group_name=log_group_name,
                deliver_logs_permission_arn=deliver_logs_permission_arn,
            )
    else:
        for asset_id in asset_ids:
            if not "LogGroupName" in action_params:
                log_group_name = f"Vpc_FlowLog_{asset_id}"
            else:
                log_group_name = action_params["LogGroupName"]

            logging.info(
                "Going to execute - %s for asset type - %s asset - %s",
                VPCTypeActions.CREATE_FLOW_LOG.value,
                EC2Types.VPC.value,
                asset_id
            )
            VPCHelper.do_create_flow_log(
                session=session,
                asset_id=asset_id,
                dry_run=dry_run,
                log_group_name=log_group_name,
                deliver_logs_permission_arn=deliver_logs_permission_arn,
            )
    return {}


def _ec2_get_imdsv1_usage_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is the implementation for security group actions
        :param session: boto3 session
        :param dry_run: Boolean flag to mark if this is dry run or not
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory:
        :return:
    """
    del dry_run  # remove unused parameters
    if not output_directory:
        output_directory = os.getcwd()

    if asset_ids is None:
        asset_ids = ["all"]
    days = (
        int(action_params["days"])
        if action_params is not None and "days" in action_params
        else 14
    )

    return EC2Helper.find_imdsv1_usage(
        session=session,
        asset_ids=asset_ids,
        days=days,
        duration_end_time=datetime.utcnow().ctime(),
    )


def _ec2_enforce_imdsv2_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is the implementation for security group actions
        :param session: boto3 session
        :param dry_run: Boolean flag to mark if this is dry run or not
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory:
        :return:
    """
    if not output_directory:
        output_directory = os.getcwd()

    client = session.client("ec2")
    for asset_id in asset_ids:
        logging.info(
            "Going to execute - %s for asset type - %s asset - %s",
            EC2Types.EC2.value,
            EC2TypeActions.ENFROCE_IMDSV2.value,
            asset_id
        )
        http_hope = (
            action_params["HttpPutResponseHopLimit"]
            if action_params and "HttpPutResponseHopLimit" in action_params
            else -1
        )
        roll_back = (
            action_params["rollBack"]
            if action_params and "rollBack" in action_params
            else False
        )
        state_path = (
            action_params["statePath"]
            if action_params and "statePath" in action_params
            else None
        )
        EC2Helper.do_imdsv2_action(
            client=client,
            asset_id=asset_id,
            dry_run=dry_run,
            http_hope=http_hope,
            roll_back=roll_back,
            state_path=state_path,
        )
    return {}


def _ec2_find_load_balancers_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This function is the implementation for security group actions
        :param session: boto3 session
        :param asset_ids: list of asset ids
        :param *unused: unused variables. If found, this will be freed from memory
        :return:
    """
    del dry_run  # remove unused parameters
    del action_params  # remove unused parameters
    del output_directory  # remove unused parameters
    return LoadBalancersHelper.find_load_balancers(session, asset_ids)


def _subnet_disable_public_ip_assignment_wrapper(
    session,
    dry_run,
    asset_ids,
    action_params,
    output_directory,
):
    """
        This is the subnet helper function to execute automation over AWS subnet using boto3 api
        :param session: boto3 session
        :param dry_run: Boolean flag to mark if this is dry run or not
        :param asset_ids: list of asset ids
        :param action_params: action params of automation
        :param output_directory: unused variables. If found, this will be freed from memory
        :return:
    """
    del output_directory  # remove unused parameters
    client = session.client("ec2")
    excluded_subnets = (
        action_params["excluded_subnets"]
        if action_params and "excluded_subnets" in action_params
        else None
    )
    roll_back = (
        action_params["rollBack"]
        if action_params and "rollBack" in action_params
        else None
    )

    return SubnetHelper.do_disable_public_ip_assignment(
        client=client,
        region=session.region_name,
        asset_ids=asset_ids,
        dry_run=dry_run,
        excluded_subnets=excluded_subnets,
        roll_back=roll_back,
    )


functions_mapping: dict[str, dict[str, Callable]] = {
    EC2Types.SNAPSHOT.value: {
        SnapshotTypeActions.DELETE.value: _snapshot_delete_wrapper,
        SnapshotTypeActions.LIST.value: _snapshot_list_wrapper,
        SnapshotTypeActions.ENCRYPT.value: _snapshot_encrypt_wrapper,
    },
    EC2Types.SG.value: {
        SecurityGroupTypeActions.CLEAN_UNUSED_SG.value: _sg_clean_unused_sg_wrapper,
        SecurityGroupTypeActions.DELETE.value: _sg_delete_wrapper,
        SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value: _sg_get_all_flow_logs_wrapper,
        SecurityGroupTypeActions.GET_USAGE.value: _sg_get_usage_wrapper,
        SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value: _remove_or_replace_rules_wrapper,
    },
    EC2Types.VPC.value: {
        VPCTypeActions.CREATE_FLOW_LOG.value: _vpc_create_flow_log_wrapper,
    },
    EC2Types.EC2.value: {
        EC2TypeActions.GET_IMDSV1_USAGE.value: _ec2_get_imdsv1_usage_wrapper,
        EC2TypeActions.ENFROCE_IMDSV2.value: _ec2_enforce_imdsv2_wrapper,
        EC2TypeActions.FIND_LOAD_BALANCERS.value: _ec2_find_load_balancers_wrapper,
    },
    EC2Types.SUBNET.value: {
        SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value:
            _subnet_disable_public_ip_assignment_wrapper,
    },
}
help_mappings: dict[str, dict[str, dict]] = {
    EC2Types.SNAPSHOT.value: {
        SnapshotTypeActions.DELETE.value: snapshot_delete_readme_data.get("cli_args", dict()),
        SnapshotTypeActions.LIST.value: snapshot_ls_readme_data.get("cli_args", dict()),
        SnapshotTypeActions.ENCRYPT.value: snapshot_encrypt_readme_data.get("cli_args", dict()),
    },
    EC2Types.SG.value: {
        SecurityGroupTypeActions.CLEAN_UNUSED_SG.value: security_group_clean_unused_sg_readme_data.get("cli_args", dict()),
        SecurityGroupTypeActions.DELETE.value: security_group_delete_readme_data.get("cli_args", dict()),
        SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value: security_group_get_all_flow_logs_readme_data.get("cli_args", dict()),
        SecurityGroupTypeActions.GET_USAGE.value: security_group_get_usage_readme_data.get("cli_args", dict()),
        SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value: security_group_remove_or_replace_rules_readme_data.get("cli_args", dict()),
    },
    EC2Types.VPC.value: {
        VPCTypeActions.CREATE_FLOW_LOG.value: vpc_create_flow_log_readme_data.get("cli_args", {}),
    },
    EC2Types.EC2.value: {
        EC2TypeActions.GET_IMDSV1_USAGE.value: ec2_get_imdsv1_usage_readme_data.get("cli_args", dict()),
        EC2TypeActions.ENFROCE_IMDSV2.value: ec2_enforce_imdsv2_readme_data.get("cli_args", dict()),
        EC2TypeActions.FIND_LOAD_BALANCERS.value: ec2_find_load_balancers_readme_data.get("cli_args", dict()),
    },
    EC2Types.SUBNET.value: {
        SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value: subnet_disable_public_ip_assignment_readme_data.get("cli_args", dict()),
    },
}

if not help_mappings:
    help_mappings = dict()


def common_args(
    parser: Union[ArgumentParser, _ArgumentGroup],
    args_json_data: dict,
    has_dry_run: bool = True
):
    """adds common arguments to the parser"""
    parser.add_argument(
        "--profile",
        required=False,
        default=None,
        metavar="",
        help=args_json_data.get("profile"),
    )
    parser.add_argument(
        "--awsAccessKey",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsAccessKey"),
    )
    parser.add_argument(
        "--awsSecret",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsSecret"),
    )
    parser.add_argument(
        "--awsSessionToken",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsSessionToken"),
    )
    parser.add_argument(
        "--regions",
        required=False,
        metavar="",
        type=str,
        default="all",
        help=args_json_data.get("regions"),
    )
    parser.add_argument(
        "--file",
        required=False,
        metavar="",
        type=str,
        default=None,
        help=args_json_data.get("file"),
    )

    parser.add_argument(
        "--logLevel",
        required=False,
        choices=["INFO", "DEBUG", "WARN", "ERROR"],
        metavar="",
        type=str,
        default="INFO",
        help=args_json_data.get("logLevel"),
    )
    parser.add_argument(
        "--outputType",
        required=False,
        metavar="",
        type=str,
        default="json",
        help=args_json_data.get("outputType"),
    )
    parser.add_argument(
        "--outDir",
        required=False,
        metavar="",
        type=str,
        default=os.getcwd(),
        help=args_json_data.get("outDir"),
    )
    parser.add_argument(
        "--testId",
        required=False,
        metavar="",
        type=str,
        help=args_json_data.get("testId"),
    )
    if has_dry_run:
        parser.add_argument(
            "--dryRun",
            required=False,
            action="store_true",
            default=False,
            help=args_json_data.get("dryRun"),
        )


def snapshot_args_parser(snapshot_type_parser: ArgumentParser):
    """ adds snapshot parser & subparser """
    # define snapshot actions parsers here
    # metavar=" or ".join(
    #     [value.value for value in SnapshotTypeActions])
    snapshot_action_subparser = snapshot_type_parser.add_subparsers(
        title="action",
        metavar="",
        dest="action",
        description=utils.type_help(
            {
                SnapshotTypeActions.DELETE.value: snapshot_delete_readme_data.get(
                    "help", ""),
                SnapshotTypeActions.ENCRYPT.value: snapshot_encrypt_readme_data.get(
                    "help", ""),
                SnapshotTypeActions.LIST.value: snapshot_ls_readme_data.get(
                    "help", "")
            })
    )
    # define snapshot actions parsers here
    snapshot_type_delete_action_parser = snapshot_action_subparser.add_parser(
        SnapshotTypeActions.DELETE.value,
        # help=snapshot_delete_readme_data.get("help"),
        description=snapshot_delete_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter

    )
    snapshot_type_list_action_parser = snapshot_action_subparser.add_parser(
        SnapshotTypeActions.LIST.value,
        # help=snapshot_ls_readme_data.get("help"),
        description=snapshot_ls_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    snapshot_type_encrypt_action_parser = snapshot_action_subparser.add_parser(
        SnapshotTypeActions.ENCRYPT.value,
        # help=snapshot_encrypt_readme_data.get('help'),
        description=snapshot_encrypt_readme_data.get('help'),
        formatter_class=RawTextHelpFormatter
    )

    # define snapshot delete action arguments here
    snapshot_type_delete_action_group = (
        snapshot_type_delete_action_parser.add_argument_group(
            SnapshotTypeActions.DELETE.value
        )
    )
    common_args(snapshot_type_delete_action_group,
                snapshot_delete_readme_data.get("cli_args", dict()))
    snapshot_type_delete_action_group.add_argument(
        '--assetIds',
        required=True,
        metavar="",
        type=str,
        help=snapshot_delete_readme_data.get(
            "cli_args", dict()).get("assetIds"),
    )

    # define snapshot list action arguments here
    snapshot_type_list_action_group = (
        snapshot_type_list_action_parser.add_argument_group(
            SnapshotTypeActions.LIST.value
        )
    )
    common_args(snapshot_type_list_action_group,
                snapshot_ls_readme_data.get("cli_args", dict()),
                False)

    # define snapshot encrypt action arguments here
    snapshot_type_encrypt_action_group = (
        snapshot_type_encrypt_action_parser.add_argument_group(
            SnapshotTypeActions.ENCRYPT.value
        )
    )
    common_args(snapshot_type_encrypt_action_group,
                snapshot_encrypt_readme_data.get("cli_args", dict()))
    snapshot_type_encrypt_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=snapshot_encrypt_readme_data.get(
            "cli_args", dict()).get("assetIds"),
    )
    snapshot_type_encrypt_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.SNAPSHOT.value][
            SnapshotTypeActions.ENCRYPT.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )


def sg_args_parser(sg_type_parser: ArgumentParser):
    """ adds security groups parser & subparser """
    # define sg actions parsers here
    # metavar=" or ".join(
    #     [value.value for value in SecurityGroupTypeActions])
    sg_action_subparser = sg_type_parser.add_subparsers(
        title="action", metavar="", dest="action", description=utils.type_help(
            {
                SecurityGroupTypeActions.CLEAN_UNUSED_SG.value: snapshot_encrypt_readme_data.get(
                    "help", ""),
                SecurityGroupTypeActions.DELETE.value: snapshot_delete_readme_data.get(
                    "help", ""),
                SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value: snapshot_ls_readme_data.get(
                    "help", ""),
                SecurityGroupTypeActions.GET_USAGE.value: snapshot_ls_readme_data.get(
                    "help", ""),
                SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value: snapshot_ls_readme_data.get(
                    "help", "")
            })
    )
    # define sg actions parsers here
    sg_type_delete_action_parser = sg_action_subparser.add_parser(
        SecurityGroupTypeActions.DELETE.value,
        # help="delete sg",
        description=security_group_delete_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    sg_type_clean_unused_sg_action_parser = sg_action_subparser.add_parser(
        SecurityGroupTypeActions.CLEAN_UNUSED_SG.value,
        # help="clean unused sg of sg",
        description=security_group_clean_unused_sg_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    sg_type_get_all_flow_logs_action_parser = sg_action_subparser.add_parser(
        SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value,
        # help="get all flow logs of sg",
        description=security_group_get_all_flow_logs_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    sg_type_get_usage_action_parser = sg_action_subparser.add_parser(
        SecurityGroupTypeActions.GET_USAGE.value,
        # help="get usage of sg",
        description=security_group_get_usage_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    sg_type_remove_or_replace_rules_action_parser = sg_action_subparser.add_parser(
        SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value,
        # help="remove or replace rules of sg",
        description=security_group_remove_or_replace_rules_readme_data.get(
            "help"),
        formatter_class=RawTextHelpFormatter
    )

    # define sg delete action arguments here
    sg_type_delete_action_group = (
        sg_type_delete_action_parser.add_argument_group(
            SecurityGroupTypeActions.DELETE.value
        )
    )
    common_args(sg_type_delete_action_group,
                help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.DELETE.value])
    sg_type_delete_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=help_mappings[EC2Types.SG.value][
            SecurityGroupTypeActions.DELETE.value
        ].get("assetIds"),
    )

    # define sg list action arguments here
    sg_type_clean_unused_sg_action_group = (
        sg_type_clean_unused_sg_action_parser.add_argument_group(
            SecurityGroupTypeActions.CLEAN_UNUSED_SG.value
        )
    )
    common_args(sg_type_clean_unused_sg_action_group,
                help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.CLEAN_UNUSED_SG.value])
    sg_type_clean_unused_sg_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.SG.value][
            SecurityGroupTypeActions.CLEAN_UNUSED_SG.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )

    # define sg get all flow logs action arguments here
    sg_type_get_all_flow_logs_action_group = (
        sg_type_get_all_flow_logs_action_parser.add_argument_group(
            SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value
        )
    )
    common_args(sg_type_get_all_flow_logs_action_group,
                help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value],
                False)
    sg_type_get_all_flow_logs_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        default="all",
        help=help_mappings[EC2Types.SG.value][
            SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value
        ].get("assetIds"),
    )
    sg_type_get_all_flow_logs_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.SG.value][
            SecurityGroupTypeActions.GET_ALL_FLOW_LOGS.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )

    # define sg get usage action arguments here
    sg_type_get_usage_action_group = (
        sg_type_get_usage_action_parser.add_argument_group(
            SecurityGroupTypeActions.GET_USAGE.value
        )
    )
    common_args(sg_type_get_usage_action_group,
                help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.GET_USAGE.value],
                False)
    sg_type_get_usage_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.GET_USAGE.value].get(
            "assetIds"),
    )
    sg_type_get_usage_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.GET_USAGE.value].get(
            "actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )

    # define sg remove or replace rules action arguments here
    sg_type_remove_or_replace_rules_action_group = (
        sg_type_remove_or_replace_rules_action_parser.add_argument_group(
            SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value
        )
    )
    common_args(sg_type_remove_or_replace_rules_action_group,
                help_mappings[EC2Types.SG.value][SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value])
    sg_type_remove_or_replace_rules_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=help_mappings[EC2Types.SG.value][
            SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value
        ].get("assetIds"),
    )
    sg_type_remove_or_replace_rules_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.SG.value][
            SecurityGroupTypeActions.REMOVE_OR_REPLACE_RULES.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )


def vpc_args_parser(vpc_type_parser: ArgumentParser):
    """ adds vpc parser & subparser """
    # define vpc actions parsers here
    # metavar=" or ".join(
    #     [value.value for value in SecurityGroupTypeActions])
    vpc_action_subparser = vpc_type_parser.add_subparsers(
        title="action", metavar="", dest="action", description=utils.type_help(
            {
                VPCTypeActions.CREATE_FLOW_LOG.value: vpc_create_flow_log_readme_data.get(
                    "help", "")
            })
    )
    # define vpc actions parsers here
    vpc_type_create_flow_log_action_parser = vpc_action_subparser.add_parser(
        VPCTypeActions.CREATE_FLOW_LOG.value,
        # help="create flow log in vpc",
        description=vpc_create_flow_log_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    # define vpc create flow logs action arguments here
    vpc_type_create_flow_log_action_group = (
        vpc_type_create_flow_log_action_parser.add_argument_group(
            VPCTypeActions.CREATE_FLOW_LOG.value
        )
    )
    common_args(vpc_type_create_flow_log_action_group,
                help_mappings[EC2Types.VPC.value][VPCTypeActions.CREATE_FLOW_LOG.value])
    vpc_type_create_flow_log_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.VPC.value][
            VPCTypeActions.CREATE_FLOW_LOG.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )


def ec2_args_parser(ec2_type_parser: ArgumentParser):
    """ adds ec2 parser & subparser """
    # define ec2 type parser here
    # metavar=" or ".join(
    #     [value.value for value in EC2TypeActions])
    ec2_action_subparser = ec2_type_parser.add_subparsers(
        title="action", metavar="", dest="action", description=utils.type_help(
            {
                EC2TypeActions.GET_IMDSV1_USAGE.value: ec2_get_imdsv1_usage_readme_data.get(
                    "help", ""),
                EC2TypeActions.ENFROCE_IMDSV2.value: ec2_enforce_imdsv2_readme_data.get(
                    "help", ""),
                EC2TypeActions.FIND_LOAD_BALANCERS.value: ec2_find_load_balancers_readme_data.get(
                    "help", "")

            })
    )
    # define ec2 actions parsers here
    ec2_type_get_imdsv1_usage_action_parser = ec2_action_subparser.add_parser(
        EC2TypeActions.GET_IMDSV1_USAGE.value,
        # help="get imdsv1 usage",
        description=ec2_get_imdsv1_usage_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    ec2_type_enforce_imdsv2_action_parser = ec2_action_subparser.add_parser(
        EC2TypeActions.ENFROCE_IMDSV2.value,
        # help="enforce imdsv2",
        description=ec2_enforce_imdsv2_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )
    ec2_type_find_load_balancers_action_parser = ec2_action_subparser.add_parser(
        EC2TypeActions.FIND_LOAD_BALANCERS.value,
        # help="find load balancers",
        description=ec2_find_load_balancers_readme_data.get("help"),
        formatter_class=RawTextHelpFormatter
    )

    # define ec2 get imdsv1 usage action arguments here
    ec2_type_get_imdsv1_usage_action_group = (
        ec2_type_get_imdsv1_usage_action_parser.add_argument_group(
            EC2TypeActions.GET_IMDSV1_USAGE.value
        )
    )
    common_args(ec2_type_get_imdsv1_usage_action_group,
                help_mappings[EC2Types.EC2.value][EC2TypeActions.GET_IMDSV1_USAGE.value],
                False)
    ec2_type_get_imdsv1_usage_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.EC2.value][
            EC2TypeActions.GET_IMDSV1_USAGE.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )
    ec2_type_get_imdsv1_usage_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=help_mappings[EC2Types.EC2.value][
            EC2TypeActions.GET_IMDSV1_USAGE.value
        ].get("assetIds"),
        default="all"
    )

    # define ec2 enforce imdsv2 action arguments here
    ec2_type_enforce_imdsv2_action_group = (
        ec2_type_enforce_imdsv2_action_parser.add_argument_group(
            EC2TypeActions.ENFROCE_IMDSV2.value
        )
    )
    common_args(ec2_type_enforce_imdsv2_action_group,
                help_mappings[EC2Types.EC2.value][EC2TypeActions.ENFROCE_IMDSV2.value])
    ec2_type_enforce_imdsv2_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.EC2.value][EC2TypeActions.ENFROCE_IMDSV2.value].get(
            "actionParams"
        ),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )
    ec2_type_enforce_imdsv2_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=help_mappings[EC2Types.EC2.value][
            EC2TypeActions.ENFROCE_IMDSV2.value
        ].get("assetIds"),
        default="all"
    )

    # define ec2 find load balancers action arguments here
    ec2_type_find_load_balancers_action_group = (
        ec2_type_find_load_balancers_action_parser.add_argument_group(
            EC2TypeActions.FIND_LOAD_BALANCERS.value
        )
    )
    common_args(ec2_type_find_load_balancers_action_group,
                help_mappings[EC2Types.EC2.value][EC2TypeActions.FIND_LOAD_BALANCERS.value],
                False)
    ec2_type_find_load_balancers_action_group.add_argument(
        '--assetIds',
        required=False,
        metavar="",
        type=str,
        help=help_mappings[EC2Types.EC2.value][
            EC2TypeActions.FIND_LOAD_BALANCERS.value
        ].get("assetIds"),
        default="all",
    )


def subnet_args_parser(subnet_type_parser: ArgumentParser):
    """ adds subnet parser & subparser """
    # define subnet actions parsers here
    # metavar=" or ".join(
    #     [value.value for value in SecurityGroupTypeActions])
    subnet_action_subparser = subnet_type_parser.add_subparsers(
        title="action", metavar="", dest="action", description=utils.type_help(
            {
                SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value: subnet_disable_public_ip_assignment_readme_data.get(
                    "help", "")
            })
    )
    # define subnet actions parsers here
    subnet_type_disable_public_ip_assignment_action_parser = subnet_action_subparser.add_parser(
        SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value,
        # help="disable public ip assignment in subnet",
        description=subnet_disable_public_ip_assignment_readme_data.get(
            "help"),
        formatter_class=RawTextHelpFormatter
    )
    # define subnet create flow logs action arguments here
    subnet_type_disable_public_ip_assignment_action_group = (
        subnet_type_disable_public_ip_assignment_action_parser.add_argument_group(
            SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value
        )
    )
    common_args(subnet_type_disable_public_ip_assignment_action_group,
                help_mappings[EC2Types.SUBNET.value][SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value])
    subnet_type_disable_public_ip_assignment_action_group.add_argument(
        "--actionParams",
        required=False,
        help=help_mappings[EC2Types.SUBNET.value][
            SubnetTypeActions.DISABLE_PUBLIC_IP_ASSIGNMENT.value
        ].get("actionParams"),
        metavar="",
        type=utils.TypeActionParams,
        default=dict(),
    )


def main(argv: list = []):
    """
    main function
    """

    parser_usage = common_json_data.get("usage", dict()).get("EC2Actions", "")
    usage = parser_usage + " [-h]"
    if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
        utils.print_help_valid_types(
            common_json_data.get("help", dict()).get(
                "EC2Actions", dict()), usage
        )
        sys.exit(1)

    parser = ArgumentParser(
        usage=parser_usage,
        conflict_handler="resolve",
    )
    type_subparser = parser.add_subparsers(
        title="type", help="choose ec2 automation type", dest="type",
    )

    # define asset type parsers here
    snapshot_type_parser = type_subparser.add_parser(
        name=EC2Types.SNAPSHOT.value, description=common_json_data.get(
            "help", {}).get('EC2Actions', {}).get(EC2Types.SNAPSHOT.value),
        formatter_class=RawTextHelpFormatter
    )
    snapshot_args_parser(
        snapshot_type_parser=snapshot_type_parser)
    # define asset type parsers here
    sg_type_parser = type_subparser.add_parser(
        name=EC2Types.SG.value, description=common_json_data.get(
            "help", {}).get('EC2Actions', {}).get(EC2Types.SG.value),
        formatter_class=RawTextHelpFormatter
    )
    sg_args_parser(sg_type_parser=sg_type_parser)
    # define asset type parsers here
    vpc_type_parser = type_subparser.add_parser(
        name=EC2Types.VPC.value, description=common_json_data.get(
            "help", {}).get('EC2Actions', {}).get(EC2Types.VPC.value),
        formatter_class=RawTextHelpFormatter
    )
    vpc_args_parser(vpc_type_parser=vpc_type_parser)
    # define asset type parsers here
    ec2_type_parser = type_subparser.add_parser(
        name=EC2Types.EC2.value, description=common_json_data.get(
            "help", {}).get('EC2Actions', {}).get(EC2Types.EC2.value),
        formatter_class=RawTextHelpFormatter
    )
    ec2_args_parser(ec2_type_parser=ec2_type_parser)
    # define asset type parsers here
    subnet_type_parser = type_subparser.add_parser(
        name=EC2Types.SUBNET.value, description=common_json_data.get(
            "help", {}).get('EC2Actions', {}).get(EC2Types.SUBNET.value),
        formatter_class=RawTextHelpFormatter
    )
    subnet_args_parser(subnet_type_parser=subnet_type_parser)

    cli_args = parser.parse_args(argv[1:])
    params = utils.build_params(args=cli_args)
    if not params:
        print(sys.exc_info())
        exit(0)

    result = dict()
    try:
        asset_type = cli_args.type
        asset_action = cli_args.action
        profile = params.get(
            "profile") if cli_args.file is not None else params.profile
        aws_access_key = params.get(
            "awsAccessKey") if cli_args.file is not None else params.awsAccessKey
        aws_secret = params.get(
            "awsSecret") if cli_args.file is not None else params.awsSecret
        aws_session_token = params.get(
            "awsSessionToken") if cli_args.file is not None else params.awsSessionToken
        dry_run = params.get(
            "dryRun") if cli_args.file is not None else params.dryRun
        log_level = params.get(
            "logLevel") if cli_args.file is not None else params.logLevel

        asset_ids = params.get("assetIds", ["all"]) if cli_args.file is not None else str(
            params.assetIds).split(",")
        action_params = params.get(
            'actionParams', None) if cli_args.file is not None else params.actionParams

        action_params = json.loads(action_params) if action_params and not isinstance(
            action_params, dict) else params.get('actionParams', None)

        regions = ",".join(
            params.get('regions', ['all'])
        ) if cli_args.file is not None else str(params.regions)

        output_type = params.get(
            "outputType", "JSON") if cli_args.file is not None else str(params.outputType)
        output_directory = params.get(
            "outDir", "") if cli_args.file is not None else str(params.outDir)
        test_id = params.get(
            "testId", None) if cli_args.file is not None else str(params.testId)
        if test_id is not None:
            result['testId'] = test_id

        utils.log_setup(log_level)
        logging.debug("python3 -m Automatios.EC2Actions %s",
                      " ".join(sys.argv[1:]))
        logging.debug(params)
        fn: Callable = functions_mapping[str(asset_type)][str(asset_action)]

        if regions:
            logging.info("Going to run over %s - region", regions)
            # in case that regions parameter is set , assume that we want to enable all vpc flow logs inside the region
            session = utils.setup_session(
                profile=profile,
                aws_access_key=aws_access_key,
                aws_secret=aws_secret,
                aws_session_token=aws_session_token
            )
            caller_identity = utils.get_caller_identity(session=session)
            result['caller-identity'] = caller_identity

            list_of_regions = utils.get_regions(
                regions_param=regions, session=session)
            for region in list_of_regions:
                logging.info("Working on Region - %s", region)
                session = utils.setup_session(
                    profile=profile,
                    region=region,
                    aws_access_key=aws_access_key,
                    aws_secret=aws_secret,
                    aws_session_token=aws_session_token
                )
                action_result = fn(
                    session=session,
                    dry_run=dry_run,
                    asset_ids=asset_ids,
                    action_params=action_params,
                    output_directory=params.outDir
                )
                if action_result:
                    result[region] = action_result
                else:
                    result[region] = {}
        else:
            session = utils.setup_session(
                profile=profile,
                aws_access_key=aws_access_key,
                aws_secret=aws_secret,
                aws_session_token=aws_session_token
            )
            caller_identity = utils.get_caller_identity(session=session)
            result['caller-identity'] = caller_identity
            logging.info(
                "Going to run over the default - %s - region", session.region_name)
            action_result = fn(
                session=session,
                dry_run=dry_run,
                asset_ids=asset_ids,
                action_params=action_params,
                output_directory=params.outDir
            )
            if action_result:
                result[session.region_name] = action_result
            else:
                result[session.region_name] = {}
    except Exception as e:
        logging.error("Something Went wrong!!", exc_info=log_level == "DEBUG")
        result['status'] = 'Error'
        result['message'] = str(e)

    result_type = "dryrun" if dry_run else "execution"

    if params.testId:
        result["testId"] = params.testId

    if not output_directory.endswith("/"):
        output_directory = str(output_directory) + "/"
    result["stateFile"] = utils.export_data_filename_with_timestamp(
        f"{output_directory}Tamnoon-Azure-Storage-{asset_type if asset_type is not None else ''}-{asset_action.replace('_', '-') if asset_action is not None else ''}-{result_type}-result",
        output_type,
    )
    utils.export_data_(
        result["stateFile"],
        result,
        export_format=output_type,
    )
    print()
    print(f"find logs in {os.path.abspath(result['stateFile'])}")


if __name__ == "__main__":
    main(sys.argv)
