"""
VPCActions
"""

import logging
import botocore.exceptions


def get_vpcs_in_region(session):
    """
    This method return all the vpc ids inside the region
    :param session:
    :return list:
    """
    try:
        ec2_client = session.client("ec2")
        vpc_ids = []
        response = ec2_client.describe_vpcs()
        vpcs = response["Vpcs"]
        while "NextToken" in response:
            response = ec2_client.describe_vpcs(
                NextToken=response["NextToken"])
            vpcs = vpcs + response["Vpcs"]

        for vpc in vpcs:
            vpc_ids.append(vpc["VpcId"])

        return vpc_ids
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "AuthFailure":
            logging.warning(
                f"The region {session.region_name} doesn't support this action please do it via console"
            )
            return []


def do_create_flow_log(
    session, dry_run, asset_id, log_group_name=None, deliver_logs_permission_arn=None
):
    """
    This method return all the vpc ids inside the region
    :param session:
    :param dry_run:
    :param asset_id:
    :param log_group_name:
    :param deliver_logs_permission_arn:
    :return list:
    """
    ec2_client = session.client("ec2")

    describe_response = ec2_client.describe_flow_logs(
        Filters=[
            {"Name": "resource-id", "Values": [asset_id]},
        ],
    )

    if len(describe_response["FlowLogs"]) > 0:
        logging.info(
            f"No Need to create a vpc flow log for vpc - {asset_id} at region {session.region_name}, it's already exists"
        )
        return

    response = ec2_client.create_flow_logs(
        LogGroupName=log_group_name,
        ResourceIds=[asset_id],
        DeliverLogsPermissionArn=deliver_logs_permission_arn,
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        DryRun=dry_run
    )

    logging.info(f"Enable flow log done for - {asset_id}")
