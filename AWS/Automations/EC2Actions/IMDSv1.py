from time import sleep
from datetime import datetime, timedelta

import json
import boto3
import logging

from Automations.Utils import utils as utils


def find_all_ec2_instance_ids(ec2_client: boto3.Session.client) -> list:
    instance_list = []
    paginator = ec2_client.get_paginator("describe_instances")
    pagination = paginator.paginate(PaginationConfig={"PageSize": 1000})
    instances = pagination.build_full_result()
    # yield instances
    sleep(0.5)

    for reservation in list(instances["Reservations"]):
        for instance in reservation["Instances"]:
            instance_list.append(instance["InstanceId"])

    return instance_list


def find_imdsv1_usage(
    session,
    dry_run=True,
    asset_ids=["all"],
    days=14,
    duration_end_time=None,
    statistics_type="Sum",
):
    if days < 0:
        raise ValueError("days can not be negative number")
    if days == 0:
        raise ValueError("days can not be zero")
    if duration_end_time is None:
        raise ValueError("duration_end_time is required")
    if statistics_type not in ["SampleCount", "Average", "Sum", "Minimum", "Maximum"]:
        raise ValueError(
            f"statistics_type must be a value in the set [SampleCount, Average, Sum, Minimum, Maximum]"
        )
    duration_start_time = datetime.strptime(
        duration_end_time, "%a %b %d %H:%M:%S %Y"
    ) - timedelta(days=days)

    metrics_summary = dict()
    metrics_summary["from"] = duration_start_time.ctime()
    metrics_summary["to"] = duration_end_time
    region_name = session.region_name
    endpoint_url = f"https://ec2.{region_name}.amazonaws.com/"
    try:
        ec2_client = session.client(
            "ec2", region_name=region_name, endpoint_url=endpoint_url
        )
        cloudwatch_resource = session.resource("cloudwatch", region_name=region_name)
        cloudwatch_client = session.client("cloudwatch", region_name=region_name)
        metric = cloudwatch_resource.Metric("AWS/EC2", "MetadataNoToken")

        ec2_instance_ids = find_all_ec2_instance_ids(ec2_client)

        is_all_asset_ids = len(asset_ids) == 1 and asset_ids[0] == "all"

        if is_all_asset_ids:
            asset_ids = ec2_instance_ids

        skip_asset_ids = []
        for asset_id in asset_ids:
            if is_all_asset_ids or ec2_instance_ids.__contains__(asset_id):
                continue
            else:
                metrics_summary[asset_id] = {
                    statistics_type: 0,
                    "message": f"ec2 instance {asset_id} not found in region {region_name}",
                }
                skip_asset_ids.append(asset_id)

        for instance in asset_ids:
            if skip_asset_ids.__contains__(instance):
                continue
            stats = metric.get_statistics(
                Dimensions=[{"Name": "InstanceId", "Value": instance}],
                StartTime=duration_start_time,
                EndTime=duration_end_time,
                Period=(days * 24 * 60 * 60),
                Statistics=[statistics_type],
            )
            if stats["Datapoints"]:
                statistics_value = 0
                for datapoint in stats["Datapoints"]:
                    statistics_value = statistics_value + datapoint[statistics_type]
                if statistics_value > 0:
                    metrics_summary[instance] = {
                        statistics_type: statistics_value,
                        "message": (
                            f"ec2 instance {instance} has been using IMDSv1 during past {days} days"
                        ),
                    }
                else:
                    metrics_summary[instance] = {
                        statistics_type: 0,
                        "message": f"instance {instance} has not been using IMDSv1 during past {days} days",
                    }

    except Exception as ex:
        logging.info(f"Error in {region_name} region :  {str(ex)}", exc_info=True)

    for key in metrics_summary.keys():
        if key == "from" or key == "to":
            continue

        logging.info(metrics_summary[key]["message"])

    return metrics_summary
