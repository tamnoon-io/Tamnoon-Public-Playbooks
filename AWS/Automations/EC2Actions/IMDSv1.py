from time import sleep
from datetime import datetime, timedelta

import base64
import logging
import boto3

from Automations.Utils import utils as utils


def find_all_ec2_instance_ids(ec2_client: boto3.Session.client) -> list:
    paginator = ec2_client.get_paginator("describe_instances")
    pagination = paginator.paginate(PaginationConfig={"PageSize": 1000})
    instances = pagination.build_full_result()
    sleep(0.5)

    obj = dict()
    for reservation in list(instances["Reservations"]):
        for instance in reservation["Instances"]:
            obj[instance["InstanceId"]] = instance["KeyName"]
    return obj


def get_images_data(ec2_client, instance_ids):
    paginator = ec2_client.get_paginator("describe_instances")
    pagination = paginator.paginate(PaginationConfig={"PageSize": 1000})
    instances = pagination.build_full_result()
    sleep(0.5)

    obj = dict()
    for reservation in list(instances["Reservations"]):
        for instance in reservation["Instances"]:
            if instance["InstanceId"] in instance_ids:
                ami_info = ec2_client.describe_images(ImageIds=[instance["ImageId"]])
                # Extract the AMI version from the image description or name
                obj[instance["InstanceId"]] = {
                    "ImageId": instance["ImageId"],
                    "ImageName": ami_info["Images"][0]["Name"],
                    "ImageDescription": ami_info["Images"][0]["Description"],
                }

    return obj


def get_user_data(ec2_client, instance_ids):
    user_data = {}
    for instance_id in instance_ids:
        response = ec2_client.describe_instance_attribute(
            InstanceId=instance_id, Attribute="userData"
        )
        if (
            "UserData" in response
            and response["UserData"]
            and "Value" in response["UserData"]
        ):
            user_data[instance_id] = base64.b64decode(response["UserData"]["Value"])
            try:
                user_data[instance_id] = user_data[instance_id].decode("UTF-8")
            except Exception as ex:
                user_data[instance_id] = str(user_data[instance_id])
                logging.info(
                    "Could not decode userdata to UTF-8. Keeping its raw format.",
                    exc_info=True,
                )
        else:
            user_data[instance_id] = None
            logging.info("Userdata not found.")
    return user_data


def find_imdsv1_usage(
    session,
    dry_run=True,
    asset_ids=["all"],
    days=14,
    duration_end_time=None,
    statistics_type="Sum",
    metric_type="MetadataNoToken",
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
        metric = cloudwatch_resource.Metric("AWS/EC2", metric_type)

        ec2_instances_list = find_all_ec2_instance_ids(ec2_client)
        if len(ec2_instances_list) == 0:
            return "ec2 instances not found in this region"

        is_all_asset_ids = asset_ids == ["all"]

        if is_all_asset_ids:
            asset_ids = ec2_instances_list.keys()

        skip_asset_ids = []
        for asset_id in asset_ids:
            if is_all_asset_ids or ec2_instances_list.keys().__contains__(asset_id):
                continue
            else:
                metrics_summary[asset_id] = {
                    f"{statistics_type}Of{metric_type}Metrics": 0,
                    "message": "ec2 instance not found in this region",
                }
                skip_asset_ids.append(asset_id)

        asset_ids = list(asset_ids)
        for skip_asset_id in skip_asset_ids:
            asset_ids.remove(skip_asset_id)

        images = get_images_data(ec2_client, asset_ids)
        user_data = get_user_data(ec2_client, asset_ids)
        for instance in asset_ids:
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
                metrics_summary[instance] = {
                    "InstanceName": ec2_instances_list[instance],
                    "Image": images[instance],
                    "UserData": user_data[instance],
                    f"{statistics_type}Of{metric_type}Metrics": statistics_value,
                    "message": (
                        f"ec2 instance {instance} has {'not' if not statistics_value else ''} been using IMDSv1 during past {days} days"
                    ),
                }

    except Exception as ex:
        logging.info(f"Error in {region_name} region :  {str(ex)}", exc_info=True)

    for key in metrics_summary.keys():
        if key == "from" or key == "to":
            continue

        logging.info(metrics_summary[key]["message"])

    return metrics_summary
