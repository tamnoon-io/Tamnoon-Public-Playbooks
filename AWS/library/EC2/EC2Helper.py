"""
EC2ActionsHelper
"""

import json
from time import sleep
from datetime import datetime, timedelta
from typing import List

import base64
import logging
import boto3
import botocore.exceptions

from Automations.Utils import utils as utils


def parse_tags(tags):
    parsed_tags = dict()
    for tag in tags:
        parsed_tags.update({tag.get("Key"): tag.get("Value")})
    return parsed_tags


def get_imdsv1_details_of_ec2_instance(ec2_client: boto3.Session.client, instance_ids: List[str]):
    is_all_asset_ids = instance_ids == ["all"]

    paginator = ec2_client.get_paginator("describe_instances")
    pagination = paginator.paginate(PaginationConfig={"PageSize": 1000})
    instances = pagination.build_full_result()
    sleep(0.5)

    obj = dict()
    for reservation in list(instances["Reservations"]):
        for instance in reservation["Instances"]:
            if is_all_asset_ids or instance["InstanceId"] in instance_ids:
                instance_id = instance.get("InstanceId")
                tags = parse_tags(instance.get("Tags", []))
                instance_obj = {}
                # add instance name in obj
                instance_obj.update({"Name": tags.get("Name", "No Name")})

                image_id = instance.get("ImageId")
                ami_info = ec2_client.describe_images(
                    ImageIds=[image_id])
                images = ami_info.get("Images", [])
                if len(images) > 0:
                    image = images[0]
                    # Extract the AMI version from the image description or name
                    instance_obj.update({"image": {
                        "ImageId": image_id,
                        "ImageName": image.get("Name", "No Name"),
                        "ImageDescription": image.get("Description", "No Description"),
                        "CreationDate": image.get("CreationDate", "No Creation Date")
                    }})
                else:
                    instance_obj.update({"image": {
                        "ImageId": image_id,
                        "ImageName": "Not Found",
                        "ImageDescription": "Not Found",
                        "CreationDate": "Not Found"
                    }})

                    print(
                        f"could not find ami info on Instance {instance_id}")
                obj.update({instance_id: instance_obj})
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
            user_data[instance_id] = base64.b64decode(
                response["UserData"]["Value"])
            try:
                user_data[instance_id] = user_data[instance_id].decode("UTF-8")
            except Exception as ex:
                user_data[instance_id] = str(user_data[instance_id])
                logging.info(
                    "Could not decode userdata to UTF-8. Keeping its raw format.")
                logging.debug(ex)
        else:
            user_data[instance_id] = None
            logging.info("Userdata not found.")
    return user_data


def find_imdsv1_usage(
    session,
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
            "statistics_type must be a value in the set [SampleCount, Average, Sum, Minimum, Maximum]"
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
        cloudwatch_resource = session.resource(
            "cloudwatch", region_name=region_name)
        metric = cloudwatch_resource.Metric("AWS/EC2", metric_type)

        ec2_instances_details = get_imdsv1_details_of_ec2_instance(
            ec2_client, asset_ids)
        if len(ec2_instances_details) == 0:
            return "ec2 instances not found in this region"

        is_all_asset_ids = asset_ids == ["all"]

        if is_all_asset_ids:
            asset_ids = ec2_instances_details.keys()

        skip_asset_ids = []
        for asset_id in asset_ids:
            if is_all_asset_ids or ec2_instances_details.keys().__contains__(asset_id):
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

        user_data = get_user_data(ec2_client, asset_ids)
        for instance in asset_ids:
            stats = metric.get_statistics(
                Dimensions=[{"Name": "InstanceId", "Value": instance}],
                StartTime=duration_start_time,
                EndTime=duration_end_time,
                Period=(days * 24 * 60 * 60),
                Statistics=[statistics_type],
            )
            statistics_value = 0.0
            if stats["Datapoints"]:
                for datapoint in stats["Datapoints"]:
                    statistics_value = statistics_value + \
                        datapoint[statistics_type]
            ec2_instance_details = ec2_instances_details.get(
                instance, {})
            metrics_summary[instance] = {
                "InstanceName": ec2_instance_details.get("Name", f"Could not find info of Instance {instance}"),
                "Image": ec2_instance_details.get("image", f"Could not find ami info on Instance {instance}"),
                "UserData": user_data[instance] if instance in user_data else f"Could not find User Data info on Instance {instance}",
                f"{statistics_type}Of{metric_type}Metrics": statistics_value,
                "message": (
                    f"ec2 instance {instance} has {'not' if not statistics_value else ''} been using IMDSv1 during past {days} days"
                ),
            }

    except Exception as ex:
        logging.info(f"Error in {region_name} region :  {str(ex)}")

    for key in metrics_summary.keys():
        if key == "from" or key == "to":
            continue
        if key in metrics_summary and "message" in metrics_summary[key]:
            logging.info(metrics_summary[key]["message"])

    return metrics_summary


def do_imdsv2_action(client, asset_id, dry_run, http_hope, roll_back, state_path):
    """
    This function execute the IMDS versioning configuration for ec2 asset
    :param client:
    :param asset_id:
    :param dry_run:
    :param http_hope:
    :param roll_back:
    :param state_path:
    :return:
    """

    try:
        if roll_back:
            if not state_path:
                logging.error(
                    f"Can't rollback without having the previous state, no json file for state was delivered to the script"
                )
            else:
                with open(state_path, "r") as state_file:
                    state = json.load(state_file)
                    if asset_id in state:
                        instance = state[asset_id]
                        http_token = instance["HttpTokens"]
                        hope = instance["HttpPutResponseHopLimit"]
                        response = client.modify_instance_metadata_options(
                            InstanceId=asset_id,
                            HttpTokens="required",
                            HttpPutResponseHopLimit=http_hope,
                            DryRun=dry_run,
                        )
        else:
            # get teh current state of the asset and save it to the state file
            response = client.describe_instances(InstanceIds=[asset_id])
            metadata_options = response["Reservations"][0]["Instances"][0][
                "MetadataOptions"
            ]
            if os.path.exists(state_path):
                with open(state_path, "r") as state_file:
                    try:
                        state = json.load(state_file)
                    except json.JSONDecodeError:
                        state = dict()

            else:
                state = dict()

            state[asset_id] = {
                "HttpTokens": metadata_options["HttpTokens"],
                "HttpPutResponseHopLimit": metadata_options["HttpPutResponseHopLimit"],
            }
            json.dump(state, open(state_path, "w"))

            # in case http hope limit provided
            if http_hope > 0:
                response = client.modify_instance_metadata_options(
                    InstanceId=asset_id,
                    HttpTokens="required",
                    HttpPutResponseHopLimit=http_hope,
                    DryRun=dry_run,
                )
            # in case no http hope limit provided use the current state
            else:
                response = client.modify_instance_metadata_options(
                    InstanceId=asset_id, HttpTokens="required", DryRun=dry_run
                )

    except botocore.exceptions.ClientError as ce:
        if ce.response["Error"]["Code"] == "DryRunOperation":
            logging.warning(f"Dry run execution!!! nothing changed")

    except Exception as e:
        logging.error(f"Something went wrong with EC2 API !!")
        raise e
