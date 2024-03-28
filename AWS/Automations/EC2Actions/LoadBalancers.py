import logging


def get_all_ec2_instance_ids(session):
    """
    This function retrieves details of all EC2 instances available in the AWS account.

    :param session: boto3 session object
    :return: List of dictionaries containing instance IDs and their status
    """
    client = session.client("ec2")
    response = client.describe_instances()
    instance_ids = []
    ec2_instances = response["Reservations"]
    for ec2_instance in ec2_instances:
        for instance in ec2_instance["Instances"]:
            instance_ids.append(
                {
                    "instanceId": instance["InstanceId"],
                    "InstanceStatus": instance["State"]["Name"],
                }
            )

    return instance_ids


def get_ec2_instance_name(session, instance_id):
    """
    This function retrieves the name of the EC2 instance with the given instance_id available in the AWS account.

    :param session: boto3 session object
    :param instance_id: EC2 instance_id
    :return: Name of the EC2 instance, or '-' if not found
    """
    ec2_client = session.client("ec2")
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if "Tags" not in instance:
                return ""
            for tag in instance["Tags"]:
                if tag["Key"] == "Name":
                    return tag["Value"]

    return None  # Return None if instance name tag is not found


def classic_ec2_instance_mapping_with_lb(session, asset_ids):
    """
    This function maps EC2 instance IDs with their associated classic load balancer type.

    :param session: boto3 session object
    :param asset_ids: EC2 instance IDs to be mapped with load balancers
    :return: Dictionary containing EC2 instance ids mapped with associated load balancers
    """
    client = session.client("elb")
    result = {}
    lb_data = client.describe_load_balancers()["LoadBalancerDescriptions"]
    for data in lb_data:
        listeners_info = []
        for listener in data["ListenerDescriptions"]:
            listeners_info.append(listener["Listener"])
        security_groups = data["SecurityGroups"]
        for instance_data in data["Instances"]:
            instance_id = instance_data["InstanceId"]
            if instance_id in asset_ids:
                if instance_id not in result:
                    result[instance_id] = [
                        {
                            "load_balancer_name": data["LoadBalancerName"],
                            "type": "classic",
                            "listeners": listeners_info,
                            "security_groups": security_groups,
                        }
                    ]
                else:
                    result[instance_id].append(
                        {
                            "load_balancer_name": data["LoadBalancerName"],
                            "type": "classic",
                            "listeners": listeners_info,
                            "security_groups": security_groups,
                        }
                    )

    return result


def non_classic_ec2_instance_mapping_with_lb(session, asset_ids):
    """
    This function maps EC2 instance IDs with their associated non-classic(application,network and gateway) load balancer type.

    :param session: non-classic load balancer type boto3 client
    :param asset_ids: EC2 instance IDs to be mapped with load balancers
    :return: Dictionary containing EC2 instance IDs mapped with associated load balancers
    """
    client = session.client("elbv2")
    result = {}
    lb_response = client.describe_load_balancers()["LoadBalancers"]
    for lb_data in lb_response:
        lb_arn = lb_data["LoadBalancerArn"]
        lb_name = lb_data["LoadBalancerName"]
        lb_type = lb_data["Type"]

        # Get Security Groups for the specified load balancer
        security_groups = ""
        if "SecurityGroups" in lb_data:
            security_groups = lb_data["SecurityGroups"]

        # Get listeners for the specified load balancer
        response_listeners = client.describe_listeners(LoadBalancerArn=lb_arn)
        listeners = response_listeners["Listeners"]
        listeners_info = []
        for listener in listeners:
            listeners_info.append(
                {
                    "ListenerArn": listener.get("ListenerArn"),
                    "Port": listener.get("Port"),
                    "Protocol": listener.get("Protocol"),
                }
            )
        # Retrieve the target groups associated with the load balancer
        target_groups_response = client.describe_target_groups(LoadBalancerArn=lb_arn)
        # Iterate through each target group associated with the load balancer
        for target_group in target_groups_response["TargetGroups"]:
            target_group_arn = target_group["TargetGroupArn"]

            # Retrieve targets (EC2 instances) registered with the target group
            targets_response = client.describe_target_health(
                TargetGroupArn=target_group_arn
            )
            target_groups_info = {
                "TargetGroupArn": target_group["TargetGroupArn"],
                "TargetGroupName": target_group["TargetGroupName"],
                "Protocol": target_group["Protocol"],
                "port": target_group["Port"],
            }
            # Extract instance IDs from the targets
            for target in targets_response["TargetHealthDescriptions"]:
                instance_id = target["Target"]["Id"]
                port = target["Target"]["Port"]
                if instance_id in asset_ids:
                    if instance_id not in result:
                        if security_groups != "":
                            result[instance_id] = [
                                {
                                    "LoadBalancerArn": lb_arn,
                                    "load_balancer_name": lb_name,
                                    "type": lb_type,
                                    "port": port,
                                    "target_groups": target_groups_info,
                                    "security_groups": security_groups,
                                    "listeners": listeners_info,
                                }
                            ]
                        else:
                            result[instance_id] = [
                                {
                                    "LoadBalancerArn": lb_arn,
                                    "load_balancer_name": lb_name,
                                    "type": lb_type,
                                    "port": port,
                                    "target_groups": target_groups_info,
                                    "listeners": listeners_info,
                                }
                            ]
                    else:
                        if security_groups != "":
                            result[instance_id].append(
                                {
                                    "LoadBalancerArn": lb_arn,
                                    "load_balancer_name": lb_name,
                                    "type": lb_type,
                                    "port": port,
                                    "target_groups": target_groups_info,
                                    "security_groups": security_groups,
                                    "listeners": listeners_info,
                                }
                            )
                        else:
                            result[instance_id].append(
                                {
                                    "LoadBalancerArn": lb_arn,
                                    "load_balancer_name": lb_name,
                                    "type": lb_type,
                                    "port": port,
                                    "target_groups": target_groups_info,
                                    "listeners": listeners_info,
                                }
                            )
    return result


def find_load_balancers(
    session,
    asset_ids,
):
    if asset_ids is None:
        logging.error("assetIds (comma separated ec2 instance IDs or all) are required")
        exit(0)

    all_instance_ids = get_all_ec2_instance_ids(session)
    instance_ids = []
    for instance in all_instance_ids:
        instance_ids.append(instance["instanceId"])
    if asset_ids == ["all"]:
        asset_ids = instance_ids

    classic_lb_data = classic_ec2_instance_mapping_with_lb(session, asset_ids)
    non_classic_lb_data = non_classic_ec2_instance_mapping_with_lb(session, asset_ids)

    instance_lb_mapping_result = classic_lb_data
    for key in non_classic_lb_data:
        if key in classic_lb_data:
            instance_lb_mapping_result[key].extend(non_classic_lb_data[key])
        else:
            instance_lb_mapping_result[key] = non_classic_lb_data[key]

    final_result = {
        "running": {},
        "stopped": {},
        "pending": {},
        "terminated": {},
        "stopping": {},
        "shutting_down": {},
    }
    for instance_data in all_instance_ids:
        instance_status = instance_data["InstanceStatus"]
        instance_id = instance_data["instanceId"]
        if instance_id in instance_lb_mapping_result:
            final_result[instance_status][instance_id] = instance_lb_mapping_result[
                instance_id
            ]
        else:
            final_result[instance_status][instance_id] = {}

    for state in final_result:
        display_state_message = True
        display_lb_message = True
        instance_data = final_result[state]
        for instance_id in instance_data:
            if instance_id in asset_ids:
                lb_data = [
                    lb["load_balancer_name"] + "({})".format(lb["type"])
                    for lb in instance_data[instance_id]
                ]
                instance_name = get_ec2_instance_name(session, instance_id)
                if display_state_message:
                    logging.info(f"Working on Instances State - {state}")
                    display_state_message = False
                if lb_data:
                    if display_lb_message:
                        logging.info("EC2 Instance: Load Balancers")
                        display_lb_message = False
                    logging.info(
                        f"{instance_name}({instance_id}): {', '.join(lb_data)}"
                    )
                else:
                    logging.info(
                        f"EC2 instance {instance_name}({instance_id}) has no load balancers."
                    )

    absent_instance_ids = []
    for instance_id in asset_ids:
        if instance_id not in instance_ids:
            absent_instance_ids.append(instance_id)

    if absent_instance_ids:
        logging.info(
            "These Instance Ids are not found in Account: "
            + ", ".join(absent_instance_ids)
        )
    return final_result
