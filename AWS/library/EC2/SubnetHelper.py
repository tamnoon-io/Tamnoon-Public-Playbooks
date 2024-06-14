
import logging
import re


def do_disable_public_ip_assignment(
    client, region, asset_ids, dry_run, excluded_subnets, roll_back
):
    """
    This function executing the logic of disabling the automated public ip assigment for subnet
    :param client:
    :param asset_ids:
    :param dry_run:
    :param excluded_subnets:
    :param roll_back:
    :return:
    """
    excluded_subnets_regex = None
    if excluded_subnets:
        excluded_subnets_regex = "|".join(
            [x.strip() for x in re.sub(",|;", " ", excluded_subnets).split()]
        )

    # Get all the potential subnets - list of all subnets in the region
    potential_subnets = list()
    subnets_resp = client.describe_subnets()
    potential_subnets = potential_subnets + subnets_resp["Subnets"]
    while "NextToken" in subnets_resp and subnets_resp["NextToken"]:
        subnets_resp = client.describe_subnets(
            NextToken=subnets_resp["NextToken"])
        potential_subnets = potential_subnets + subnets_resp["Subnets"]

    results = list()
    # Work for each subnet
    for subnet in potential_subnets:
        current_setting = subnet["MapPublicIpOnLaunch"]
        record = {
            "region": region,
            "vpcId": subnet["VpcId"],
            "subnetId": subnet["SubnetId"],
            "MapPublicIpOnLaunch": current_setting,
        }

        # Goin to check exclusion over subnet Name or Id
        tag_name = (
            subnet["Tags"]["Name"]
            if "Tags" in subnet and "Name" in subnet["Tags"]
            else None
        )

        # check if subnet should be excluded or not part of the provided subnets ids
        if (
            (
                excluded_subnets_regex
                and (
                    (tag_name and re.search(excluded_subnets_regex, tag_name))
                    or re.search(excluded_subnets_regex, subnet["SubnetId"])
                )
            )
            or asset_ids
            and subnet["SubnetId"] not in asset_ids
        ):
            logging.info(
                f"Subnet - {record['subnetId']} in Vpc - {record['vpcId']} at region - {record['region']} is excluded or not part of the provided subnets ids, going to skip this one"
            )
            record["actionResult"] = "SKIP"
        else:
            if not current_setting:
                # no setting on and this is not roll-back
                if not roll_back:
                    logging.info(
                        f"For Subnet - {record['subnetId']} in Vpc - {record['vpcId']} at region - {record['region']} public ip on lunch setting is off"
                    )
                    record["actionResult"] = "NO-NEED"
                else:
                    # roll-back -execution
                    logging.info(
                        f"Enabling auto-assign public IP for subnet {record['subnetId']} in VPC {record['vpcId']} in region {record['region']} - roll-back"
                    )
                    if dry_run:
                        logging.info(
                            "############## Dry Run ###################")
                        record["actionResult"] = "DRY-RUN: CHANGED"
                    else:
                        client.modify_subnet_attribute(
                            SubnetId=record["subnetId"],
                            MapPublicIpOnLaunch={"Value": True},
                        )
                        record["actionResult"] = "ROLL-BACK"

            else:
                if dry_run:
                    logging.info("############## Dry Run ###################")
                    record["actionResult"] = "DRY-RUN: CHANGED"
                    logging.info(
                        f"Disabling auto-assign public IP for subnet {record['subnetId']} in VPC {record['vpcId']} in region {record['region']}"
                    )
                else:
                    logging.info(
                        f"Disabling auto-assign public IP for subnet {record['subnetId']} in VPC {record['vpcId']} in region {record['region']}"
                    )
                    client.modify_subnet_attribute(
                        SubnetId=record["subnetId"],
                        MapPublicIpOnLaunch={"Value": False},
                    )
                    record["actionResult"] = "CHANGED"
        results.append(record)
    return results
