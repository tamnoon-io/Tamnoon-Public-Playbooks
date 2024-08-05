import os
import json
import logging
import boto3
import botocore
import botocore.exceptions

boto3.set_stream_logger("boto3", logging.ERROR)


def _get_reslut_by_api(d9key, d9secret):
    pass


def _load_from_file(result_file):
    with open(result_file, "r") as result_json:
        return json.load(result_json)


def _auth_ingress(permissions, sg_id, region_ec2_resource):
    security_group = region_ec2_resource.SecurityGroup(sg_id)
    security_group.authorize_ingress(IpPermissions=permissions)


def _auth_egress(permissions, sg_id, region_ec2_resource):
    security_group = region_ec2_resource.SecurityGroup(sg_id)
    security_group.authorize_egress(IpPermissions=permissions)


def _execute_rollback(region_session, region, sg_definition, output_result, sg_id=None):
    region_ec2_resource = region_session.resource("ec2")
    if not sg_id:
        for sg_id, permissions in sg_definition.items():
            output_result[sg_id] = dict()
            output_result[sg_id]["Ingress"] = dict()
            output_result[sg_id]["Egress"] = dict()
            logging.info(
                f"Going to rollback sg - {sg_id} in region - {region}")
            if "Ingress" in permissions and len(permissions["Ingress"]) > 0:
                _auth_ingress(permissions["Ingress"],
                              sg_id, region_ec2_resource)
                output_result[sg_id]["Ingress"]["rollBack Status"] = "Success"
            else:
                logging.info(
                    f"No Ingress rules for sg -{sg_id} at region - {region}")
                output_result[sg_id]["Ingress"]["rollBack Status"] = "Skip"
            if "Egress" in permissions and len(permissions["Egress"]) > 0:
                _auth_egress(permissions["Egress"], sg_id, region_ec2_resource)
                output_result[sg_id]["Egress"]["rollBack Status"] = "Success"
            else:
                logging.info(
                    f"No Egress rules for sg -{sg_id} at region - {region}")
                output_result[sg_id]["Egress"]["rollBack Status"] = "Skip"
    else:
        output_result[sg_id] = dict()
        output_result[sg_id]["Ingress"] = dict()
        output_result[sg_id]["Egress"] = dict()
        logging.info(f"Going to rollback sg - {sg_id} in region - {region}")
        permissions = sg_definition
        if "Ingress" in permissions and len(permissions["Ingress"]) > 0:
            _auth_ingress(permissions["Ingress"], sg_id, region_ec2_resource)
            output_result[sg_id]["Ingress"]["rollBack Status"] = "Success"
        if "Egress" in permissions and len(permissions["Egress"]) > 0:
            _auth_egress(permissions["Egress"], sg_id, region_ec2_resource)
            output_result[sg_id]["Egress"]["rollBack Status"] = "Success"


def _remove_unused_sg_rules(sg_id, sg, ec2_resource, is_dry_run, output_result):
    """
    This function responsible to clean ingress and egress rules from the security group
    In case of remove
    :param sg:
    :param ec2_resource:
    :param is_dry_run:
    :param dry_run_result:
    :param output_result:
    :return:
    """
    security_group = ec2_resource.SecurityGroup(sg_id)
    sg_name = sg["name"]
    output_result[sg_name]["Ingress"] = dict()
    output_result[sg_name]["Egress"] = dict()
    if len(sg["Ingress"]) == 0:
        output_result[sg_name]["Ingress"]["result"] = "Skip"
        output_result[sg_name]["Ingress"][
            "reason"
        ] = f"No ingress rules to remove for {sg_id}"
    else:
        if is_dry_run:
            output_result[sg_name]["Ingress"]["result"] = "DryRun"
        else:
            security_group.revoke_ingress(IpPermissions=sg["Ingress"])
            output_result[sg_name]["result"] = "Success"

    if len(sg["Egress"]) == 0:
        output_result[sg_name]["Egress"]["result"] = "Skip"
        output_result[sg_name]["Egress"][
            "reason"
        ] = f"No egress rules to remove for {sg_id}"
    else:
        if is_dry_run:
            output_result[sg_name]["result"] = "DryRun"
        else:
            security_group.revoke_egress(IpPermissions=sg["Egress"])
            output_result[sg_name]["result"] = "Success"

    # tag to remove
    if security_group.group_name != "default":
        if not is_dry_run:
            tamnoon_remove_tag = {
                "Key": "Tamnoon-Tag",
                "Value": "SecurityGroup-To-Remove",
            }
            curr_tags = []
            curr_tags.append(tamnoon_remove_tag)
            tag = security_group.create_tags(Tags=curr_tags)


def _delete_unused_sg_rules(
    _id, sg, region_ec2_resource, is_dry_run, output_result, tag_deletion
):
    """
    This method will delete security group - if tag_deletion provided it will delete only security group that have this tag

    :param sg:
    :param region_ec2_resource:
    :param is_dry_run:
    :param dry_run_result:
    :param output_result:
    :param tag_deletion:
    :return:
    """
    sg_id = _id
    sg_name = sg["name"]
    security_group = region_ec2_resource.SecurityGroup(sg_id)
    sg_tags = security_group.tags
    go_delete = False
    if tag_deletion:
        for tag in sg_tags:
            if (
                tag["Key"] == "Tamnoon-Tag"
                and tag["Value"] == "SecurityGroup-To-Remove"
            ):
                go_delete = True
    else:
        go_delete = True

    if len(sg["Ingress"]) > 0:
        if tag_deletion:
            output_result[sg_name]["result"] = "Skip"
            output_result[sg_name][
                "reason"
            ] = f"Tamnoon marked it to delete but new inbound rules created for -  {sg_id}"
            go_delete = False
        else:
            go_delete = True

    if go_delete:
        if is_dry_run:
            output_result[sg_name]["result"] = "DryRun"
        else:
            response = security_group.delete(GroupName=sg_name)
            output_result[sg_name]["result"] = "Deleted"


def _get_service_usage_name(service_usage_type):
    if service_usage_type == "NIC":
        return "Network Interface"
    if service_usage_type == "Lambda":
        return "Lambda"
    if service_usage_type == "Launch Template":
        return "Launch Template"
    if service_usage_type == "Launch Configuration":
        return "Launch Configuration"


def clean_unused_sg(
    is_rollback,
    aws_session,
    region,
    only_defaults,
    is_dry_run,
    state_path,
    sg_to_rb,
    asset_ids=None,
    action_type="Clean",
    tag_deletion=None,
):
    """
    :param is_rollback: A flag to sign if this is a rollback or not
    :param aws_session: The aws boto session
    :param region: The name of the executed region
    :param only_defaults: A flag to sign if this execution is related only to default security groups
    :param is_dry_run: A flag to sign if this is a dry run execution
    :param state_path: The full path where to save the current state of the remediate security groups
    :param: sg_to_rb: teh sg (1 or All) to rollback
    :return:
    """

    output_result = dict()

    if is_rollback:
        logging.info(
            f"Start execute security group roll back for - {sg_to_rb}")
    else:
        logging.info(f"Start execute security group rules removal")

    state_dict = dict()
    if os.path.exists(state_path):
        with open(state_path, "r") as state_file:
            try:
                state_dict = json.load(state_file)
            except json.JSONDecodeError:
                state_dict = dict()

    if not is_rollback:
        session = aws_session
        try:
            # For each region in aws it will create specific ec2 client and ec2 resource
            region_ec2_resource = session.resource("ec2")

            # get all the nics in the region to check attachment of default sg
            sgs_usage = get_sg_usage(
                session=session,
                output_result=output_result,
                only_defaults=only_defaults,
                asset_ids=asset_ids,
                asset_name="GroupName"
            )

            for _id, entry in sgs_usage.items():
                sg_name = entry["name"]
                sg_id = _id

                # check if the security group is in use
                if len(entry["usage"]) > 0:
                    output_result[sg_name]["attachments"] = list()
                    usage_str = f"Going to skip security group name - {sg_name}, id - {sg_id} region - {region} is used by "
                    used_by_services_list = set()
                    for sg_usage in entry["usage"]:
                        service_usage = _get_service_usage_name(
                            sg_usage["type"])
                        used_by_services_list.add(service_usage)
                        output_result[sg_name]["result"] = "Skip"
                        output_result[sg_name]["attachments"].append(sg_usage)
                    output_result[sg_name]["reason"] = usage_str + ",".join(
                        list(used_by_services_list)
                    )
                else:
                    # Unused SG
                    # Save the current sg in the sg state for rollback purpose
                    if region not in state_dict:
                        state_dict[region] = dict()
                    state_dict[region][sg_id] = dict()
                    state_dict[region][sg_id]["Ingress"] = entry["Ingress"]
                    state_dict[region][sg_id]["Egress"] = entry["Egress"]

                    if action_type == "Clean":
                        _remove_unused_sg_rules(
                            sg_id, entry, region_ec2_resource, is_dry_run, output_result
                        )
                    if action_type == "Remove" and entry["name"] != "default":
                        _delete_unused_sg_rules(
                            sg_id,
                            entry,
                            region_ec2_resource,
                            is_dry_run,
                            output_result,
                            tag_deletion,
                        )

        except Exception as e:
            logging.info(f"Persist the state")
            with open(state_path, "w") as state_path_json:
                json.dump(state_dict, state_path_json)
                raise Exception(e)

        logging.info(f"Persist the state")
        with open(state_path, "w") as state_path_json:
            json.dump(state_dict, state_path_json)
    else:
        with open(state_path, "r") as state_path_json:
            state = json.load(state_path_json)
            if region in state:
                for sg_id, sg_definition in state[region].items():
                    if sg_to_rb == "All":
                        logging.info(
                            f"Going to rollback all the security groups from state file - {state_path}"
                        )
                        _execute_rollback(
                            region_session=aws_session,
                            region=region,
                            sg_definition=sg_definition,
                            sg_id=sg_id,
                            output_result=output_result,
                        )
                    else:
                        if sg_to_rb in sg_definition:
                            logging.info(
                                f"Going to rollback {sg_to_rb} from state file - {state_path}"
                            )
                            _execute_rollback(
                                region_session=aws_session,
                                region=region,
                                sg_definition=sg_definition,
                                sg_id=sg_to_rb,
                                output_result=output_result,
                            )

    return output_result


def get_sg_usage(session, output_result, only_defaults, asset_ids=None, asset_name="GroupId"):
    """
    This function return the usage of security groups - if asset_ids array was supplied the result will be narrowed to that scope
    if not it will bring all the usage of al the security groups
    :param session:
    :param asset_ids:
    :return:
    """

    # For each region in aws it will create specific ec2 client and ec2 resource
    region_client = session.client("ec2")

    # describe all the sg in the region
    res_desc_sg = region_client.describe_security_groups()

    sg_usage = _get_used_sg(asset_ids, session)
    result = dict()
    for sg in res_desc_sg["SecurityGroups"]:
        asset_id = sg[asset_name]
        if asset_ids:
            if asset_id not in asset_ids:
                continue

        output_result[asset_id] = dict()
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]
        sg_ip_permissions = sg["IpPermissions"]
        sg_ip_permissions_egress = sg["IpPermissionsEgress"]

        # in case that we focus only on default sg
        if only_defaults:
            if asset_id != "default":
                continue

        if sg_id not in sg_usage:
            sg_usage[asset_id] = {
                "id": sg_id,
                "name": sg_name,
                "usage": [],
                "Ingress": sg_ip_permissions,
                "Egress": sg_ip_permissions_egress,
            }
        else:
            sg_usage[asset_id]["name"] = sg_name
            sg_usage[asset_id]["Ingress"] = sg_ip_permissions
            sg_usage[asset_id]["Egress"] = sg_ip_permissions_egress

        key_to_del = asset_name.lower().replace("group", "")
        if key_to_del in sg_usage[asset_id]:
            del sg_usage[asset_id][key_to_del]
        result[asset_id] = sg_usage[asset_id]

    return result


def _get_used_sg(asset_ids, session):
    """
    This function return all the used security groups in the env
    :param asset_ids:
    :param session:
    :return:
    """
    # check nics
    region_client = session.client("ec2")
    sg_usage = dict()
    nic_paginator = region_client.get_paginator("describe_network_interfaces")
    response_nics = [
        y for x in nic_paginator.paginate() for y in x.get("NetworkInterfaces", [])
    ]
    for nic in response_nics:
        for group in nic.get("Groups", []):
            group_id = group.get("GroupId", "")
            nic_id = nic.get("NetworkInterfaceId", "")
            nic_ip = nic.get("PrivateIpAddress", "")
            nic_nic_description = nic.get("Description", "")
            nic_type = nic.get("InterfaceType", "")
            nic_status = nic.get("Status", "")
            check_security_group_usage(
                asset_ids=asset_ids,
                group=group_id,
                usage_desc={
                    "type": "NIC",
                    "id": nic_id,
                    "ip": nic_ip,
                    "desc": nic_nic_description,
                    "nic_type": nic_type,
                    "status": nic_status,
                },
                sg_to_service=sg_usage,
            )
    # check also lambdas
    region_client = session.client("lambda")
    lambda_paginator = region_client.get_paginator("list_functions")
    response_lambda = [
        y for x in lambda_paginator.paginate() for y in x.get("Functions", [])
    ]
    for lambda_asset in response_lambda:
        if (
            "VpcConfig" in lambda_asset
            and "SecurityGroupIds" in lambda_asset["VpcConfig"]
        ):
            for group in lambda_asset["VpcConfig"]["SecurityGroupIds"]:
                lambda_id = lambda_asset.get("FunctionName", "")
                check_security_group_usage(
                    asset_ids, group, {"type": "Lambda",
                                       "id": lambda_id}, sg_usage
                )
    # Check also ASG launch templates
    region_client = session.client("ec2")
    lt_paginator = region_client.get_paginator("describe_launch_templates")
    lts = [y for x in lt_paginator.paginate()
           for y in x.get("LaunchTemplates", [])]
    for lt in lts:
        lt_versions = region_client.describe_launch_template_versions(
            LaunchTemplateId=lt["LaunchTemplateId"]
        )
        for lt_version in lt_versions["LaunchTemplateVersions"]:
            if "NetworkInterfaces" in lt_version["LaunchTemplateData"]:
                for lt_data_nic in lt_version["LaunchTemplateData"][
                    "NetworkInterfaces"
                ]:
                    if "Groups" in lt_data_nic:
                        for group in lt_data_nic["Groups"]:
                            lt_id = lt.get("LaunchTemplateId", "")
                            check_security_group_usage(
                                asset_ids,
                                group,
                                {"type": "Launch Template", "id": lt_id},
                                sg_usage,
                            )
            elif "SecurityGroupIds" in lt_version["LaunchTemplateData"]:
                for group in lt_version["LaunchTemplateData"]["SecurityGroupIds"]:
                    lt_id = lt.get("LaunchTemplateId", "")
                    check_security_group_usage(
                        asset_ids,
                        group,
                        {"type": "Launch Template", "id": lt_id},
                        sg_usage,
                    )
    # Check also ASG launch configuration
    region_client = session.client("autoscaling")
    asg_paginator = region_client.get_paginator(
        "describe_launch_configurations")
    lconfigs = [
        y for x in asg_paginator.paginate() for y in x.get("LaunchConfigurations", [])
    ]
    for launch_cfg in lconfigs:
        if "SecurityGroups" in launch_cfg:
            for group in launch_cfg["SecurityGroups"]:
                launch_cfg_id = launch_cfg.get("LaunchConfigurationName", "")
                check_security_group_usage(
                    asset_ids,
                    group,
                    {"type": "Launch Configuration", "id": launch_cfg_id},
                    sg_usage,
                )
    return sg_usage


def check_security_group_usage(asset_ids, group, usage_desc, sg_to_service):
    if (asset_ids and group in asset_ids) or not asset_ids:
        if group not in sg_to_service:
            sg_to_service[group] = {"usage": list()}
        sg_to_service[group]["usage"].append(usage_desc)


def get_ingress_rules_for_sg(
    ec2client=None, Cidrs=None, sgid=None, IpProt=None, Ports=None
):
    filters = [{"Name": "group-id", "Values": [sgid]}]
    routput = ec2client.describe_security_group_rules(Filters=filters, MaxResults=1000)[
        "SecurityGroupRules"
    ]
    routput = list(filter(lambda x: x["IsEgress"] == False, routput))
    if Cidrs:
        if type(Cidrs) == str:
            Cidrs = [Cidrs]
        routput = list(filter(lambda x: x.get("CidrIpv4") in Cidrs, routput))
    if IpProt:
        routput = list(filter(lambda x: x.get(
            "IpProtocol") == IpProt, routput))
    if Ports:  # we're only matching single-port rules
        if type(Ports) == int:
            Ports = [Ports]
        elist = []
        for port in Ports:
            elist.extend(
                list(
                    filter(
                        lambda x: x.get("ToPort") == port and x.get(
                            "FromPort") == port,
                        routput,
                    )
                )
            )
        routput = elist
    return routput


def remove_rules_from_sg(ec2client=None, rule=None, is_dry_run=False):
    ruleremoved = False
    message = ""
    try:
        ec2client.revoke_security_group_ingress(
            GroupId=rule["GroupId"],
            SecurityGroupRuleIds=[rule["SecurityGroupRuleId"]],
            DryRun=is_dry_run,
        )
        logging.debug(f"removed rule {rule}")
        ruleremoved = True
    except botocore.exceptions.ClientError as ce:
        if ce.response["Error"]["Code"] == "DryRunOperation":
            message = f"Dry run execution!!! " + str(ce)
            logging.warning(message)
    except Exception as e:
        message = f"got the error below. Did not remove rule {rule['SecurityGroupRuleId']} in group {rule['GroupId']}: \n {e}"
        logging.exception(message)
        ruleremoved = False
    output = {"inputrule": rule, "ruleremoved": ruleremoved, "error": message}
    return output


def replace_sg_rule(
    ec2client=None, rule=None, newcidrs=None, allprivate=False, is_dry_run=False
):
    message = ""
    if not newcidrs and not allprivate:
        raise Exception(
            "no params provided for what to replace the rules with. Quiting"
        )
        exit()
    elif allprivate:
        privateranges = """
            10.0.0.0/8
            172.16.0.0/12
            192.168.0.0/16
            169.254.0.0/16
        """
        newcidrs = privateranges.split()
    else:
        if type(newcidrs) != list:
            newcidrs = [newcidrs]
    sgrids = list()
    new_rule = {
        "FromPort": rule["FromPort"],
        "ToPort": rule["ToPort"],
        "IpProtocol": rule["IpProtocol"],
        "IpRanges": [{"CidrIp": x} for x in newcidrs],
    }
    if "UserIdGroupPairs" in rule.keys():
        new_rule["UserIdGroupPairs"] = rule["UserIdGroupPairs"]
    try:
        response = ec2client.authorize_security_group_ingress(
            GroupId=rule["GroupId"], IpPermissions=[
                new_rule], DryRun=is_dry_run
        )
        sgrids = response["SecurityGroupRules"]
        logging.debug(f"added rules: {str(sgrids)}")
    except Exception as e:
        if "aready exists" in str(e) or "InvalidPermission.Duplicate" in str(
            e
        ):  # sometime some of the rules already exist, now we have to try one by one
            sgrids = []
            for x in newcidrs:
                new_rule["IpRanges"] = [{"CidrIp": x}]
                try:
                    response = ec2client.authorize_security_group_ingress(
                        GroupId=rule["GroupId"],
                        IpPermissions=[new_rule],
                        DryRun=is_dry_run,
                    )
                    sgridsx = response["SecurityGroupRules"]
                    logging.debug(f"added rule {str(sgridsx)} for cidr {x}")
                    sgrids.extend(sgridsx)
                except botocore.exceptions.ClientError as ce:
                    if ce.response["Error"]["Code"] == "DryRunOperation":
                        message = f"Dry run execution!!! " + str(ex)
                        logging.warning(message)
                        sgrids.append(message)
                except Exception as e:
                    if "aready exists" in str(
                        e
                    ) or "InvalidPermission.Duplicate" in str(e):
                        message = f"rule already exists for for {new_rule}"
                        logging.exception(message)
                        sgrids.append(message)
                    else:
                        message = f"when going for a single cidr add, got the error below. Did not replace rule {rule['SecurityGroupRuleId']} in group {rule['GroupId']}: \n {e}"
                        logging.exception(message)
                        sgrids.append(message)

        else:
            message = f"got the error below. Did not replace rule {rule['SecurityGroupRuleId']} in group {rule['GroupId']}: \n {e}"
            logging.error(message)
            sgrids.append(message)
    ruleremoved = remove_rules_from_sg(
        ec2client, rule, is_dry_run)["ruleremoved"]
    return {
        "inputrule": rule,
        "ruleremoved": ruleremoved,
        "rulereplaced": True,
        "rulescreated": sgrids,
    }


def create_ingress_rule_in_sg(ec2client=None, rule=None, is_dry_run=False):
    sgrids = []
    try:
        ip_ranges = []
        new_rule = {
            "FromPort": rule["FromPort"],
            "ToPort": rule["ToPort"],
            "IpProtocol": rule["IpProtocol"],
            "IpRanges": [{"CidrIp": rule["CidrIpv4"]}],
        }
        if "UserIdGroupPairs" in rule.keys():
            new_rule["UserIdGroupPairs"] = rule["UserIdGroupPairs"]

        response = ec2client.authorize_security_group_ingress(
            GroupId=rule["GroupId"], IpPermissions=[
                new_rule], DryRun=is_dry_run
        )
        sgrids = response["SecurityGroupRules"]
        logging.debug(f"added rules: {str(sgrids)}")

    except Exception as e:
        if e.response["Error"]["Code"] == "DryRunOperation":
            message = f"Dry run execution!!! " + str(e)
            logging.warning(message)
            sgrids.append(message)
        else:
            message = f"got the error below. Did not create rule {rule['SecurityGroupRuleId']} in group {rule['GroupId']}: \n {e}"
            logging.error(message)
            sgrids.append(message)
    return dict(
        {
            rule["GroupId"]: {
                "inputrule": rule,
                "ruleremoved": False,
                "rulereplaced": False,
                "rulescreated": sgrids,
            }
        }
    )


def replace_ingress_rules_in_sg(
    ec2client=None,
    sgid=None,
    oldcidrs="0.0.0.0/0",
    newcidrs=None,
    allprivate=False,
    Ports=None,
    IpProt=None,
    is_dry_run=False,
):
    rules = get_ingress_rules_for_sg(
        ec2client=ec2client, sgid=sgid, Cidrs=oldcidrs, IpProt=IpProt, Ports=Ports
    )
    if rules == []:
        logging.info("No relevant rules to replace")
        return "No relevant rules to replace"
    else:
        foutput = dict()
        for rule in rules:
            output = replace_sg_rule(
                ec2client=ec2client,
                rule=rule,
                newcidrs=newcidrs,
                allprivate=allprivate,
                is_dry_run=is_dry_run,
            )
            output["rulesreplaced"] = True
            foutput[rule["SecurityGroupRuleId"]] = output
        logging.debug(json.dumps(foutput, indent=2))
        return foutput


def remove_ingress_rules_from_sg(
    ec2client=None,
    sgid=None,
    oldcidrs="0.0.0.0/0",
    Ports=None,
    IpProt=None,
    is_dry_run=False,
):
    rules = get_ingress_rules_for_sg(
        ec2client=ec2client, sgid=sgid, Cidrs=oldcidrs, IpProt=IpProt, Ports=Ports
    )
    if rules == []:
        print("No relevant rules to replace")
        return "No relevant rules to replace"
    else:
        foutput = dict()
        for rule in rules:
            output = remove_rules_from_sg(
                ec2client=ec2client,
                rule=rule,
                is_dry_run=is_dry_run,
            )
            output["rulesreplaced"] = False
            foutput[rule["SecurityGroupRuleId"]] = output
        logging.debug(json.dumps(foutput, indent=2))
        return foutput


def do_sg_delete(resource, asset_id, dry_run):
    """
    This function execute security group deletion
    :param resource: The boto ec2 resource
    :param asset_id: The security group id
    :param dry_run: dry run flag
    :return:
    """

    logging.info(f"Going to delete security group - {asset_id}")
    security_group = resource.SecurityGroup(asset_id)
    try:
        response = security_group.delete(GroupName=asset_id, DryRun=dry_run)
    except botocore.exceptions.ClientError as ce:
        if ce.response["Error"]["Code"] == "DryRunOperation":
            logging.warning(
                f"This is a Dry run - operation would have succeeded")
        else:
            raise Exception(ce)


def do_rollback_remove_or_replace_security_rules(
    session,
    dry_run,
    state_path
):
    ec2client = session.client("ec2", region_name=session.region_name)
    goutput = dict()

    with open(str(state_path), "r", encoding="utf-8") as state_path_json:
        state = json.load(state_path_json)
        if session.region_name in state:
            for sg_id, sg_definition in state[session.region_name].items():
                # print((sg_id, sg_definition), end="\n\n")
                goutput[sg_id] = []
                if not isinstance(sg_definition, dict):
                    continue
                for sgr_id, sgr_definition in sg_definition.items():
                    # print((sgr_id, sgr_definition))

                    if (
                        "rulereplaced" in sgr_definition
                        and sgr_definition["rulereplaced"]
                    ):
                        for rule in sgr_definition["rulescreated"]:
                            ports = []
                            if rule["FromPort"] == rule["ToPort"]:
                                ports = [rule["FromPort"]]
                            else:
                                ports = [rule["FromPort"],
                                         rule["ToPort"]]
                            sgr = remove_ingress_rules_from_sg(
                                ec2client=ec2client,
                                sgid=sg_id,
                                oldcidrs=rule["CidrIpv4"],
                                IpProt=rule["IpProtocol"],
                                Ports=ports,
                                is_dry_run=dry_run,
                            )
                            goutput[sg_id].append(sgr)
                    if (
                        "ruleremoved" in sgr_definition
                        and sgr_definition["ruleremoved"]
                    ):
                        sgr = create_ingress_rule_in_sg(
                            ec2client=ec2client,
                            rule=sgr_definition["inputrule"],
                            is_dry_run=dry_run,
                        )
                        goutput[sg_id].append(sgr)
    return goutput


def do_remove_or_replace_security_rules(
    session,
    dry_run,
    asset_ids,
    replace,
    old_cidrs,
    new_cidrs,
    ports,
    ip_prot,
    allprivate,
):
    Ports = ""
    newcidrs = ""
    oldcidrs = ""
    if ports:
        try:
            Ports = [int(x) for x in ports.split(" ")]
        except Exception as e:
            print(f"Couldn't parse ports. getting error: \n {e}")
            exit()
    if replace:
        if new_cidrs:
            newcidrs = new_cidrs.split(" ")
    if old_cidrs:
        oldcidrs = old_cidrs.split(" ")

    ec2client = session.client("ec2", region_name=session.region_name)
    goutput = dict()
    interesting_asset_ids = list(
        map(
            lambda sg: sg["GroupId"],
            list(
                filter(
                    lambda sg: asset_ids == None
                    or asset_ids[0] == "all"
                    or sg["GroupId"] in asset_ids,
                    list(
                        ec2client.describe_security_groups()[
                            "SecurityGroups"]
                    ),
                )
            ),
        )
    )

    for sgid in interesting_asset_ids:
        if replace:
            goutput[sgid] = replace_ingress_rules_in_sg(
                ec2client=ec2client,
                sgid=sgid,
                oldcidrs=oldcidrs,
                IpProt=ip_prot,
                Ports=Ports,
                newcidrs=newcidrs,
                allprivate=allprivate,
                is_dry_run=dry_run,
            )
        else:
            goutput[sgid] = remove_ingress_rules_from_sg(
                ec2client=ec2client,
                sgid=sgid,
                oldcidrs=oldcidrs,
                IpProt=ip_prot,
                Ports=Ports,
                is_dry_run=dry_run,
            )

    if asset_ids is not None and asset_ids != ["all"]:
        for asset_id in asset_ids:
            if asset_id not in interesting_asset_ids:
                goutput[asset_id] = "sg not found in region"
    return goutput
