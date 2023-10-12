import argparse
import json
import logging
import boto3
import botocore
from botocore import exceptions

boto3.set_stream_logger('boto3', logging.ERROR)

import os





def _get_reslut_by_api(d9key, d9secret):
    pass


def _load_from_file(result_file):
    with open(result_file, 'r') as result_json:
        return json.load(result_json)




def _auth_ingress(permissions, sg_id, region_ec2_resource):
    security_group = region_ec2_resource.SecurityGroup(sg_id)
    security_group.authorize_ingress(IpPermissions=permissions)


def _auth_egress(permissions, sg_id, region_ec2_resource):
    security_group = region_ec2_resource.SecurityGroup(sg_id)
    security_group.authorize_egress(IpPermissions=permissions)


def _execute_rollback(region_session, region, sg_definition, output_result, sg_id=None):
    region_ec2_resource = region_session.resource('ec2')
    if not sg_id:
        for sg_id, permissions in sg_definition.items():
            output_result[sg_id] = dict()
            output_result[sg_id]['Ingress'] = dict()
            output_result[sg_id]['Egress'] = dict()
            logging.info(f"Going to rollback sg - {sg_id} in region - {region}")
            if 'Ingress' in permissions and len(permissions['Ingress']) > 0:
                _auth_ingress(permissions['Ingress'], sg_id, region_ec2_resource)
                output_result[sg_id]['Ingress']['rollBack Status'] = 'Success'
            else:
                logging.info(f"No Ingress rules for sg -{sg_id} at region - {region}")
                output_result[sg_id]['Ingress']['rollBack Status'] = 'Skip'
            if 'Egress' in permissions and len(permissions['Egress']) > 0:
                _auth_egress(permissions['Egress'], sg_id, region_ec2_resource)
                output_result[sg_id]['Egress']['rollBack Status'] = 'Success'
            else:
                logging.info(f"No Egress rules for sg -{sg_id} at region - {region}")
                output_result[sg_id]['Egress']['rollBack Status'] = 'Skip'
    else:
        output_result[sg_id] = dict()
        output_result[sg_id]['Ingress'] = dict()
        output_result[sg_id]['Egress'] = dict()
        logging.info(f"Going to rollback sg - {sg_id} in region - {region}")
        permissions = sg_definition
        if 'Ingress' in permissions and len(permissions['Ingress']) > 0:
            _auth_ingress(permissions['Ingress'], sg_id, region_ec2_resource)
            output_result[sg_id]['Ingress']['rollBack Status'] = 'Success'
        if 'Egress' in permissions and len(permissions['Egress']) > 0:
            _auth_egress(permissions['Egress'], sg_id, region_ec2_resource)
            output_result[sg_id]['Egress']['rollBack Status'] = 'Success'

def _remove_unused_sg_rules(sg, ec2_resource, is_dry_run, output_result):
    '''
    This function responsible to clean ingress and egress rules from the security group
    In case of remove
    :param sg:
    :param ec2_resource:
    :param is_dry_run:
    :param dry_run_result:
    :param output_result:
    :return:
    '''
    sg_id = sg['GroupId']
    security_group = ec2_resource.SecurityGroup(sg['GroupId'])
    output_result[sg_id]["Ingress"] = dict()
    output_result[sg_id]["Egress"] = dict()
    if len(sg['IpPermissions']) == 0:
        output_result[sg_id]["Ingress"]["result"] = "Skip"
        output_result[sg_id]["Ingress"]["reason"] = f"No ingress rules to remove for {sg['GroupId']}"

    else:
        if is_dry_run:
            output_result[sg_id]["Ingress"]["result"] = "DryRun"
        else:
            security_group.revoke_ingress(IpPermissions=sg['IpPermissions'])
            output_result[sg_id]["result"] = "Success"

    if len(sg['IpPermissionsEgress']) == 0:
        output_result[sg_id]["Egress"]["result"] = "Skip"
        output_result[sg_id]["Egress"]["reason"] = f"No egress rules to remove for {sg['GroupId']}"
    else:
        if is_dry_run:
            output_result[sg_id]["result"] = "DryRun"
        else:
            security_group.revoke_egress(IpPermissions=sg['IpPermissionsEgress'])
            output_result[sg_id]["result"] = "Success"

    # tag to remove
    if security_group.group_name != 'default':
        if not is_dry_run:
            tamnoon_remove_tag = {
                'Key': 'Tamnoon-Tag',
                'Value': 'SecurityGroup-To-Remove'
            }
            curr_tags = []
            curr_tags.append(tamnoon_remove_tag)
            tag = security_group.create_tags(Tags=curr_tags)


def _delete_unused_sg_rules(sg, region_ec2_resource, is_dry_run, output_result, tag_deletion):
    '''
    This method will delete security group - if tag_deletion provided it will delete only security group that have this tag

    :param sg:
    :param region_ec2_resource:
    :param is_dry_run:
    :param dry_run_result:
    :param output_result:
    :param tag_deletion:
    :return:
    '''
    sg_id = sg['GroupId']
    security_group = region_ec2_resource.SecurityGroup(sg['GroupId'])
    sg_tags = security_group.tags
    go_delete = False
    if tag_deletion:
        for tag in sg_tags:
            if tag['Key'] == 'Tamnoon-Tag' and tag['Value'] == 'SecurityGroup-To-Remove':
                go_delete = True
    else:
        go_delete = True

    if len(sg['IpPermissions']) > 0:
        if tag_deletion:
            output_result[sg_id]["result"] = "Skip"
            output_result[sg_id]["reason"] = f"Tamnoon marked it to delete but new inbound rules created for -  {sg['GroupId']}"
            go_delete = False
        else:
            go_delete = True

    if go_delete:
        if is_dry_run:
            output_result[sg_id]["result"] = "DryRun"
        else:
            response = security_group.delete(GroupName=sg['GroupId'])
            output_result[sg_id]["result"] = "Deleted"


def _get_service_usage_name(service_usage_type):
    if service_usage_type == 'NIC':
        return 'Network Interface'
    if service_usage_type == 'Lambda':
        return 'Lambda'
    if service_usage_type == 'Launch Template':
        return 'Launch Template'
    if service_usage_type == 'Launch Configuration':
        return 'Launch Configuration'

def execute(is_rollback, aws_session, region, only_defaults, is_dry_run, state_path, sg_to_rb, asset_ids = None, action_type='Clean', tag_deletion=None):

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
        logging.info(f"Start execute security group roll back for - {sg_to_rb}")
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
            region_ec2_resource = session.resource('ec2')
            region_client = session.client('ec2')

            # describe all the sg in the region
            res_desc_sg = region_client.describe_security_groups()

            # get all the nics in the region to check attachment of default sg
            sgs_usage = get_sg_usage(session)

            for sg in res_desc_sg['SecurityGroups']:
                sg_name = sg['GroupId']
                if asset_ids:
                    if sg_name not in asset_ids:
                        continue

                output_result[sg_name] = dict()
                sg_id = sg['GroupId']
                sg_ip_permissions = sg['IpPermissions']
                sg_ip_permissions_egress = sg['IpPermissionsEgress']

                # in case that we focus only on default sg
                if only_defaults:
                    if sg_name != 'default':
                        continue

                # check if the security group is in use
                if sg_id in sgs_usage and len(sgs_usage[sg_id]) > 0:
                    output_result[sg_name]["attachments"] = list()
                    usage_str = f"Going to skip security group name - {sg['GroupName']}, id - {sg['GroupId']} region - {region} is used by "
                    used_by_services_list = set()
                    for sg_usage in sgs_usage[sg_id]:
                        service_usage = _get_service_usage_name(sg_usage['type'])
                        used_by_services_list.add(service_usage)
                        output_result[sg_name]["result"] = "Skip"
                        output_result[sg_name]["attachments"].append(sg_usage)
                    output_result[sg_name]["reason"] = usage_str + ','.join(list(used_by_services_list))
                else:
                    # Unused SG
                    # Save the current sg in the sg state for rollback purpose
                    if region not in state_dict:
                        state_dict[region] = dict()
                    state_dict[region][sg_id] = dict()
                    state_dict[region][sg_id]['Ingress'] = sg_ip_permissions
                    state_dict[region][sg_id]['Egress'] = sg_ip_permissions_egress

                    if action_type == 'Clean':
                        _remove_unused_sg_rules(sg, region_ec2_resource, is_dry_run, output_result)
                    if action_type == 'Remove' and sg['GroupName'] != 'default':
                        _delete_unused_sg_rules(sg, region_ec2_resource, is_dry_run,
                                                output_result, tag_deletion)


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
                    if sg_to_rb == 'All':
                        logging.info(f"Going to rollback all the security groups from state file - {state_path}")
                        _execute_rollback(region_session=aws_session, region=region, sg_definition=sg_definition, sg_id=sg_id, output_result=output_result)
                    else:
                        if sg_to_rb in sg_definition:
                            logging.info(f"Going to rollback {sg_to_rb} from state file - {state_path}")
                            _execute_rollback(region_session=aws_session, region=region, sg_definition=sg_definition, sg_id=sg_to_rb, output_result=output_result)

    return output_result

def get_sg_usage(session, asset_ids=None):
    """
    This function return the usage of security groups - if asset_ids array was supplied the result will be narrowed to that scope
    if not it will bring all the usage of al the security groups
    :param session:
    :param asset_ids:
    :return:
    """

    # check nics
    region_client = session.client('ec2')
    sg_usage = dict()

    nic_paginator = region_client.get_paginator('describe_network_interfaces')
    response_nics = [y for x in nic_paginator.paginate() for y in x.get('NetworkInterfaces', [])]
    for nic in response_nics:
        for group in nic.get('Groups',[]):
            group_id = group.get('GroupId','')
            nic_id = nic.get('NetworkInterfaceId', '')
            nic_ip = nic.get('PrivateIpAddress', '')
            check_security_group_usage(asset_ids, group_id, {'type':'NIC','id':nic_id, 'ip':nic_ip}, sg_usage)

    # check also lambdas
    region_client = session.client('lambda')
    lambda_paginator = region_client.get_paginator('list_functions')
    response_lambda = [y for x in lambda_paginator.paginate() for y in x.get('Functions', [])]
    for lambda_asset in response_lambda:
        if 'VpcConfig' in lambda_asset and 'SecurityGroupIds' in lambda_asset['VpcConfig']:
            for group in lambda_asset['VpcConfig']['SecurityGroupIds']:
                lambda_id = lambda_asset.get('FunctionName', '')
                check_security_group_usage(asset_ids, group, {'type':'Lambda','id':lambda_id}, sg_usage)

    # Check also ASG launch templates

    region_client=session.client('ec2')
    lt_paginator = region_client.get_paginator('describe_launch_templates')
    lts=[y for x in lt_paginator.paginate() for y in x.get('LaunchTemplates', [])]
    for lt in lts:
        lt_versions = region_client.describe_launch_template_versions(LaunchTemplateId=lt['LaunchTemplateId'])
        for lt_version in lt_versions['LaunchTemplateVersions']:
            if 'NetworkInterfaces' in lt_version['LaunchTemplateData']:
                for lt_data_nic in lt_version['LaunchTemplateData']['NetworkInterfaces']:
                    if 'Groups' in lt_data_nic:
                        for group in lt_data_nic['Groups']:
                            lt_id = lt.get('LaunchTemplateId', '')
                            check_security_group_usage(asset_ids, group, {'type':'Launch Template','id':lt_id}, sg_usage)
            elif 'SecurityGroupIds' in lt_version['LaunchTemplateData']:
                for group in lt_version['LaunchTemplateData']['SecurityGroupIds']:
                    lt_id = lt.get('LaunchTemplateId', '')
                    check_security_group_usage(asset_ids, group,
                                               {'type': 'Launch Template', 'id': lt_id}, sg_usage)


    # Check also ASG launch configuration
    region_client = session.client('autoscaling')
    asg_paginator = region_client.get_paginator('describe_launch_configurations')
    lconfigs = [y for x in asg_paginator.paginate() for y in x.get('LaunchConfigurations', [])]
    for launch_cfg in lconfigs:
        if 'SecurityGroups' in launch_cfg:
            for group in launch_cfg['SecurityGroups']:
                launch_cfg_id = launch_cfg.get('LaunchConfigurationName', '')
                check_security_group_usage(asset_ids, group, {'type':'Launch Configuration','id':launch_cfg_id}, sg_usage)

    return sg_usage


def check_security_group_usage(asset_ids, group, usage_desc, sg_to_service):
    if (asset_ids and group in asset_ids) or not asset_ids:
        if group not in sg_to_service:
            sg_to_service[group] = list()
        sg_to_service[group].append(usage_desc)
