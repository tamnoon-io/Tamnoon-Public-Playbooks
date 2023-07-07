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


def _execute_rollback(region_session, region, sg_definition, sg_id=None):
    region_ec2_resource = region_session.resource('ec2')
    if not sg_id:
        for sg_id, permissions in sg_definition.items():
            logging.info(f"Going to rollback sg - {sg_id} in region - {region}")
            if 'Ingress' in permissions and len(permissions['Ingress']) > 0:
                _auth_ingress(permissions['Ingress'], sg_id, region_ec2_resource)
            else:
                logging.info(f"No Ingress rules for sg -{sg_id} at region - {region}")
            if 'Egress' in permissions and len(permissions['Egress']) > 0:
                _auth_egress(permissions['Egress'], sg_id, region_ec2_resource)
            else:
                logging.info(f"No Egress rules for sg -{sg_id} at region - {region}")
    else:
        logging.info(f"Going to rollback sg - {sg_id} in region - {region}")
        permissions = sg_definition[sg_id]
        if 'Ingress' in permissions:
            _auth_ingress(permissions['Ingress'], sg_id, region_ec2_resource)
        if 'Egress' in permissions:
            _auth_egress(permissions['Egress'], sg_id, region_ec2_resource)

def _remove_unused_sg_rules(sg, ec2_resource, is_dry_run, dry_run_result, output_result):
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
            dry_run_result.add(sg['GroupId'])
        else:
            security_group.revoke_ingress(IpPermissions=sg['IpPermissions'])
            output_result[sg_id]["result"] = "Executed"

    if len(sg['IpPermissionsEgress']) == 0:

        output_result[sg_id]["Egress"]["result"] = "Skip"
        output_result[sg_id]["Egress"]["reason"] = f"No egress rules to remove for {sg['GroupId']}"
    else:
        if is_dry_run:
            output_result[sg_id]["result"] = "DryRun"
            dry_run_result.add(sg['GroupId'])
        else:
            security_group.revoke_egress(IpPermissions=sg['IpPermissionsEgress'])
            output_result[sg_id]["result"] = "Executed"

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


def _delete_unused_sg_rules(sg, region_ec2_resource, is_dry_run, dry_run_result, output_result, tag_deletion):
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
            dry_run_result.add(sg['GroupId'])
        else:
            response = security_group.delete(GroupName=sg['GroupId'])
            output_result[sg_id]["result"] = "Deleted"




def execute(is_rollback, aws_session, region, only_defaults, is_dry_run, state_path, sg_to_rb, asset_ids = None, action_type='Clean', tag_deletion=None):
    '''

    :param is_rollback: A flag to sign if this is a rollback or not
    :param aws_session: The aws boto session
    :param region: The name of the executed region
    :param only_defaults: A flag to sign if this execution is related only to default security groups
    :param is_dry_run: A flag to sign if this is a dry run execution
    :param state_path: The full path where to save the current state of the remediate security groups
    :param: sg_to_rb: teh sg (1 or All) to rollback
    :return:
    '''

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
            dry_run_result = dict()
            # For each region in aws it will create specific ec2 client and ec2 resource
            dry_run_result[region] = set()

            region_ec2_resource = session.resource('ec2')
            region_client = session.client('ec2')

            # describe all the sg in the region
            res_desc_sg = region_client.describe_security_groups()

            # get all the nics in the region to check attachment of default sg
            sg_to_lambda, sg_to_nic = get_sg_usage(session)

            for sg in res_desc_sg['SecurityGroups']:
                sg_name = sg['GroupId']
                if asset_ids:
                    if sg_name not in asset_ids:
                        continue
                attached_nics = []
                attached_lambdas = []

                output_result[sg_name] = dict()
                sg_id = sg['GroupId']
                sg_ip_permissions = sg['IpPermissions']
                sg_ip_permissions_egress = sg['IpPermissionsEgress']
                # in case that we focus only on default sg
                if only_defaults:
                    if sg_name != 'default': continue

                sg_attached_to_nic = sg_id in sg_to_nic and len(sg_to_nic[sg_id])>0
                sg_attached_to_lambda = sg_id in sg_to_lambda and len(sg_to_lambda[sg_id])>0

                if sg_attached_to_nic:
                    attached_nics = [nic['id'] for nic in  sg_to_nic[sg_id]]
                    output_result[sg_name]["result"] = "Skip"
                    output_result[sg_name]["reason"] = f"security group name - {sg['GroupName']}, id - {sg['GroupId']} is attached to some Network Interface in region - {region} going to skip it"
                    output_result[sg_name]["attachments"] = f"Attached Network Interfaces  - {','.join(attached_nics)}"

                if sg_attached_to_lambda:
                    attached_lambdas = [l for l in sg_to_lambda[sg_id]]
                    output_result[sg_name]["result"] = "Skip"
                    output_result[sg_name]["reason"] = f"security group name - {sg['GroupName']}, id - {sg['GroupId']} is attached to some lambdas in region - {region} going to skip it"
                    output_result[sg_name]["attachments"] = f"Attached AWS Lambdas - {','.join(attached_lambdas)}"

                # Unused SG
                if not sg_attached_to_nic and not sg_attached_to_lambda:
                    # Save the current sg in the sg state for rollback purpose
                    if region not in state_dict:
                        state_dict[region] = dict()
                    state_dict[region][sg_id] = dict()
                    state_dict[region][sg_id]['Ingress'] = sg_ip_permissions
                    state_dict[region][sg_id]['Egress'] = sg_ip_permissions_egress

                    if action_type == 'Clean':
                        _remove_unused_sg_rules(sg, region_ec2_resource, is_dry_run, dry_run_result[region], output_result)
                    if action_type == 'Remove' and sg['GroupName'] != 'default':
                        _delete_unused_sg_rules(sg, region_ec2_resource, is_dry_run, dry_run_result[region],
                                                output_result, tag_deletion)


            logging.info("####################### Status #######################")
            json_formatted_str = json.dumps(output_result, indent=2)
            print(json_formatted_str)
            if is_dry_run:
                logging.info("####################### Dry Run execution - Nothing executed #######################")
                for region in dry_run_result:
                    dry_run_result[region] = list(dry_run_result[region])
                json_formatted_str = json.dumps(dry_run_result, indent=2)
                print(json_formatted_str)


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
            from botocore.config import Config
            state = json.load(state_path_json)
            if sg_to_rb == 'All':
                logging.info(f"Going to rollback all the security groups from state file - {state_path}")
                for region, sg_definition in state.items():
                    config = Config(region_name=region)

                    # modify the session to use the new config object
                    aws_session._session = aws_session._session.clone(
                        botocore_session=aws_session._session._session,
                        region_name=region,
                        config=config
                    )

                    _execute_rollback(aws_session, region, sg_definition)
            else:
                logging.info(f"Going to rollback {sg_to_rb} from state file - {state_path}")
                for region, sg_definition in state.items():
                    if sg_to_rb in sg_definition:
                        config = Config(region_name=region)

                        # modify the session to use the new config object
                        aws_session._session = aws_session._session.clone(
                            botocore_session=aws_session._session._session,
                            region_name=region,
                            config=config
                        )
                        _execute_rollback(aws_session, region, sg_definition, sg_to_rb)


def get_sg_usage(session, asset_ids=None):
    region_client = session.client('ec2')
    #nic_to_sg = dict()
    sg_to_nic = dict()
    response_nics = region_client.describe_network_interfaces()
    # check nics
    for nic in response_nics['NetworkInterfaces']:
        #nic_to_sg[nic['NetworkInterfaceId']] = list()
        for group in nic['Groups']:
            if (asset_ids and group['GroupId'] in asset_ids) or not asset_ids:
                if group['GroupId'] not in sg_to_nic:
                    sg_to_nic[group['GroupId']] = list()
                sg_to_nic[group['GroupId']].append({'id':nic['NetworkInterfaceId'], 'ip':nic['PrivateIpAddress']})
                #nic_to_sg[nic['NetworkInterfaceId']].append(group['GroupId'])
    # get all the lambdas to see which on enis attached to that sg
    #lambda_to_sg = dict()
    sg_to_lambda = dict()
    region_client = session.client('lambda')
    response_lambda = region_client.list_functions()
    # check also lambdas
    for lambda_asset in response_lambda['Functions']:
        if 'VpcConfig' in lambda_asset and 'SecurityGroupIds' in lambda_asset['VpcConfig']:
            #lambda_to_sg[lambda_asset['FunctionName']] = list()
            for group in lambda_asset['VpcConfig']['SecurityGroupIds']:
                if (asset_ids and group in asset_ids) or not asset_ids:
                    if group not in sg_to_lambda:
                        sg_to_lambda[group] = list()
                    sg_to_lambda[group].append(lambda_asset['FunctionName'])
                    #lambda_to_sg[lambda_asset['FunctionName']].append(group)
    return sg_to_lambda, sg_to_nic
