import argparse
import json
import logging
import boto3
import botocore
from  botocore import exceptions
boto3.set_stream_logger('boto3', logging.ERROR)

import sys


def log_setup(log_l):
    """
        This method setup the logging level an params
        logs output path can be controlled by the log stdout cmd param (stdout / file)
    """
    logging.basicConfig(format='[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s')
    log_level = log_l
    logging.getLogger().setLevel(log_level)


def print_help():
    text = (
        '\n'
        '\n '
        '''

\t\t\t ___                                                                                           
\t\t\t(   )                                                                            .-.           
\t\t\t | |_       .---.   ___ .-. .-.    ___ .-.     .--.     .--.    ___ .-.         ( __)   .--.   
\t\t\t(   __)    / .-, \ (   )   '   \  (   )   \   /    \   /    \  (   )   \        (''")  /    \  
\t\t\t | |      (__) ; |  |  .-.  .-. ;  |  .-. .  |  .-. ; |  .-. ;  |  .-. .         | |  |  .-. ; 
\t\t\t | | ___    .'`  |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | |(   )  / .'| |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | | | |  | /  | |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | ' | |  ; |  ; |  | |  | |  | |  | |  | |  | '  | | | '  | |  | |  | |   .-.   | |  | '  | | 
\t\t\t ' `-' ;  ' `-'  |  | |  | |  | |  | |  | |  '  `-' / '  `-' /  | |  | |  (   )  | |  '  `-' / 
\t\t\t  `.__.   `.__.'_. (___)(___)(___)(___)(___)  `.__.'   `.__.'  (___)(___)  `-'  (___)  `.__.'  

        '''
        '\t\t Welcome Tamnoon Remediation script for unused default security groups \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t To run this script you should have:\n'
        '\t\t\t\t 1.EC2 write permissions to modify security group in a given account\n'
        '\t\t\t\t 2.Filesystem write permissions to the state file path to read/write for the execution state file\n'
        '\t\t\t\t 3.Python v3.6 and above and boto3 package installed\n'
        '\t\t\t'
        '\n'
        '\t\t\t\t The script is based on AWS Boto3 API \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.SecurityGroup.revoke_ingress'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.SecurityGroup.revoke_egress\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 TAWSDefaultSGRemidiation.py --profile <aws authz profile> --statePath <path to state json file > \n'
        '\t\t\t\t python3 TAWSDefaultSGRemidiation.py --profile <aws authz profile> --statePath <path to state json file > --rollBack True\n'
        '\t\t\t\t python3 TAWSDefaultSGRemidiation.py --profile <aws authz profile> --statePath <path to state json file > --rollBack True --sgTorollBack <sg id of the sg to rollback>\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile -  The AWS creds profile to use\n'
        '\t\t\t\t dryRun - (optional) A flag that will mark to avoid actual execution of revoking and just check permissions"\n'
        '\t\t\t\t statePath -  The full path to a JSON file that will contain the current revoked sg states in a case we want to rollback\n'
        '\t\t\t\t rollBack - (optional) A flag that sign if this is a rollback execution\n'
        '\t\t\t\t sgTorollBack - The id for specific security group that we want to rollback\n'
        '\n\n'

    )
    print(text)


def _get_reslut_by_api(d9key, d9secret):
    pass


def _load_from_file(result_file):
    with open(result_file, 'r') as result_json:
        return json.load(result_json)


def _remove_defaut_sg_rules(sg, ec2_resource, is_dry_run):
    security_group = ec2_resource.SecurityGroup(sg['GroupId'])
    if len(sg['IpPermissions']) == 0:
        logging.info(f"No ingress rules to remove for sg- {sg['GroupName']}-{sg['GroupId']}")
    else:
        security_group.revoke_ingress(IpPermissions=sg['IpPermissions'], DryRun=is_dry_run)


    if len(sg['IpPermissionsEgress']) == 0:
        logging.info(f"No egress rules to remove for sg- {sg['GroupName']}-{sg['GroupId']}")
    else:
        security_group.revoke_egress(IpPermissions=sg['IpPermissionsEgress'], DryRun=is_dry_run)



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
            if 'Ingress' in permissions:
                _auth_ingress(permissions['Ingress'], sg_id, region_ec2_resource)
            if 'Egress' in permissions:
                _auth_egress(permissions['Egress'], sg_id, region_ec2_resource)
    else:
        logging.info(f"Going to rollback sg - {sg_id} in region - {region}")
        permissions = sg_definition[sg_id]
        if 'Ingress' in permissions:
            _auth_ingress(permissions['Ingress'], sg_id, region_ec2_resource)
        if 'Egress' in permissions:
            _auth_egress(permissions['Egress'], sg_id, region_ec2_resource)



if __name__ == '__main__':
    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default="")
    parser.add_argument('--dryRun', required=False, default=False)
    parser.add_argument('--statePath', required=True)
    parser.add_argument('--rollBack', required=False, default=False)
    parser.add_argument('--sgTorollBack', required=False, default="All")

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()
    log_setup(args.logLevel)

    aws_profile = args.profile
    is_dry_run = args.dryRun
    is_rollback = args.rollBack
    state_path = args.statePath
    sg_to_rb = args.sgTorollBack

    if is_rollback:
        logging.info(f"Start execute security group roll back for - {sg_to_rb}")
    else:
        logging.info(f"Start execute security group rule removal")

    state_dict = dict()

    if not is_rollback:
        with open(state_path, "w") as state_path_json:
            try:
                session = boto3.Session(profile_name=aws_profile)
                client = session.client('ec2')
                regions = client.describe_regions()
            except botocore.exceptions.NoRegionError:
                session = boto3.Session(profile_name=aws_profile,
                                        region_name='us-east-1')
                client = session.client('ec2')
                regions = client.describe_regions()

            # For each region in aws it will create specific ec2 client and ec2 resource
            for region in regions['Regions']:

                region_session = boto3.Session(profile_name=aws_profile, region_name=region['RegionName'])
                region_ec2_resource = region_session.resource('ec2')
                region_client = region_session.client('ec2')

                # describe all the sg in the region
                res_desc_sg = region_client.describe_security_groups()

                # get all the nics in teh region to check attachment of default sg
                response_nics = region_client.describe_network_interfaces()

                is_attached = False
                for sg in res_desc_sg['SecurityGroups']:
                    sg_name = sg['GroupName']
                    sg_id = sg['GroupId']
                    sg_ip_permissions = sg['IpPermissions']
                    sg_ip_permissions_egress = sg['IpPermissionsEgress']
                    # in case that we focus only on default sg
                    if sg_name != 'default': continue

                    for nic in response_nics['NetworkInterfaces']:
                        for group in nic['Groups']:
                            if group['GroupId'] == sg['GroupId']:
                                is_attached = True
                                break
                        if is_attached:
                            break

                    if is_attached:
                        logging.warning(f"security group name - {sg['GroupName']}, id - {sg['GroupId']} is attahced to some nics in region - {region['RegionName']}")
                    else:
                        logging.info(f"Going to remove rulse for sg - {sg['GroupId']} in region - {region['RegionName']}")

                        # Save the current sg in the sg state for rollback purpose
                        if region['RegionName'] not in state_dict:
                            state_dict[region['RegionName']] = dict()
                        state_dict[region['RegionName']][sg_id] = dict()
                        state_dict[region['RegionName']][sg_id]['Ingress'] = sg_ip_permissions
                        state_dict[region['RegionName']][sg_id]['Egress'] = sg_ip_permissions_egress

                        _remove_defaut_sg_rules(sg, region_ec2_resource, is_dry_run)

            json.dump(state_dict, state_path_json)
    else:
        with open(state_path, "r") as state_path_json:
            state = json.load(state_path_json)
            if sg_to_rb == 'All':
                for region, sg_definition in state.items():

                    region_session = boto3.Session(profile_name=aws_profile, region_name=region)
                    _execute_rollback(region_session, region, sg_definition)
            else:
                for region, sg_definition in state.items():
                    if sg_to_rb in sg_definition:
                        region_session = boto3.Session(profile_name=aws_profile, region_name=region)
                        _execute_rollback(region_session, region, sg_definition, sg_to_rb)






