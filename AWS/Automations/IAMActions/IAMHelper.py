import argparse
import json
import logging
import sys
import boto3
import botocore.exceptions
import datetime


def log_setup(log_l):
    """This method setup the logging level an params
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
        '\t\t Welcome To Tamnoon AWS IAM Helper- The script that will help you with your IAM Service Actions \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t Supported Actions:\n'
        '\t\t\t\t 1. IAMUsers - last_activity, delete, ls, remove_console_access\n'


        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 IAMHelper.py --profile <aws_profile> --type <The Iam service type> --action <The action to execute> --params <the params for the action>\n'
        '\t\t\t\t python3 IAMHelper.py  --type IAMUser --action delete --assetIds "id1,id2" --dryRun True\n'
        '\t\t\t\t python3 IAMHelper.py  --type IAMUser --action last_activity --assetIds "id1,id2" --dryRun True\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile -  The AWS profile to use to execute this script\n'
        '\t\t\t\t type -     The AWS EC2 asset type - for example - instance,snapshot,security-group ....\n'
        '\t\t\t\t action -   The EC2 action to execute - (snapshot-delete, sg-delete)\n'
        '\t\t\t\t actionParmas  - A key value Dictionary of action params"\n'
        '\t\t\t\t assetIds  - List of assets ids (string seperated by commas)"\n'
        '\n\n'

    )
    print(text)


class DateTimeEncoder(json.JSONEncoder):
    import datetime
    def default(self, obj):
        if type(obj) == datetime.datetime:
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        return json.JSONEncoder.default(self, obj)


def setup_session(profile=None, region=None, aws_access_key=None, aws_secret=None):
    '''
    This method setup the boto session to AWS
    :param profile:  The aws credentials profile as they defined on the machine (~/.aws/credentials)
    :param region:   The aws target region to execute on
    :param aws_access_key:
    :param aws_secret:
    :return:
    '''
    if profile:
        if region:
            return boto3.Session(profile_name=profile, region_name=region)
        return boto3.Session(profile_name=profile)
    if aws_access_key and aws_secret:
        if region:
            return boto3.Session(region_name=region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
        return boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
    if region:
        return boto3.Session(region_name=region)
    return boto3.Session()


def _get_regions(regions_param, session):
    """
    This method extract thje list of regions to run over
    :param regions_param: The input region parameter - could be single region, multi regions (reg1,reg2...) or 'all'
    :param session: boto3 ec2 session
    :return:
    """
    regions_list = list()
    default_region = 'us-east-1'
    logging.info(f"Get regions")
    if 'all' in regions_param:
        try:
            account_client = session.client('account')
            response = account_client.list_regions(RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'])
            regions_list = [x["RegionName"] for x in response["Regions"]]
            logging.info(f"Got {len(regions_list)} regions")
            return regions_list
            # ec2_client = session.client('ec2')
            # response = ec2_client.describe_regions(AllRegions=True)
            # for region in response['Regions']:
            #    regions_list.append(region['RegionName'])

        except botocore.exceptions.NoRegionError as nr:
            logging.warning(f"falling back to default region - {default_region}")
            account_client = session.client('account', region_name=default_region)
            response = account_client.list_regions(RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'])
            regions_list = [x["RegionName"] for x in response["Regions"]]
            return regions_list

    return regions_param.split(",")


def _do_action(asset_type, session, dry_run, action, asset_ids, action_parmas=None):
    if asset_type == 'IAMUser':
        do_user_action(session=session, dry_run=dry_run, action=action, asset_ids=asset_ids)
    if asset_type == 'IAMRole':
        pass


def do_user_last_activity(resource, user_name):
    """
    Thi function check and return the last date of user activity in the console based on password last used
    :param resource: The boto iam resource
    :param user_name: The aws IAMUser name
    :param dry_run: Boolean flag to mark if this is dry run or not
    :return:
    """

    user = resource.User(user_name)
    result = dict()

    try:
        pwd_last_used = user.password_last_used
        if pwd_last_used:
            current_date = datetime.datetime.now().date()
            unused_for = (current_date - pwd_last_used.date()).days
            result['user'] = user_name
            result['last-password-used'] = pwd_last_used.strftime("%Y-%m-%d %H:%M:%S")
            result['unused for (in days)'] = unused_for
        else:
            result['user'] = user_name
            result['last-password-used'] = "Never"
            result['unused for (in days)'] = "Never Used"
        return result

    except Exception as e:
        logging.error(f"Something Went wrong - {e}")


def do_user_delete(session, user_name, dry_run):
    resource = session.resource('iam')
    user = resource.User(user_name)
    # Check if the user have access key , if so ignore the deletion need to understand the impact
    kys = user.access_keys.all()
    if len(list(kys)) > 0:
        logging.warning(
            f"Going to ignore deletion request fro user - {user_name}, The user has attached keys need to understand the impact of deletion")
        return
    else:
        try:
            iam_client = session.client('iam')
            # delete pwd
            logging.info(f"Going to remove Console access for user - {user_name}")
            try:
                response = iam_client.get_login_profile(UserName=user_name)
                if not dry_run:
                    iam_client.delete_login_profile(UserName=user_name)
                else:
                    logging.info(f"Dry run execution - {user_name} console access should removed - nothing executed!!")
            except Exception as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    logging.info(f"The uer doesn't have any console pwd defined")

            # Sining certificates
            logging.info(f"Going to remove signing certificates for user - {user_name}")
            response = iam_client.list_signing_certificates(UserName=user_name)
            if response['IsTruncated']:
                logging.warning(
                    f"Pagination over signin certificates is not supported yet -  to much certificates to delete going to skip")
                return
            for cert in response['Certificates']:
                if not dry_run:
                    iam_client.delete_signing_certificate(UserName=user_name, CertificateId=cert['CertificateId'])
                else:
                    logging.info(f"Dry run execution - {user_name} certificate - {cert['CertificateId']}  should removed - nothing executed!!")


            # ssh keys
            logging.info(f"Going to remove ssh public keys for user - {user_name}")
            response = iam_client.list_ssh_public_keys(UserName=user_name)
            if response['IsTruncated']:
                logging.warning(
                    f"Pagination over ssh public key is not supported yet - to much keys to delete going to skip")
                return
            for key in response['SSHPublicKeys']:
                if not dry_run:
                    iam_client.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key['SSHPublicKeyId'])
                else:
                    logging.info(
                        f"Dry run execution - {user_name} ssh key - {key['SSHPublicKeyId']}  should removed - nothing executed!!")

            # Git creds
            logging.info(f"Going to remove  service specific  keys to user - {user_name}")
            response = iam_client.list_service_specific_credentials(UserName=user_name)
            for service_specific_creds in response['ServiceSpecificCredentials']:
                if not dry_run:
                    logging.info(
                        f"Going to remove key for service - {service_specific_creds['ServiceName']}  to user - {user_name}")
                    res = iam_client.delete_service_specific_credential(UserName=user_name,
                                                                        ServiceSpecificCredentialId=service_specific_creds[
                                                                            'ServiceSpecificCredentialId'])
                else:
                    logging.info(
                        f"Dry run execution - {user_name} service specific key  - {service_specific_creds['ServiceName']}  should removed - nothing executed!!")

            # MFA delete
            logging.info(f"Going to delete MFA device for user - {user_name}")
            response = iam_client.list_mfa_devices(UserName=user_name)
            if response['IsTruncated']:
                logging.warning(
                    f"Pagination over mfa device is not supported yet -  to much devices to delete going to skip")
                return
            for mfa_device in response['MFADevices']:
                if not dry_run:
                    logging.info(f"Going to deactivate the MFA device - {mfa_device['SerialNumber']}")
                    iam_client.deactivate_mfa_device(UserName=user_name, SerialNumber=mfa_device['SerialNumber'])
                    logging.info(f"Going to delete MFA device - {mfa_device['SerialNumber']}")
                    response = iam_client.delete_virtual_mfa_device(SerialNumber=mfa_device['SerialNumber'])
                else:
                    logging.info(
                        f"Dry run execution - {user_name} MFA device  - {mfa_device['SerialNumber']}  should removed - nothing executed!!")

            # inline polices
            logging.info(f"Going to delete inline policies for user - {user_name}")
            response = iam_client.list_user_policies(UserName=user_name)
            if response['IsTruncated']:
                logging.warning(
                    f"Pagination over inline policies is not supported yet -  to much policies to delete going to skip")
                return
            for policy in response['PolicyNames']:
                if not dry_run:
                    logging.info(f"Going to remove the inline policy - {policy}")
                    iam_client.delete_user_policy(UserName=user_name, PolicyName=policy)
                else:
                    logging.info(
                        f"Dry run execution - {user_name} policy  - {policy}  should removed - nothing executed!!")
            # managed policies
            logging.info(f"Going to delete managed policies for user - {user_name}")
            response = iam_client.list_attached_user_policies(UserName=user_name)
            if response['IsTruncated']:
                logging.warning(
                    f"Pagination over managed policies is not supported yet -  to much policies to delete going to skip")
                return
            for policy in response['AttachedPolicies']:
                if not dry_run:
                    logging.info(f"Going to remove the managed policy - {policy['PolicyName']}")
                    iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
                else:
                    logging.info(
                        f"Dry run execution - {user_name} policy  - {policy['PolicyName']}  should removed - nothing executed!!")

            # group membership
            logging.info(f"Going to delete group membership for user - {user_name}")
            response = iam_client.list_groups_for_user(UserName=user_name)
            if response['IsTruncated']:
                logging.warning(
                    f"Pagination over users groups is not supported yet -  to much groups to delete going to skip")
                return
            for group in response['Groups']:
                if not dry_run:
                    logging.info(f"Going to remove the user -{user_name} from group - {group['GroupName']}")
                    iam_client.remove_user_from_group(GroupName=group['GroupName'], UserName=user_name)
                else:
                    logging.info(
                        f"Dry run execution - {user_name} group relation to - {group['GroupName']}  should removed - nothing executed!!")

            if not dry_run:
                logging.info(f"Going to delete the user - {user_name}")
                user.delete()
            else:
                logging.info(
                    f"Dry run execution - {user_name}  should removed - nothing executed!!")

        except Exception as e:
            logging.error(f"Something went wrong - {e}")


def do_ls(session):
    iam_client = session.client('iam')
    final_result = dict()
    final_result['Users'] = list()
    response = iam_client.list_users()
    final_result['Users'] = final_result['Users'] + response['Users']
    while response['IsTruncated']:
        response = iam_client.list_users(Marker=response['Marker'])
        final_result['Users'] = final_result['Users'] + response['Users']
    return final_result


def do_remove_concole_access(session, user_name, dry_run):
    iam_client = session.client('iam')
    # delete pwd
    logging.info(f"Going to remove Console access for user - {user_name}")
    try:
        response = iam_client.get_login_profile(UserName=user_name)
        if not dry_run:
            iam_client.delete_login_profile(UserName=user_name)
        else:
            logging.info(f"Dry run -{user_name}  should be deleted - Nothing executed!!")
    except Exception as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            logging.info(f"The uer doesn't have any console pwd defined")


def do_user_action(session, dry_run, action, asset_ids):
    """
    This function is the implementation for IAMUser actions
    :param session: boto3 session
    :param asset_id:
    :param dry_run:
    :param action:
    :return:
    """
    if action == 'last_activity':
        resource = session.resource('iam')
        pretty_result = list()
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            pretty_result.append(do_user_last_activity(resource=resource, user_name=asset_id))
        print(json.dumps(pretty_result, indent=4))

    if action == 'delete':
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_user_delete(session=session, user_name=asset_id, dry_run=dry_run)

    if action == 'ls':
        users = do_ls(session=session)
        print(json.dumps(users, cls=DateTimeEncoder, indent=4))

    if action == 'remove_console_access':
        for asset_id in asset_ids:
            logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
            do_remove_concole_access(session=session, user_name=asset_id, dry_run=dry_run)


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--type', required=True, type=str)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--regions', required=False, type=str, default=None)
    parser.add_argument('--awsAccessKey', required=False, type=str, default=None)
    parser.add_argument('--awsSecret', required=False, type=str, default=None)
    parser.add_argument('--assetIds', required=False, type=str)
    parser.add_argument('--actionParams', required=False, type=json.loads, default=None)
    parser.add_argument('--dryRun', required=False, type=bool, default=False)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = None
    profile = args.profile
    action = args.action
    asset_ids = args.assetIds
    asset_ids = asset_ids.split(',') if asset_ids else None
    params = args.actionParams
    dry_run = args.dryRun
    asset_type = args.type

    aws_access_key = args.awsAccessKey
    aws_secret = args.awsSecret

    result = dict()

    session = setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret)

    _do_action(asset_type=asset_type, session=session, dry_run=dry_run, action=action,
               asset_ids=asset_ids,
               action_parmas=params)


