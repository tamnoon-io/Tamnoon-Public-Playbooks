import argparse
import json
import logging
import os
import sys
import datetime

from typing import List
from ..Utils import utils as utils

try:
    from Automations.IAMActions import help_jsons_data
except ModuleNotFoundError as ex:
    pass

IAMUser_remove_console_access_readme_data = (
    help_jsons_data.iam_user_remove_console_access_readme_data
    if hasattr(help_jsons_data, "iam_user_remove_console_access_readme_data")
    else dict()
)
IAMUser_delete_readme_data = (
    help_jsons_data.iam_user_delete_readme_data
    if hasattr(help_jsons_data, "iam_user_delete_readme_data")
    else dict()
)
IAMUser_deactivate_access_key_readme_data = (
    help_jsons_data.iam_user_deactivate_access_key_readme_data
    if hasattr(help_jsons_data, "iam_user_deactivate_access_key_readme_data")
    else dict()
)
IAMUser_last_activity_readme_data = (
    help_jsons_data.iam_user_last_activity_readme_data
    if hasattr(help_jsons_data, "iam_user_last_activity_readme_data")
    else dict()
)
IAMUser_ls_readme_data = (
    help_jsons_data.iam_user_ls_readme_data
    if hasattr(help_jsons_data, "iam_user_ls_readme_data")
    else dict()
)
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


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
        '\t\t\t\t python3 IAMHelper.py  --type iam-user --action delete --assetIds "id1,id2" --dryRun True\n'
        '\t\t\t\t python3 IAMHelper.py  --type iam-user --action last_activity --assetIds "id1,id2" --dryRun True\n'
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


def do_user_last_activity(
        asset_type,
        session,
        dry_run,
        action,
        asset_ids,
        action_params
):
    resource = session.resource('iam')
    output_result = dict()
    output_result["executionResults"] = list()
    pretty_result = list()
    for asset_id in asset_ids:
        logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
        user_name = asset_id
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

        except Exception as e:
            logging.error(f"Something Went wrong - {e}")
        pretty_result.append(result)
    output_result["executionResults"] = pretty_result
    return output_result


def do_user_delete(
        asset_type,
        session,
        dry_run,
        action,
        asset_ids,
        action_params
):
    result = dict()
    result["executionResults"] = list()
    for asset_id in asset_ids:
        logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
        results = dict()
        user_name = asset_id
        resource = session.resource('iam')
        user = resource.User(user_name)
        step_iterator = 1
        # Check if the user have access key , if so ignore the deletion need to understand the impact
        kys = user.access_keys.all()
        if len(list(kys)) > 0:
            logging.warning(
                f"Going to ignore deletion request for user - {user_name}, The user has attached keys need to "
                f"understand the impact of deletion")
            results.update(
                {
                    "asset_id": user_name,
                    "action": f"Ignored deletion request for user - {user_name}, The user has attached keys need to understand the impact of deletion",
                    "status": "Fail"
                }
            )
            result["executionResults"].append(results)
            break
        else:
            try:
                iam_client = session.client('iam')
                # delete pwd
                logging.info(f"Going to remove Console access for user - {user_name}")
                try:
                    response = iam_client.get_login_profile(UserName=user_name)
                    if not dry_run:
                        iam_client.delete_login_profile(UserName=user_name)
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Deleted Login Profile of user - {user_name}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} console access should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Dry run execution - {user_name} console access should removed - nothing executed!!",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1
                except Exception as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        logging.info(f"The user doesn't have any console pwd defined")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Error: The user doesn't have any console pwd defined",
                                "status": "Fail"
                            }
                        )
                        step_iterator += 1

                # Signing certificates
                logging.info(f"Going to remove signing certificates for user - {user_name}")
                response = iam_client.list_signing_certificates(UserName=user_name)
                if response['IsTruncated']:
                    logging.warning(
                        f"Pagination over signin certificates is not supported yet -  to much certificates to delete "
                        f"going to skip")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Error: Pagination over signin certificates is not supported yet -  to much certificates to delete going to skip",
                            "status": "Fail"
                        }
                    )
                    step_iterator += 1

                    result["executionResults"].append(results)
                    break
                for cert in response['Certificates']:
                    if not dry_run:
                        iam_client.delete_signing_certificate(UserName=user_name, CertificateId=cert['CertificateId'])
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Deleted signing certificate for user - {user_name}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} certificate - {cert['CertificateId']}  should removed - "
                            f"nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Mock Delete signing certificate for user - {user_name}",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1

                # ssh keys
                logging.info(f"Going to remove ssh public keys for user - {user_name}")
                response = iam_client.list_ssh_public_keys(UserName=user_name)
                if response['IsTruncated']:
                    logging.warning(
                        f"Pagination over ssh public key is not supported yet - to much keys to delete going to skip")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Pagination over ssh public key is not supported yet - to much keys to delete going to skip",
                            "status": "Fail"
                        }
                    )
                    step_iterator += 1
                    result["executionResults"].append(results)
                    break
                for key in response['SSHPublicKeys']:
                    if not dry_run:
                        iam_client.delete_ssh_public_key(UserName=user_name, SSHPublicKeyId=key['SSHPublicKeyId'])
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Deleted SSH public key - {key['SSHPublicKeyId']} for user - {user_name}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} ssh key - {key['SSHPublicKeyId']}  should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                "action": f"Mock Delete SSH public key - {key['SSHPublicKeyId']} for user - {user_name}",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1

                # Git creds
                logging.info(f"Going to remove  service specific  keys to user - {user_name}")
                response = iam_client.list_service_specific_credentials(UserName=user_name)
                for service_specific_creds in response['ServiceSpecificCredentials']:
                    if not dry_run:
                        logging.info(
                            f"Going to remove key for service - {service_specific_creds['ServiceName']}  to user - {user_name}")
                        res = iam_client.delete_service_specific_credential(UserName=user_name,
                                                                            ServiceSpecificCredentialId=
                                                                            service_specific_creds[
                                                                                'ServiceSpecificCredentialId'])
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Removed key for service - {service_specific_creds['ServiceSpecificCredentialId']} for user - {user_name}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} service specific key  - {service_specific_creds['ServiceName']}  should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Dry run execution - {user_name} service specific key  - {service_specific_creds['ServiceName']}  should removed - nothing executed!!",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1

                # MFA delete
                logging.info(f"Going to delete MFA device for user - {user_name}")
                response = iam_client.list_mfa_devices(UserName=user_name)
                if response['IsTruncated']:
                    logging.warning(
                        f"Pagination over mfa device is not supported yet -  to much devices to delete going to skip")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Pagination over mfa device is not supported yet -  to much devices to delete going to skip",
                            "status": "Fail"
                        }
                    )
                    step_iterator += 1
                    result["executionResults"].append(results)
                    break
                for mfa_device in response['MFADevices']:
                    if not dry_run:
                        logging.info(f"Going to deactivate the MFA device - {mfa_device['SerialNumber']}")
                        iam_client.deactivate_mfa_device(UserName=user_name, SerialNumber=mfa_device['SerialNumber'])
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Deactivated the MFA device - {mfa_device['SerialNumber']}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                        logging.info(f"Going to delete MFA device - {mfa_device['SerialNumber']}")
                        response = iam_client.delete_virtual_mfa_device(SerialNumber=mfa_device['SerialNumber'])
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Deleted MFA device - {mfa_device['SerialNumber']}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} MFA device  - {mfa_device['SerialNumber']}  should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Dry run execution - {user_name} MFA device  - {mfa_device['SerialNumber']}  should removed - nothing executed!!",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1

                # inline polices
                logging.info(f"Going to delete inline policies for user - {user_name}")
                response = iam_client.list_user_policies(UserName=user_name)
                if response['IsTruncated']:
                    logging.warning(
                        f"Pagination over inline policies is not supported yet -  to much policies to delete going to skip")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Pagination over inline policies is not supported yet -  to much policies to delete going to skip",
                            "status": "Fail"
                        }
                    )
                    step_iterator += 1
                    result["executionResults"].append(results)
                    break
                for policy in response['PolicyNames']:
                    if not dry_run:
                        logging.info(f"Going to remove the inline policy - {policy}")
                        iam_client.delete_user_policy(UserName=user_name, PolicyName=policy)
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Removed the inline policy - {policy}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} policy  - {policy}  should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Dry run execution - {user_name} policy  - {policy}  should removed - nothing executed!!",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1
                # managed policies
                logging.info(f"Going to delete managed policies for user - {user_name}")
                response = iam_client.list_attached_user_policies(UserName=user_name)
                if response['IsTruncated']:
                    logging.warning(
                        f"Pagination over managed policies is not supported yet -  to much policies to delete going to skip")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Pagination over managed policies is not supported yet -  to much policies to delete going to skip",
                            "status": "Fail"
                        }
                    )
                    step_iterator += 1
                    result["executionResults"].append(results)
                    break
                for policy in response['AttachedPolicies']:
                    if not dry_run:
                        logging.info(f"Going to remove the managed policy - {policy['PolicyName']}")
                        iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Removed the managed policy - {policy['PolicyName']}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} policy  - {policy['PolicyName']}  should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Dry run execution - {user_name} policy  - {policy['PolicyName']}  should removed - nothing executed!!",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1

                # group membership
                logging.info(f"Going to delete group membership for user - {user_name}")
                response = iam_client.list_groups_for_user(UserName=user_name)
                if response['IsTruncated']:
                    logging.warning(
                        f"Pagination over users groups is not supported yet -  to much groups to delete going to skip")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Pagination over users groups is not supported yet -  to much groups to delete going to skip",
                            "status": "Fail"
                        }
                    )
                    step_iterator += 1
                    result["executionResults"].append(results)
                    break
                for group in response['Groups']:
                    if not dry_run:
                        logging.info(f"Going to remove the user -{user_name} from group - {group['GroupName']}")
                        iam_client.remove_user_from_group(GroupName=group['GroupName'], UserName=user_name)
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Removed the user -{user_name} from group - {group['GroupName']}",
                                "status": "Success"
                            }
                        )
                        step_iterator += 1
                    else:
                        logging.info(
                            f"Dry run execution - {user_name} group relation to - {group['GroupName']}  should removed - nothing executed!!")
                        results.update(
                            {
                                "asset_id": user_name,
                                f"step-{step_iterator}": f"Dry run execution - {user_name} group relation to - {group['GroupName']}  should removed - nothing executed!!",
                                "status": "Dry-run"
                            }
                        )
                        step_iterator += 1

                if not dry_run:
                    logging.info(f"Going to delete the user - {user_name}")
                    user.delete()
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Deleted the user - {user_name}",
                            "status": "Success"
                        }
                    )
                    step_iterator += 1
                else:
                    logging.info(
                        f"Dry run execution - {user_name}  should removed - nothing executed!!")
                    results.update(
                        {
                            "asset_id": user_name,
                            f"step-{step_iterator}": f"Dry run execution - {user_name}  should removed - nothing executed!!",
                            "status": "Dry-run"
                        }
                    )
                    step_iterator += 1

            except Exception as e:
                logging.error(f"Something went wrong - {e}")
                results.update(
                    {
                        "asset_id": user_name,
                        f"step-{step_iterator}": f"Error: Something went wrong - {e}",
                        "status": "Fail"
                    }
                )
                step_iterator += 1
        result["executionResults"].append(results)

    return result


def do_ls(
        asset_type,
        session,
        dry_run,
        action,
        asset_ids,
        action_params
):
    iam_client = session.client('iam')
    result = dict()
    result["executionResults"] = None
    final_result = dict()
    final_result['Users'] = list()
    response = iam_client.list_users()
    final_result['Users'] = final_result['Users'] + response['Users']
    while response['IsTruncated']:
        response = iam_client.list_users(Marker=response['Marker'])
        final_result['Users'] = final_result['Users'] + response['Users']
    result["executionResults"] = final_result
    return result


def do_remove_console_access(
        asset_type,
        session,
        dry_run,
        action,
        asset_ids,
        action_params
):
    result = dict()
    result['executionResults'] = list()
    for asset_id in asset_ids:
        logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")
        user_name = asset_id

        iam_client = session.client('iam')
        # delete pwd
        logging.info(f"Going to remove Console access for user - {user_name}")
        results = list()
        try:
            response = iam_client.get_login_profile(UserName=user_name)
            if not dry_run:
                iam_client.delete_login_profile(UserName=user_name)
                results.append(
                    {
                        "asset_id": user_name,
                        "action": f"removed console access of username - {user_name}",
                        "status": "Success"
                    }
                )
            else:
                logging.info(f"Dry run -{user_name}  console access should be removed - Nothing executed!!")
                results.append(
                    {
                        "asset_id": user_name,
                        "action": f"Didn't remove console access of username - {user_name}",
                        "status": "Dry-run"
                    }
                )
        except Exception as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                logging.info(f"The user doesn't have any console pwd defined")
                results.append(
                    {
                        "asset_id": user_name,
                        "action": f"The user doesn't have any console pwd defined",
                        "status": "Fail"
                    }
                )
        result['executionResults'].extend(results)
    return result


def do_key_deactivation(
        asset_type,
        session,
        dry_run,
        action,
        asset_ids,
        action_params
):
    result = dict()
    result['executionResults'] = list()
    client = session.client('iam')
    for asset_id in asset_ids:
        specific_keys = action_params['specificKeys'].split(
            ",") if action_params and 'specificKeys' in action_params else None
        is_roll_back = action_params['rollBack'] if action_params and 'rollBack' in action_params else None
        logging.info(f"Going to execute - {action} for asset type - {asset_type} asset - {asset_id}")

        user_name = asset_id
        results = list()
        if specific_keys:

            for specific_key in specific_keys:
                if not is_roll_back:
                    response = client.update_access_key(
                        UserName=user_name,
                        AccessKeyId=specific_key,
                        Status='Inactive'
                    )
                    results.append(
                        {
                            "asset_id": user_name,
                            "action": f"Inactive access key - {specific_key}",
                            "status": "Success"
                        }
                    )
                else:
                    response = client.update_access_key(
                        UserName=user_name,
                        AccessKeyId=specific_key,
                        Status='Active'
                    )
                    results.append(
                        {
                            "asset_id": user_name,
                            "action": f"Inactive access key - {specific_key}",
                            "status": "Roll-Back"
                        }
                    )
        else:
            # get all access key of user
            response = client.list_access_keys(UserName=user_name)
            for access_key in response['AccessKeyMetadata']:
                access_key_id = access_key['AccessKeyId']

                if dry_run:
                    logging.info(f"DryRun - update access key - {access_key_id} , make Inactive")
                    results.append(
                        {
                            "asset_id": user_name,
                            "action": f"Re active access key - {access_key_id}",
                            "status": "Dry-run"
                        }
                    )

                if not is_roll_back:
                    response = client.update_access_key(
                        UserName=user_name,
                        AccessKeyId=access_key_id,
                        Status='Inactive'
                    )
                    results.append(
                        {
                            "asset_id": user_name,
                            "action": f"Inactive access key - {access_key_id}",
                            "status": "Success"
                        }
                    )
                else:
                    response = client.update_access_key(
                        UserName=user_name,
                        AccessKeyId=access_key_id,
                        Status='Active'
                    )
                    results.append(
                        {
                            "asset_id": user_name,
                            "action": f"Inactive access key - {access_key_id}",
                            "status": "Roll-Back"
                        }
                    )
        result['executionResults'].extend(results)
    return result


def common_args(parser, args_json_data):
    parser.add_argument(
        "--profile",
        required=False,
        default=None,
        metavar="",
        help=args_json_data.get("profile"),
    )
    parser.add_argument(
        "--awsAccessKey",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsAccessKey"),
    )
    parser.add_argument(
        "--awsSecret",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsSecret"),
    )
    parser.add_argument(
        "--awsSessionToken",
        required=False,
        type=str,
        default=None,
        metavar="",
        help=args_json_data.get("awsSessionToken")
    )
    parser.add_argument(
        "--file",
        required=False,
        metavar="",
        type=str,
        default=None,
        help=args_json_data.get("file"),
    )
    parser.add_argument(
        "--logLevel",
        required=False,
        choices=["INFO", "DEBUG", "WARN", "ERROR"],
        metavar="",
        type=str,
        default="INFO",
        help=args_json_data.get("logLevel"),
    )
    parser.add_argument(
        "--outputType",
        required=False,
        metavar="",
        type=str,
        default="json",
        help=args_json_data.get("outputType"),
    )
    parser.add_argument(
        "--outDir",
        required=False,
        metavar="",
        type=str,
        default=os.getcwd(),
        help=args_json_data.get("outDir"),
    )
    parser.add_argument(
        "--testId",
        required=False,
        metavar="",
        type=str,
        help=args_json_data.get("testId"),
    )


def main(argv: List):
    """
    main function
    """

    parser_usage = common_json_data.get("usage", dict()).get("IAMActions", "")
    usage = parser_usage + " [-h]"
    if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
        utils.print_help_valid_types(
            common_json_data.get("help", dict()).get(
                "IAMActions", dict()), usage
        )
        sys.exit(1)

    # help mapping for iam-user Actions - Help Content is mapped with associated action of type iam-user.
    IAMUser_help = {
        'delete': IAMUser_delete_readme_data,
        'remove_console_access': IAMUser_remove_console_access_readme_data,
        'deactivate_access_key': IAMUser_deactivate_access_key_readme_data,
        'last_activity': IAMUser_last_activity_readme_data,
        'ls': IAMUser_ls_readme_data
    }
    type_IAMUser_help = {
        str(key): value.get("help", "None") for key, value in IAMUser_help.items()
    }
    parser = argparse.ArgumentParser(
        usage=parser_usage,
        conflict_handler="resolve",
    )
    type_subparser = parser.add_subparsers(
        title="type", help="choose iam-user automation type", dest="type", metavar=""
    )

    IAMUser_parser = type_subparser.add_parser(
        name="iam-user",
        formatter_class=argparse.RawTextHelpFormatter
    )
    IAMUser_action_subparser = IAMUser_parser.add_subparsers(
        title="choose iam-user action", dest='action', metavar="", description=utils.type_help(
            type_IAMUser_help)
    )
    IAMUser_delete_parser = IAMUser_action_subparser.add_parser(
        name='delete', formatter_class=argparse.RawTextHelpFormatter
    )
    IAMUser_remove_console_access_parser = IAMUser_action_subparser.add_parser(
        name='remove_console_access', formatter_class=argparse.RawTextHelpFormatter
    )
    IAMUser_deactivate_access_key_parser = IAMUser_action_subparser.add_parser(
        name='deactivate_access_key', formatter_class=argparse.RawTextHelpFormatter
    )
    IAMUser_last_activity_parser = IAMUser_action_subparser.add_parser(
        name='last_activity', formatter_class=argparse.RawTextHelpFormatter
    )
    IAMUser_ls_parser = IAMUser_action_subparser.add_parser(
        name='ls', formatter_class=argparse.RawTextHelpFormatter
    )

    # Overriding "optional arguments" to corresponding "action" in help CLI message
    IAMUser_delete_parser._optionals.title = "delete"
    IAMUser_remove_console_access_parser._optionals.title = "remove_console_access"
    IAMUser_deactivate_access_key_parser._optionals.title = "deactivate_access_key"
    IAMUser_last_activity_parser._optionals.title = "last_activity"
    IAMUser_ls_parser._optionals.title = "ls"

    asset_type = sys.argv[1]
    action = sys.argv[2]

    args_json_data = IAMUser_help.get(action, {}).get("cli_args", {})
    common_args(IAMUser_delete_parser, args_json_data=args_json_data)
    common_args(IAMUser_remove_console_access_parser, args_json_data=args_json_data)
    common_args(IAMUser_deactivate_access_key_parser, args_json_data=args_json_data)
    common_args(IAMUser_last_activity_parser, args_json_data=args_json_data)
    common_args(IAMUser_ls_parser, args_json_data=args_json_data)

    if action == "delete":
        IAMUser_delete_parser.add_argument(
            "--assetIds",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("assetIds")
        )
        IAMUser_delete_parser.add_argument(
            "--dryRun",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("dryRun"),
        )
    if action == "remove_console_access":
        IAMUser_remove_console_access_parser.add_argument(
            "--assetIds",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("assetIds")
        )
        IAMUser_remove_console_access_parser.add_argument(
            "--dryRun",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("dryRun"),
        )
    if action == "last_activity":
        IAMUser_last_activity_parser.add_argument(
            "--assetIds",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("assetIds")
        )

    if action == "deactivate_access_key":
        IAMUser_deactivate_access_key_parser.add_argument(
            "--assetIds",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("assetIds")
        )
        IAMUser_deactivate_access_key_parser.add_argument(
            "--actionParams",
            required=False,
            default=None,
            metavar="",
            help=args_json_data.get("actionParams"),
        )
        IAMUser_deactivate_access_key_parser.add_argument(
            "--dryRun",
            required=False,
            metavar="",
            type=str,
            help=args_json_data.get("dryRun"),
        )

    args = parser.parse_args()
    params = utils.build_params(args=args)
    if not params:
        print(sys.exc_info())
        exit(0)

    # Function Mapping - Function is mapped with associated asset_type and action.
    function_mapping = {
        "iam-user": {
            "delete": do_user_delete,
            "remove_console_access": do_remove_console_access,
            "deactivate_access_key": do_key_deactivation,
            "last_activity": do_user_last_activity,
            "ls": do_ls
        }
    }

    action_result = dict()

    profile = params.get(
        "profile") if args.file is not None else params.profile
    aws_access_key = params.get(
        "awsAccessKey") if args.file is not None else params.awsAccessKey
    aws_secret = params.get(
        "awsSecret") if args.file is not None else params.awsSecret
    aws_session_token = params.get(
        "awsSessionToken") if args.file is not None else params.awsSessionToken
    dry_run = params.get(
        "dryRun") if args.file is not None else params.dryRun
    log_level = params.get(
        "logLevel") if args.file is not None else params.logLevel

    output_type = params.get(
        "outputType", "JSON") if args.file is not None else str(params.outputType)

    output_directory = params.get(
        "outDir", "./") if args.file is not None else str(params.outDir)

    test_id = params.get(
        "testId", None) if args.file is not None else str(params.testId)
    if test_id is not None:
        action_result['testId'] = test_id

    if params.get("assetIds") is None:
        asset_ids = []
    elif args.file is None:
        asset_ids = params.assetIds.split(",")
    else:
        asset_ids = params.get('assetIds', [])

    action_params = params.get(
        'actionParams', None) if args.file is not None else params.actionParams

    action_params = json.loads(action_params) if action_params and not isinstance(
        action_params, dict) else params.get('actionParams', None)
    try:
        utils.log_setup(log_level)
        logging.debug("python3 -m Automations.IAMActions %s",
                      " ".join(sys.argv[1:]))
        logging.debug(params)

        session = utils.setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret,
                                      aws_session_token=aws_session_token)
        caller_identity = utils.get_caller_identity(session=session)
        action_result = function_mapping[asset_type][action](
            asset_type=asset_type,
            session=session,
            dry_run=dry_run,
            action=action,
            asset_ids=asset_ids,
            action_params=action_params
        )
        action_result['caller-identity'] = caller_identity

    except Exception as ex:
        logging.error("Something Went wrong!!", exc_info=log_level == "DEBUG")
        action_result['status'] = 'Error'
        action_result['message'] = str(ex)
    filename = os.path.join(
        output_directory,
        f"Tamnoon-IAMAction-{asset_type}-{action.replace('_', '-')}-execution-result"
        + "."
        + output_type,
    )
    utils.export_data(filename, action_result)


if __name__ == "__main__":
    main(sys.argv)
