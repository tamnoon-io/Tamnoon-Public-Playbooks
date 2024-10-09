import argparse
import json
import logging
import sys
import os
from argparse import ArgumentParser
from typing import List
import botocore.exceptions

from ..Utils import utils as utils

try:
    from Automations.S3Actions import help_jsons_data
except ModuleNotFoundError as ex:
    pass

s3_deny_http_access_readme_data = (
    help_jsons_data.s3_deny_http_access_readme_data
    if hasattr(help_jsons_data, "s3_deny_http_access_readme_data")
    else dict()
)
s3_enable_mfa_protection_readme_data = (
    help_jsons_data.s3_enable_mfa_protection_readme_data
    if hasattr(help_jsons_data, "s3_enable_mfa_protection_readme_data")
    else dict()
)
s3_check_public_access_readme_data = (
    help_jsons_data.s3_check_public_access_readme_data
    if hasattr(help_jsons_data, "s3_check_public_access_readme_data")
    else dict()
)
s3_enable_encryption_readme_data = (
    help_jsons_data.s3_enable_encryption_readme_data
    if hasattr(help_jsons_data, "s3_enable_encryption_readme_data")
    else dict()
)
s3_enable_server_logging_readme_data = (
    help_jsons_data.s3_enable_server_logging_readme_data
    if hasattr(help_jsons_data, "s3_enable_server_logging_readme_data")
    else dict()
)
s3_enable_versioning_readme_data = (
    help_jsons_data.s3_enable_versioning_readme_data
    if hasattr(help_jsons_data, "s3_enable_versioning_readme_data")
    else dict()
)
s3_block_public_access_readme_data = (
    help_jsons_data.s3_block_public_access_readme_data
    if hasattr(help_jsons_data, "s3_block_public_access_readme_data")
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
        '\t\t Welcome To S3 soft remediation \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t This script will know how to handle soft configuration for remediate s3 misconfiguration\n '
        '\t\t\t Supported Actions:\n'
        '\t\t\t\t 1. Bucket Server side logging\n'
        '\t\t\t\t\t params -  "{\"target_bucket\":<The name of the s3 bucket that will contain the logs>}"\n'
        '\t\t\t\t 2. Bucket Server side encryption\n'
        '\t\t\t\t\t params- "{\"kms\":<The arn of the kms managed key to use>}\n'
        '\t\t\t\t 3. Bucket Versioning\n'
        '\t\t\t\t 4. Bucket MFA deletion protection\n'
        '\t\t\t\t\t params -"{\"mfa\":<The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device>}\n'
        '\t\t\t\t\t\t "for example - "{\"mfa\":\"arn:aws:iam::123456789:mfa/bob 572055\"}" where 572055 is the serial from that mfa on execution time\n'
        '\t\t\t\t 4. Bucket Configure public access\n'
        '\t\t\t\t\t\t params (optional) -BlockPublicAcls or IgnorePublicAcls or BlockPublicPolicy or RestrictPublicBuckets - True/False\n'
        '\t\t\t\t\tbased on - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html#access-control-block-public-access-policy-status\n'

        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 S3Helper.py --profile <aws_profile> --action <The S3 action to execute> --bucketNames <The S3 bucket name>\n'
        '\t\t\t\t --actionParmas <key value dictionary with the action execution params> --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3Helper.py --profile <aws_profile> --action server_logging  --bucketNames <The S3 bucket name>\n'
        '\t\t\t\t --actionParmas {"target_bucket":<the target buckt to contain the logs>} --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3Helper.py --profile <aws_profile> --action encryption  --bucketNames <The S3 bucket name> \n'
        '\t\t\t\t --actionParmas {"kms":<the target buckt to contain the logs>} --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3Helper.py --profile <aws_profile> --action versioning  --bucketNames <The S3 bucket name>\n'
        '\t\t\t\t --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3Helper.py --profile <aws_profile> --action mfa_protection  --bucketNames <The S3 bucket name>\n'
        '\t\t\t\t --actionParmas {"mfa":<The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device>}  --revert <true/false if to revert this action>\n\n'

        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile -  The AWS profile to use to execute this script\n'
        '\t\t\t\t action -   The S3 action to execute - (server_logging, encryption, versioning, mfa_protection)\n'
        '\t\t\t\t\t * for mfa_protection you have to execute the script as the root user of the account according to: \n'
        '\t\t\t\t\t https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html\n'
        '\t\t\t\t bucketNames - List of The bucket names for example b1,b2,b3\n'
        '\t\t\t\t actionParmas  - A key value Dictionary of action params"\n'
        '\t\t\t\t revert  - A true false flag to a sign if this action need to revert"\n'
        '\n\n'

    )
    print(text)


def setup_client(session):
    client = session.client('s3')
    return client


def do_logging(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    '''
    Implement the set/remove loggin operation over a bucket
    :param client: S3 boto3 client
    :param bucket_name: the source bucket name
    :param target_bucket_name: the target bucket name where the logs will be writen to
    :param is_revert: enable or disable logging?
    :return:
    '''
    client = setup_client(session)
    result = list()
    for bucket_name in list_of_buckets:
        results = dict()
        logging.info(f"Going to work on bucket - {bucket_name}")

        if not action_params:
            logging.error(f"Action - server_logging must include action params property")
            return "Action - server_logging must include action params property"
        if "target_bucket" not in action_params:
            logging.error(f"Action - server_logging must include target_bucket param in the action params property")
            return "Action - server_logging must include target_bucket param in the action params property"
        if is_revert:
            logging.info(f"Going to revert server logging for bucket - {bucket_name}")
            req_element = {}
        else:
            logging.info(f"Going to set server logging for bucket - {bucket_name}")
            target_bucket_name = action_params.get("target_bucket", "")
            req_element = {
                'LoggingEnabled': {
                    'TargetBucket': target_bucket_name,
                    'TargetPrefix': f'{bucket_name} - '
                }
            }
            results["bucket_name"] = bucket_name
            results["result"] = "Server Logging for bucket set successfully."

        try:
            response = client.put_bucket_logging(
                Bucket=bucket_name,
                BucketLoggingStatus=req_element
            )
            results["bucket_name"] = bucket_name
            results["result"] = "Server Logging for bucket reverted successfully."
        except Exception as e:
            logging.error(f"enable logging failed for - {bucket_name}")
            results["bucket_name"] = bucket_name
            results["result"] = f"Enable Logging Failed for bucket due to - {str(e)}"
        result.append(results)
    return result


def do_encryption(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    result = list()
    client = setup_client(session)
    for bucket_name in list_of_buckets:
        results = dict()
        logging.info(f"Going to work on bucket - {bucket_name}")

        kms_key_id = None
        if action_params and 'kms' in action_params:
            kms_key_id = action_params['kms']

        if is_revert:
            logging.info(f"Going to remove encryption from bucket - {bucket_name}")
            response = client.delete_bucket_encryption(
                Bucket=bucket_name
            )
            results["bucket_name"] = bucket_name
            results["result"] = "Removed encryption from bucket successfully."
            result.append(results)
            continue

        if kms_key_id:
            logging.info(f"Going to encrypt bucket - {bucket_name} using kms key- {kms_key_id}")
            rule = {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': kms_key_id
                },
                'BucketKeyEnabled': False
            }
            results["bucket_name"] = bucket_name
            results["result"] = f"Encrypted bucket using kms key - {kms_key_id} successfully."
        else:
            logging.info(f"Going to encrypt bucket - {bucket_name} using aws:s3 key")
            rule = {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                },
                'BucketKeyEnabled': True
            }
            results["bucket_name"] = bucket_name
            results["result"] = f"Encrypted bucket using aws:s3 key successfully."
        response = client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [rule]
            }
        )
        result.append(results)
    return result


def do_versioning(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    result = list()
    client = setup_client(session)
    for bucket_name in list_of_buckets:
        results = dict()
        logging.info(f"Going to work on bucket - {bucket_name}")
        if is_revert:
            logging.info(f"Going to remove versioning  from bucket - {bucket_name}")
            response = client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'Status': 'Suspended'
                }
            )
            results["bucket_name"] = bucket_name
            results["result"] = "Removed versioning from bucket successfully."
        else:
            logging.info(f"Going to add versioning to bucket - {bucket_name}")
            response = client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'MFADelete': 'Disabled',
                    'Status': 'Enabled'
                }
            )
            results["bucket_name"] = bucket_name
            results["result"] = "Added versioning to bucket successfully."
        result.append(results)
    return result


def do_mfa_protection(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    # get the bucket versioning status
    result = list()
    client = setup_client(session)
    for bucket_name in list_of_buckets:
        results = dict()
        logging.info(f"Going to work on bucket - {bucket_name}")

        if not action_params:
            logging.error(f"Action - mfa_protection must include action params property")
            return "Action - mfa_protection must include action params property"
        if "mfa" not in action_params:
            logging.error(f"Action - mfa_protection must include mfa param in the action params property")
            return "Action - mfa_protection must include mfa param in the action params property"
        mfa = action_params['mfa']

        response = client.get_bucket_versioning(
            Bucket=bucket_name
        )
        versioning_status = response['Status']

        if is_revert:
            logging.info(f"Going to remove mfa deletion protection from bucket - {bucket_name}")
            response = client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={
                    'MFADelete': 'Disabled',
                    'Status': versioning_status

                }
            )
            results["bucket_name"] = bucket_name
            results["result"] = "Removed mfa deletion protection from bucket successfully."
        else:
            logging.info(f"Going to add mfa deletion protection to bucket - {bucket_name}")
            response = client.put_bucket_versioning(
                Bucket=bucket_name,
                MFA=mfa,
                VersioningConfiguration={
                    'MFADelete': 'Enabled',
                    'Status': versioning_status
                }
            )
            results["bucket_name"] = bucket_name
            results["result"] = "Added mfa deletion protection to bucket successfully."
        result.append(results)
    return result


def do_block_public_access(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    result = list()
    client = setup_client(session)
    for bucket_name in list_of_buckets:
        results = dict()
        logging.info(f"Going to work on bucket - {bucket_name}")

        if not action_params:
            block_public_acl = True
            ignore_public_acl = True
            block_public_policy = True
            restrict_public_bucket = True
        else:
            block_public_acl = action_params["BlockPublicAcls"] if "BlockPublicAcls" in action_params else False
            ignore_public_acl = action_params['IgnorePublicAcls'] if "IgnorePublicAcls" in action_params else False
            block_public_policy = action_params["BlockPublicPolicy"] if "BlockPublicPolicy" in action_params else False
            restrict_public_bucket = action_params[
                "RestrictPublicBuckets"] if "RestrictPublicBuckets" in action_params else False

        logging.info(f"Going to block public access to bucket- {bucket_name}")
        try:
            response = client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': block_public_acl,
                    'IgnorePublicAcls': ignore_public_acl,
                    'BlockPublicPolicy': block_public_policy,
                    'RestrictPublicBuckets': restrict_public_bucket
                }
            )
            results["bucket_name"] = bucket_name
            results["result"] = f"Block Public Access enabled successfully."
        except Exception as ex:
            results["bucket_name"] = bucket_name
            results["result"] = f"Error Occurred: {ex}"
        result.append(results)
    return result


def _check_statment_exist(statement, curr_policy):
    for sts in curr_policy['Statement']:
        if sts['Effect'] == statement['Effect'] and sts['Principal'] == statement['Principal'] and sts['Action'] == \
                statement['Action'] and sts['Condition'] == statement['Condition'] and sorted(
            sts['Resource']) == sorted(statement['Resource']):
            return True
    return False


def do_block_http(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    client = setup_client(session)
    result = list()
    for bucket_name in list_of_buckets:
        results = dict()
        logging.info(f"Going to work on bucket - {bucket_name}")
        logging.info(f"Going to block http access to bucket - {bucket_name}")
        statement = {
            "Sid": "RestrictToTLSRequestsOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }

        policy = {
            "Version": "2012-10-17",
            "Statement": [statement]
        }
        try:
            response = client.get_bucket_policy(Bucket=bucket_name)
            curr_policy = json.loads(response['Policy'])
            if not _check_statment_exist(statement, curr_policy):
                curr_policy['Statement'].append(statement)
                response = client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(curr_policy)
                )
            else:
                logging.info(f"HTTP Deny policy already exist")
                results["bucket_name"] = bucket_name
                results["result"] = "HTTP Deny policy already exist."
                result.append(results)
                continue
        except botocore.exceptions.ClientError as e:
            if 'Error' in e.response and 'Code' in e.response['Error'] and e.response['Error'][
                'Code'] == 'NoSuchBucketPolicy':
                response = client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(policy)
                )
            results["bucket_name"] = bucket_name
            results["result"] = f"Error Occurred: {str(e)}"

        logging.info(f"Bucket policy created/updated with http deny policy")
        results["bucket_name"] = bucket_name
        results["result"] = "Bucket policy created/updated with http deny policy."
        result.append(results)
    return result


def do_check_public_access(
        list_of_buckets,
        session,
        is_revert,
        action,
        action_params,
        caller_identity
):
    client = setup_client(session)
    account_id = caller_identity['Account']
    from .S3BucketsPublicAccess import (
        find_buckets_bpa
    )

    try:
        response = client.list_buckets()
        buckets = list(
            filter(
                lambda bucket: (len(list_of_buckets) == 1 and list_of_buckets[0] == "all") or bucket[
                    "Name"] in list_of_buckets,
                response["Buckets"]
            )
        )
    except botocore.exceptions.ClientError as ce:
        if ce.response["Error"]["Code"] == "AccessDenied":
            logging.exception(f"This account does not have access to list the buckets.", exc_info=True)
        else:
            logging.exception(f"Something went wrong.", exc_info=True)
        return {}
    except Exception as ex:
        logging.exception(f"Something went wrong.", exc_info=True)
        return {}

    region_data = find_buckets_bpa(session, buckets, account_id)
    found_buckets = region_data["Buckets"].keys()
    if len(found_buckets) < len(list_of_buckets):
        if list_of_buckets != ["all"]:
            for bucket_name in list_of_buckets:
                if bucket_name not in found_buckets:
                    region_data["Buckets"][bucket_name] = "bucket not found"
                    logging.exception(f"bucket {bucket_name} not found", exc_info=False)
        else:
            region_data["Buckets"]['all'] = "buckets not found"
            logging.exception(f"There are no buckets", exc_info=False)

    return region_data


def common_args(
        parser,
        args_json_data
):
    """adds common arguments to the parser"""
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
        help=args_json_data.get("awsSessionToken"),
    )
    parser.add_argument(
        "--regions",
        required=False,
        metavar="",
        type=str,
        default="all",
        help=args_json_data.get("regions"),
    )
    parser.add_argument(
        "--bucketNames",
        required=False,
        metavar="",
        type=str,
        default=None,
        help=args_json_data.get("bucketNames"),
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

    parser_usage = common_json_data.get("usage", dict()).get("S3Actions", "")
    usage = parser_usage + " [-h]"
    if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
        utils.print_help_valid_types(
            common_json_data.get("help", dict()).get(
                "S3Actions", dict()), usage
        )
        sys.exit(1)

    # help mapping for S3 Action - Help Content is mapped with associated action of type S3.
    s3_help = {
        'block_http': s3_deny_http_access_readme_data,
        'mfa_protection': s3_enable_mfa_protection_readme_data,
        'check_public_access': s3_check_public_access_readme_data,
        'encryption': s3_enable_encryption_readme_data,
        'server_logging': s3_enable_server_logging_readme_data,
        'versioning': s3_enable_versioning_readme_data,
        'configure_public_access': s3_block_public_access_readme_data
    }
    type_s3_help = {
        str(key): value.get("help", "None") for key, value in s3_help.items()
    }
    parser = ArgumentParser(
        usage=parser_usage,
        conflict_handler="resolve",
    )
    type_subparser = parser.add_subparsers(
        title="type", help="choose s3 automation type", dest="type", metavar=""
    )

    s3_parser = type_subparser.add_parser(
        name="s3",
        formatter_class=argparse.RawTextHelpFormatter
    )
    s3_action_subparser = s3_parser.add_subparsers(
        title="choose s3 action", dest='action', metavar="", description=utils.type_help(
            type_s3_help)
    )
    s3_deny_http_access_parser = s3_action_subparser.add_parser(
        name='block_http', formatter_class=argparse.RawTextHelpFormatter
    )
    s3_enable_mfa_protection_parser = s3_action_subparser.add_parser(
        name='mfa_protection', formatter_class=argparse.RawTextHelpFormatter
    )
    s3_check_public_access_parser = s3_action_subparser.add_parser(
        name='check_public_access', formatter_class=argparse.RawTextHelpFormatter
    )
    s3_enable_encryption_parser = s3_action_subparser.add_parser(
        name='encryption', formatter_class=argparse.RawTextHelpFormatter
    )
    s3_enable_server_logging_parser = s3_action_subparser.add_parser(
        name='server_logging', formatter_class=argparse.RawTextHelpFormatter
    )
    s3_enable_versioning_parser = s3_action_subparser.add_parser(
        name='versioning', formatter_class=argparse.RawTextHelpFormatter
    )
    s3_block_public_access_parser = s3_action_subparser.add_parser(
        name='configure_public_access', formatter_class=argparse.RawTextHelpFormatter
    )

    # Overriding "optional arguments" to "arguments" in help CLI message
    s3_deny_http_access_parser._optionals.title = "block_http"
    s3_enable_mfa_protection_parser._optionals.title = "mfa_protection"
    s3_check_public_access_parser._optionals.title = "check_public_access"
    s3_enable_encryption_parser._optionals.title = "encryption"
    s3_enable_server_logging_parser._optionals.title = "server_logging"
    s3_enable_versioning_parser._optionals.title = "versioning"
    s3_block_public_access_parser._optionals.title = "configure_public_access"

    asset_type = sys.argv[1]
    action = sys.argv[2]

    args_json_data = s3_help.get(action, {}).get("cli_args", {})
    common_args(s3_deny_http_access_parser, args_json_data=args_json_data)
    common_args(s3_enable_mfa_protection_parser, args_json_data=args_json_data)
    common_args(s3_check_public_access_parser, args_json_data=args_json_data)
    common_args(s3_enable_encryption_parser, args_json_data=args_json_data)
    common_args(s3_enable_server_logging_parser, args_json_data=args_json_data)
    common_args(s3_enable_versioning_parser, args_json_data=args_json_data)
    common_args(s3_block_public_access_parser, args_json_data=args_json_data)
    if action == "encryption":
        s3_enable_encryption_parser.add_argument(
            "--revert",
            required=False,
            metavar="",
            type=str,
            default=False,
            help=args_json_data.get("revert"),
        )
        s3_enable_encryption_parser.add_argument(
            "--actionParams",
            required=True,
            default=None,
            metavar="",
            help=args_json_data.get("actionParams"),
        )
    if action == "configure_public_access":
        s3_block_public_access_parser.add_argument(
            "--actionParams",
            required=True,
            default=None,
            metavar="",
            help=args_json_data.get("actionParams"),
        )
    if action == "mfa_protection":
        s3_enable_mfa_protection_parser.add_argument(
            "--revert",
            required=False,
            metavar="",
            type=str,
            default=False,
            help=args_json_data.get("revert"),
        )
        s3_enable_mfa_protection_parser.add_argument(
            "--actionParams",
            required=True,
            default=None,
            metavar="",
            help=args_json_data.get("actionParams"),
        )
    if action == "server_logging":
        s3_enable_server_logging_parser.add_argument(
            "--revert",
            required=False,
            metavar="",
            type=str,
            default=False,
            help=args_json_data.get("revert"),
        )
        s3_enable_server_logging_parser.add_argument(
            "--actionParams",
            required=True,
            default=None,
            metavar="",
            help=args_json_data.get("actionParams"),
        )
    if action == "versioning":
        s3_enable_versioning_parser.add_argument(
            "--revert",
            required=False,
            metavar="",
            type=str,
            default=False,
            help=args_json_data.get("revert"),
        )
    args = parser.parse_args()
    params = utils.build_params(args=args)
    if not params:
        print(sys.exc_info())
        exit(0)

    # Function Mapping - Function is mapped with associated asset_type and action.
    function_mapping = {
        "s3": {
            'block_http': do_block_http,
            'mfa_protection': do_mfa_protection,
            'check_public_access': do_check_public_access,
            'encryption': do_encryption,
            'server_logging': do_logging,
            'versioning': do_versioning,
            'configure_public_access': do_block_public_access
        }
    }

    result = dict()

    profile = params.get(
        "profile") if args.file is not None else params.profile
    aws_access_key = params.get(
        "awsAccessKey") if args.file is not None else params.awsAccessKey
    aws_secret = params.get(
        "awsSecret") if args.file is not None else params.awsSecret
    aws_session_token = params.get(
        "awsSessionToken") if args.file is not None else params.awsSessionToken

    regions = ",".join(
        params.get('regions', ['all'])
    ) if args.file is not None else str(params.regions)

    log_level = params.get(
        "logLevel") if args.file is not None else params.logLevel

    if params.get("bucketNames") is None:
        list_of_buckets = []
    elif args.file is None:
        list_of_buckets = params.bucketNames.split(",")
    else:
        list_of_buckets = params.get('bucketNames', [])

    action_params = params.get(
        'actionParams', None) if args.file is not None else params.actionParams

    action_params = json.loads(action_params) if action_params and not isinstance(
        action_params, dict) else params.get('actionParams', None)

    is_revert = params.get(
        "revert", False) if args.file is not None else params.profile

    output_type = params.get(
        "outputType", "JSON") if args.file is not None else str(params.outputType)

    output_directory = params.get(
        "outDir", "./") if args.file is not None else str(params.outDir)

    test_id = params.get(
        "testId", None) if args.file is not None else str(params.testId)
    if test_id is not None:
        result['testId'] = test_id

    try:
        utils.log_setup(log_level)
        logging.debug("python3 -m Automations.S3Actions %s",
                      " ".join(sys.argv[1:]))
        logging.debug(params)

        if regions:
            session = utils.setup_session(profile=profile, aws_access_key=aws_access_key, aws_secret=aws_secret,
                                          aws_session_token=aws_session_token)
            list_of_regions = utils.get_regions(regions, session)
            if len(list_of_regions) > 0:
                regions = list_of_regions[0]

        session = utils.setup_session(profile=profile, region=regions, aws_access_key=aws_access_key,
                                      aws_secret=aws_secret, aws_session_token=aws_session_token)
        caller_identity = utils.get_caller_identity(session=session)
        result['caller-identity'] = caller_identity

        logging.info(f"Working on Region - {session.region_name}")
        action_result = function_mapping[asset_type][action](
            list_of_buckets,
            session,
            is_revert,
            action,
            action_params,
            caller_identity
        )

        if action_result:
            result[session.region_name] = action_result
        else:
            result[session.region_name] = {}
    except Exception as ex:
        logging.error("Something Went wrong!!", exc_info=log_level == "DEBUG")
        result['status'] = 'Error'
        result['message'] = str(ex)
    filename = os.path.join(
        output_directory,
        f"Tamnoon-S3Helper-{action.replace('_', '-')}-execution-result"
        + "."
        + output_type,
    )
    utils.export_data(filename, result)


if __name__ == "__main__":
    main(sys.argv)
