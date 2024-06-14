import argparse
import json
import logging
import sys
import os

import botocore.exceptions

from ..Utils import utils as utils


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


def do_logging(client, bucket_name, target_bucket_name, is_revert=False):
    '''
    Implement the set/remove loggin operation over a bucket
    :param client: S3 boto3 client
    :param bucket_name: the source bucket name
    :param target_bucket_name: the target bucket name where the logs will be writen to
    :param is_revert: enable or disable logging?
    :return:
    '''
    if is_revert:
        logging.info(f"Going to revert server logging for bucket - {bucket_name}")
        req_element = {}

    else:
        logging.info(f"Going to set server logging for bucket - {bucket_name}")
        req_element = {
            'LoggingEnabled': {
                'TargetBucket': target_bucket_name,
                'TargetPrefix': f'{bucket_name} - '
            }
        }

    try:
        response = client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus=req_element
        )
    except Exception as e:
        logging.error(f"enable logging failed for - {bucket_name}")


def do_encryption(client, bucket_name, kms_key_id, is_revert=False):
    if is_revert:
        logging.info(f"Going to remove encryption from bucket - {bucket_name}")
        response = client.delete_bucket_encryption(
            Bucket=bucket_name
        )
        return True

    if kms_key_id:
        logging.info(f"Going to encrypt bucket - {bucket_name} using kms key- {kms_key_id}")
        rule = {
            'ApplyServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'aws:kms',
                'KMSMasterKeyID': kms_key_id
            },
            'BucketKeyEnabled': False
        }
    else:
        logging.info(f"Going to encrypt bucket - {bucket_name} using aws:s3 key")
        rule = {
            'ApplyServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'AES256'
            },
            'BucketKeyEnabled': True
        }

    response = client.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [rule]
        }
    )


def do_versioning(client, bucket_name, is_revert=False):
    if is_revert:
        logging.info(f"Going to remove versioning  from bucket - {bucket_name}")
        response = client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                'Status': 'Suspended'
            }
        )
    else:
        logging.info(f"Going to add versioning to bucket - {bucket_name}")
        response = client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                'MFADelete': 'Disabled',
                'Status': 'Enabled'
            }
        )


def do_mfa_protection(client, bucket_name, mfa):
    # get the bucket versioning status
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


def do_block_public_access(block_public_acl, ignore_public_acl, block_public_policy, restrict_public_bucket,
                           bucket_name):
    logging.info(f"Going to block public access to bucket- {bucket_name}")
    response = client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': block_public_acl,
            'IgnorePublicAcls': ignore_public_acl,
            'BlockPublicPolicy': block_public_policy,
            'RestrictPublicBuckets': restrict_public_bucket
        }
    )


def do_s3_ls(client, bucket_name):
    pass


def _check_statment_exist(statement, curr_policy):
    for sts in curr_policy['Statement']:
        if sts['Effect'] == statement['Effect'] and sts['Principal'] == statement['Principal'] and sts['Action'] == \
                statement['Action'] and sts['Condition'] == statement['Condition'] and sorted(
            sts['Resource']) == sorted(statement['Resource']):
            return True
    return False


def do_block_http(client, bucket_name):
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
            return
    except botocore.exceptions.ClientError as e:
        if 'Error' in e.response and 'Code' in e.response['Error'] and e.response['Error'][
            'Code'] == 'NoSuchBucketPolicy':
            response = client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy)
            )

    logging.info(f"Bucket policy created/updated with http deny policy")


def do_check_public_access(session, client, list_of_buckets, account_id):
    from .S3BucketsPublicAccess import (
        find_buckets_bpa
    )

    region_data = {}
    buckets = []
    try:
        response = client.list_buckets()
        for bucket in response["Buckets"]:
            bucket_name = bucket["Name"]
        buckets = list(
            filter(
                lambda bucket: (len(list_of_buckets) == 1 and list_of_buckets[0] == "all") or bucket["Name"] in list_of_buckets,
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

    region_data = find_buckets_bpa(session, buckets, caller_identity['Account'])
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


def _do_action(list_of_buckets, session, is_revert, action, params, caller_identity):
    client = setup_client(session)
    for bucket_name in list_of_buckets:
        logging.info(f"Going to work on bucket - {bucket_name}")
        if action == 'server_logging':
            if not params:
                logging.error(f"Action - server_logging must include action params property")
                exit(1)
            if "target_bucket" not in params:
                logging.error(f"Action - server_logging must include target_bucket param in the action params property")
                exit(1)
            do_logging(client=client, bucket_name=bucket_name, target_bucket_name=params['target_bucket'],
                       is_revert=is_revert)

        if action == "encryption":
            kms_key_id = None
            if params and 'kms' in params:
                kms_key_id = params['kms']
            do_encryption(client=client, bucket_name=bucket_name, kms_key_id=kms_key_id, is_revert=is_revert)

        if action == "versioning":
            do_versioning(client=client, bucket_name=bucket_name, is_revert=is_revert)

        if action == "mfa_protection":
            if not params:
                logging.error(f"Action - mfa_protection must include action params property")
                exit(1)
            if "mfa" not in params:
                logging.error(f"Action - mfa_protection must include mfa param in the action params property")
                exit(1)
            mfa = params['mfa']
            do_mfa_protection(client=client, bucket_name=bucket_name, mfa=mfa)

        if action == "configure_public_access":
            if not params:
                block_public_acl = True
                ignore_public_acl = True
                block_public_policy = True
                restrict_public_bucket = True
            else:
                block_public_acl = params["BlockPublicAcls"] if "BlockPublicAcls" in params else False
                ignore_public_acl = params['IgnorePublicAcls'] if "IgnorePublicAcls" in params else False
                block_public_policy = params["BlockPublicPolicy"] if "BlockPublicPolicy" in params else False
                restrict_public_bucket = params["RestrictPublicBuckets"] if "RestrictPublicBuckets" in params else False
            do_block_public_access(block_public_acl=block_public_acl, ignore_public_acl=ignore_public_acl,
                                   block_public_policy=block_public_policy,
                                   restrict_public_bucket=restrict_public_bucket, bucket_name=bucket_name)

        if action == "check_public_access":
            account_id = caller_identity['Account']
            return do_check_public_access(session, client, list_of_buckets, account_id)

        if action == "ls":
            do_s3_ls(client=client, bucket_name=bucket_name)

        if action == "block_http":
            do_block_http(client=client, bucket_name=bucket_name)


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--awsAccessKey', required=False, type=str, default=None)
    parser.add_argument('--awsSecret', required=False, type=str, default=None)
    parser.add_argument('--awsSessionToken', required=False, type=str, default=None)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--bucketNames', required=True, type=str)
    parser.add_argument('--actionParmas', required=False, type=str, default=None)
    parser.add_argument('--revert', required=False, type=bool, default=None)
    parser.add_argument('--regions', required=False, type=str, default=None)
    parser.add_argument(
        "--outputDirectory", required=False, type=str, default=os.getcwd()
    )
    parser.add_argument("--outputType", required=False, type=str, default="JSON")


    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = dict()
    profile = args.profile
    aws_access_key = args.awsAccessKey
    aws_secret = args.awsSecret
    aws_session_token = args.awsSessionToken
    action = args.action
    regions = args.regions
    bucket_names = args.bucketNames
    list_of_buckets = bucket_names.split(',')
    params = json.loads(args.actionParmas) if args.actionParmas else None
    is_revert = args.revert if args.revert else False

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
    action_result = _do_action(list_of_buckets=list_of_buckets, session=session, is_revert=is_revert,
                            action=action, params=params, caller_identity=caller_identity)
    if action_result:
        result[session.region_name] = action_result
    else:
        result[session.region_name] = {}

    filename = os.path.join(
        args.outputDirectory,
        f"Tamnoon-S3Helper-{action.replace('_', '-')}-execution-result"
        + "."
        + args.outputType,
    )
    utils.export_data(filename, result)
