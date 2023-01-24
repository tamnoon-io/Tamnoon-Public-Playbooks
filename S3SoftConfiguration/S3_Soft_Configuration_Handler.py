import argparse
import json
import requests
import logging
import sys
import boto3




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
        '\t\t\t\t 2. Bucket Server side encryption\n'
        '\t\t\t\t 3. Bucket Versioning\n'
        '\t\t\t\t 4. Bucket MFA deletion protection\n'
        
        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action <The S3 action to execute> --bucketName <The S3 bucket name>\n'
        '\t\t\t\t --actionParmas <key value dictionary with the action execution params> --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action server_logging  --bucketName <The S3 bucket name>\n'
        '\t\t\t\t --actionParmas {"target_bucket":<the target buckt to contain the logs>} --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action encryption  --bucketName <The S3 bucket name> \n'
        '\t\t\t\t --actionParmas {"kms":<the target buckt to contain the logs>} --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action versioning  --bucketName <The S3 bucket name>\n'
        '\t\t\t\t --revert <true/false if to revert this action>\n\n'
        '\t\t\t\t python3 S3_Soft_Configuration_Handler.py --profile <aws_profile> --action mfa_protection  --bucketName <The S3 bucket name>\n'
        '\t\t\t\t --actionParmas {"mfa":<The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device>}  --revert <true/false if to revert this action>\n\n'
        
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile -  The AWS profile to use to execute this script\n'
        '\t\t\t\t action -   The S3 action to execute - (server_logging, encryption, versioning, mfa_protection)\n'
        '\t\t\t\t\t * for mfa_protection you have to execute the script as the root user of the account according to: \n'
        '\t\t\t\t\t https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html\n'
        '\t\t\t\t bucketName - The bucket name\n'
        '\t\t\t\t actionParmas  - A key value Dictionary of action params:"\n'
        '\t\t\t\t\t 1. for action - server_logging:"\n'
        '\t\t\t\t\t\t "{\"target_bucket\":<The name of the s3 bucket that will contain the logs>}"\n'
        '\t\t\t\t\t 2. for action - encryption:"\n'
        '\t\t\t\t\t\t "{\"kms\":<The arn of the kms managed key to use>}\n'
        '\t\t\t\t\t 3. for action - mfa_protection:"\n'
        '\t\t\t\t\t\t "{\"mfa\":<The concatenation of the authentication devices serial number, a space, and the value that is displayed on your authentication device>}\n'
        '\t\t\t\t\t\t "for example - "{\"mfa\":\"arn:aws:iam::123456789:mfa/bob 572055\"}" where 572055 is the serial from that mfa on execution time\n'
        '\t\t\t\t revert  - A true false flag to a sign if this action need to revert"\n'
        '\n\n'

    )
    print(text)




def setup_client(profile):
    if profile:
        session = boto3.Session(profile_name=profile)
        client = session.client('s3')
        return client

    client = boto3.client('s3')
    return client


def do_logging(client, bucket_name, target_bucket_name, is_revert = False):
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


def do_encryption(client, bucket_name, kms_key_id, is_revert = False):

    if is_revert:
        logging.info(f"Going to remove encryption from bucket - {bucket_name}")
        response = client.delete_bucket_encryption(
            Bucket=bucket_name
        )
        return True

    if kms_key_id:
        logging.info(f"Going to encrypt bucket - {bucket_name} using kms key- {kms_key_id}")
        rule =  {
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
                'Status':  'Suspended'
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

    #get the bucket versioning status
    response = client.get_bucket_versioning(
        Bucket=bucket_name
    )
    versioning_status = response['Status']


    if is_revert:
        logging.info(f"Going to remove mfa deletion protection from bucket - {bucket_name}")
        response = client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={
                'MFADelete':  'Disabled',
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


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--bucketName', required=True, type=str)
    parser.add_argument('--actionParmas', required=False, type=str, default=None)
    parser.add_argument('--revert', required=False, type=bool,  default=None)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = None
    profile= args.profile
    action = args.action
    bucket_name = args.bucketName
    params = json.loads(args.actionParmas) if args.actionParmas else None
    is_revert = args.revert if args.revert else False

    logging.info("Going to setup client")
    client = setup_client(profile)

    if action == 'server_logging':
        if not params:
            logging.error(f"Action - server_logging must include action params property")
            exit (1)
        if "target_bucket" not in params:
            logging.error(f"Action - server_logging must include target_bucket param in the action params property")
            exit(1)
        do_logging(client=client, bucket_name=bucket_name, target_bucket_name=params['target_bucket'], is_revert=is_revert)

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
            exit (1)
        if "mfa" not in params:
            logging.error(f"Action - mfa_protection must include mfa param in the action params property")
            exit(1)
        mfa = params['mfa']
        do_mfa_protection(client=client, bucket_name=bucket_name, mfa=mfa)

        
        








