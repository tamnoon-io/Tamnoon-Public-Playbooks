import argparse
import json
import logging
import sys
import boto3


BASE_POLICY_PATH = "BasicIamUserPolicy.json"

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
        '\t\t Welcome To Tamnoon AWS MFA enforcement script \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t Description:\n'
        '\t\t\t\t This script is part of the MFA enforcement playbook\n'
        '\t\t\t\t The assumption is that Tamnoon SCP policy is already setup on the organization level\n'
        '\t\t\t\t This script will help to:\n'
        '\t\t\t\t\t 1. Create basicIamPolicyForUsers policy - this policy allow the identity to manage their own IAM configuration\n'
        '\t\t\t\t\t 2. Inject policy fom step 1 to all users without MFA in the account.\n'

        '\n'
        '\t\t\t\t The script is based on AWS API and documentation \n'
        '\t\t\t\t https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 RemediateMFA.py --profile <aws_profile> --action <The action to execute> --params <the params for the action>\n'
        '\t\t\t\t python3 RemediateMFA.py --profile <aws_profile> --action create_policy \n'
        '\t\t\t\t python3 RemediateMFA.py --profile <aws_profile> --action remediate_user --names "user1,user2" \n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile -  The AWS profile to use to execute this script\n'
        '\t\t\t\t action -   The  action to execute - (create_policy, remediate_user)\n'
        '\t\t\t\t names  - List of user names to inject the policy to, no value means all users\n'
        '\n\n'

    )
    print(text)


def setup_session(profile):
    if profile:
        session = boto3.Session(profile_name=profile)
        return session

    return boto3.Session()


def _check_policy_not_exist(iam_client):
    policies = _get_policies(iam_client)

    for policy in policies:
        if policy['PolicyName'] == 'BasicIamUserPolicy':
            return False
    return True


def _get_policies(iam_client):
    response = iam_client.list_policies(
        Scope='All'
    )
    policies = response['Policies']
    # Pagination
    if 'IsTruncated' in response and response['IsTruncated']:
        response = iam_client.list_policies(
            Scope='All',
            Marker=response['Marker']
        )
        policies = policies + response['Policies']
    return policies


def do_careate_policy(session):
    iam_client = session.client('iam')
    if _check_policy_not_exist(iam_client=iam_client):

        policy_doc = json.load(open(BASE_POLICY_PATH,"r"))
        response = iam_client.create_policy(
            PolicyName='BasicIamUserPolicy',
            PolicyDocument=json.dumps(policy_doc),
            Description='Base policy for IAMUser to manage his own AWS creds such as MFA,Console Passwords, SSH keys etc',
            Tags=[
                {
                    'Key': 'Owner',
                    'Value': 'Tamnoon.io'
                },
            ]
        )
    else:
        logging.info(f"The policy BasicIamUserPolicy already exist")


def execute_inject_policy(session, name):
    iam = session.resource('iam')
    iam_client = session.client('iam')
    user = iam.User(name)
    polices = _get_policies(iam_client)
    policy_arn = None
    for policy in polices:
        if policy['PolicyName'] == 'BasicIamUserPolicy':
            policy_arn = policy['Arn']
            break

    if not policy_arn:
        logging.error(f"The policy BasicIamUserPolicy is not exist , please create the policy using create_policy action and re run this script again")
        raise Exception("policy BasicIamUserPolicy is not exist")

    response = user.attach_policy(
        PolicyArn=policy_arn
    )



def _get_users(iam_client):
    response = iam_client.list_users()
    users = response['Users']

    if 'IsTruncated' in response and response['IsTruncated']:
        response = iam_client.list_users(Marker=response['Marker'])
        users = users + response['Users']

    user_without_mfa = list()
    for user in users:
        response = iam_client.list_mfa_devices(UserName=user['UserName'])
        if len(response['MFADevices']) == 0:
            user_without_mfa.append(user)

    return user_without_mfa


def do_user_mfa_remediation(session, names):
    iam_client = session.client('iam')
    if names:
        for name in names:
            execute_inject_policy(session=session, name=name)
    else:
        users = _get_users(iam_client=iam_client)
        for user in users:
            execute_inject_policy(session=session, name=user['UserName'])



if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--names', required=False, type=str, default=None)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = None
    profile = args.profile
    action = args.action
    names = args.names
    if names:
        names = names.split(',')
    

    logging.info("Going to setup resource")
    session = setup_session(profile)
    if action == 'create_policy':
        do_careate_policy(session=session)
    if action == 'remediate_user':
        do_user_mfa_remediation(session=session, names=names)
