import argparse
import json
import requests
import logging
import sys
import boto3
import re

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
        '\t\t Welcome To AWS resource tagging helper \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t AWS CLI\n'
        '\t\t\t\t Python v3.8 and up\n'
        '\t\t\t\t Boto3 pacakge 1.26 and above\n'
        '\n'
        '\t\t\t This script will help you to bulk tag assets in your AWS environment\n '
        '\t\t\t The script provides the ability to tag dynamic value to each asset (for example, its asset id or arn\n '
        '\n'
        '\t\t\t This script is based on AWS API and rely on the fallback mechanism of AWS Authentication and Authorization\n'
        '\t\t\t (Profile, creds file, os environment)\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 resourceTagging.py --profile <aws_profile> --action ls  \n'
        '\t\t\t\t python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey testtag --tagValue {{id}}\n'
        '\t\t\t\t python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey testtag --tagValue someTagValue\n'
        '\t\t\t\t python3 resourceTagging.py --profile <aws_profile> --action tag --service ec2:snapshot  --tagKey testtag --revert true\n'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t profile  - The AWS profile to use to execute this script\n'
        '\t\t\t\t action   - Which action to execute:\n'
        '\t\t\t\t\t 1.listOfSupportedResources - print out the supported service and resources that the script can tag\n'
        '\t\t\t\t\t 2.tag - tag the given assets or the entire assets related to the service with the given tag value\n'
        '\t\t\t\t service - The service which all resources from will be tagged:\n'
        '\t\t\t\t\t It could be high level, for example, ec2 - in that case, all resources under ec2 will tag (instances, snapshots, volumes...)\n'
        '\t\t\t\t\t Or it could be as the output of the  listOfSupportedResources execution - for example, ec2:snapshot will tag only snapshots\n'
        '\t\t\t\t tagKey  - The name of the tag (the key part of the tag)"\n'
        '\t\t\t\t tagValue  - The value of the tag, two options are supported:"\n'
        '\t\t\t\t\t 1. Dynamic value - property have to be surrounded by {{}}, for example, {{id}} - the id of the resource"\n'
        '\t\t\t\t\t 2. Static value - string value to bulk all over the resources"\n'
        '\t\t\t\t revert  - A true false flag to a sign if this action need to revert"\n'
        '\n\n'

    )
    print(text)

def setup_botot_session(profile):
    if profile:
        session = boto3.Session(profile_name=profile)
    else:
        session = boto3.Session()

    # Test for valid credentials
    sts_client = session.client("sts")
    try:
        sts_response = sts_client.get_caller_identity()
        return session
    except:
        print("No or invalid AWS credentials configured")
        sys.exit(1)


def do_get_list_of_resources(session):
    '''
    This function execute the api call for getting the supported resources that can be tagged
    :param sesion: boto3 seesion instance
    :return:
    '''
    client = session.client('resource-explorer-2')
    response = client.list_supported_resource_types()
    full_response = response['ResourceTypes']

    while 'NextToken' in response:
        response = client.list_supported_resource_types(NextToken=response['NextToken'])
        full_response = full_response + response['ResourceTypes']
    return full_response


def do_check_params_for_tag():
    if not is_revert and not tag_value:
        logging.error(f" --tagValue parameter must be part of the execution of tag action")
        return False
    if not service and not assets_list:
        logging.error(f" --service or --assets must be part of the execution of tag action")
        return False
    return True


def do_get_resources_list(session, service):
    client = session.client('resource-explorer-2')
    response = client.search(QueryString=f"resourcetype:{service}")

    full_response = response['Resources']

    while 'NextToken' in response:
        response = client.search(QueryString=f"resourcetype:{service}", NextToken=response['NextToken'])
        full_response = full_response + response['Resources']
    return full_response


def do_tagging(session, resources,tag_key, tag_value):
    print(tag_value)
    logging.warning("Currently supporting dynamic tagging is arn,id")
    client = session.client('resourcegroupstaggingapi')
    matches = re.findall(r'{{([a-zA-Z]+)}}', tag_value)
    # dynamic tagging
    if matches and len(matches)>0:
        # input should support only one dynamic value from the form {{$some_val}}
        dynamic_val = matches[0]
        logging.info(f"Dynamic tagging for key - {tag_key} value - {dynamic_val}")
        for resource in resources:
            arn = resource['Arn']
            actual_tag_val = resource[dynamic_val]
            resp = client.tag_resources(ResourceARNList=[arn],Tags={tag_key: actual_tag_val})
    else:
        logging.info(f"Not a dynamic tag value - {tag_value}")
        # static bulk tagging
        list_of_arn = list()

        for resource in resources:
            list_of_arn.append(resource['Arn'])
        resp = client.tag_resources(ResourceARNList=list_of_arn, Tags={tag_key: tag_value})


def do_untag(session, resources, tag_key):

    client = session.client('resourcegroupstaggingapi')
    arns = [resource['Arn'] for resource in resources]
    resp = client.untag_resources(ResourceARNList=arns, TagKeys=[tag_key])


if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--profile', required=False, default=None)
    parser.add_argument('--service', required=False, type=str, default=None)
    parser.add_argument('--assets', required=False, type=str, default=None)
    parser.add_argument('--action', required=True, type=str)
    parser.add_argument('--tagValue', required=False, type=str, default=None)
    parser.add_argument('--revert', required=False, type=bool, default=None)
    parser.add_argument('--tagKey', required=False, type=str, default=None)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()

    log_setup(args.logLevel)

    result = None
    profile = args.profile
    action = args.action
    service = args.service
    tag_value = args.tagValue
    tag_key = args.tagKey
    is_revert = args.revert
    assets_list = args.assets




    logging.info("Going to setup client")
    session = setup_botot_session(profile)

    if action == "ls":
        supported_resource_list = do_get_list_of_resources(session=session)
        print(f"You can tag all the assets from specific supported resource type by  using the Service value from that list as --service param")
        print(json.dumps(supported_resource_list, indent=1))
        #logging.info(supported_resource_list)



    if action == "tag":
        if do_check_params_for_tag():
            if service:
                resources = do_get_resources_list(session=session, service=service)
                # extract asset id from the arn
                for resource in resources:
                    asset_id = None
                    match = re.match(r'^arn:aws:([a-zA-Z0-9-]+):([a-zA-Z0-9-]+):([0-9]+):([a-zA-Z0-9-]+)/([a-zA-Z0-9-]+)$|^arn:aws:([a-zA-Z0-9-]+):([a-zA-Z0-9-]+):([0-9]+):([a-zA-Z0-9-]+)$|^arn:aws:([a-zA-Z0-9-]+):([a-zA-Z0-9-]+):([0-9]+):([a-zA-Z0-9-]+):([a-zA-Z0-9-]+)$', resource['Arn'])
                    if match:
                        # asset id will be the last entry at the arn
                        asset_id = match.group(match.lastindex)
                        resource['id'] = asset_id
                if is_revert:
                    logging.info(f"Going to remove tag - {tag_key} from all resources of type - {service}")
                    do_untag(session=session, resources=resources, tag_key=tag_key)
                else:
                    logging.info(f"Going to tag all resource from type - {service} - with tag  {tag_key}:"+tag_value)
                    do_tagging(session=session, resources=resources, tag_key=tag_key, tag_value=tag_value)
            else:
                if is_revert:
                    logging.info(f"Going to remove tag - {tag_key} from all given resources")
                    do_untag(session=session, resources=assets_list, tag_key=tag_key)
                else:
                    logging.info(f"Going to tag all given resource with tag  {tag_key}:{tag_value} ")
                    do_tagging(session=session, resources=assets_list, tag_key=tag_key, tag_value=tag_value)

                







