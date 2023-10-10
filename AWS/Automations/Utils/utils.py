
import botocore
import boto3
import logging
import yaml
import time
import os
import json





class Params(dict):
    '''
    This class represent the Tamnoon Automation params
    It will be built based on dict object that contain the params key and value
    First class params
        logLevel - The level of the execution logging
        type - The target asset type - ec2/vpc... wil determine the action type
        action - The action
        dryRun - execute in dryrun mode (in case of dryrun no actual execution will happen)
        assetIds - on eor more asset id to execute on

    '''
    def __init__(self, *args, **kwargs):
        super(Params, self).__init__(*args, **kwargs)

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Params, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Params, self).__delitem__(key)
        del self.__dict__[key]

def get_regions(regions_param, session):
    """
    This method extract thje list of regions to run over
    :param regions_param: The input region parameter - could be single region, multi regions (reg1,reg2...) or 'all'
    :param session: boto3 ec2 session
    :return:
    """
    default_region = 'us-east-1'
    logging.info(f"Get regions")
    if 'all' in regions_param:
        try:
            account_client = session.client('account')
            response = account_client.list_regions(RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'])
            regions_list = [x["RegionName"] for x in response["Regions"]]
            logging.info(f"Got {len(regions_list)} regions")
            return regions_list
            #ec2_client = session.client('ec2')
            #response = ec2_client.describe_regions(AllRegions=True)
            #for region in response['Regions']:
            #    regions_list.append(region['RegionName'])

        except botocore.exceptions.NoRegionError as nr:
            logging.warning(f"falling back to default region - {default_region}")
            account_client = session.client('account', region_name=default_region)
            response = account_client.list_regions(RegionOptStatusContains=['ENABLED', 'ENABLED_BY_DEFAULT'])
            regions_list = [x["RegionName"] for x in response["Regions"]]
            return regions_list

    return regions_param.split(",")

def setup_session(profile=None, region=None, aws_access_key=None, aws_secret=None, aws_session_token=None):
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
            if aws_session_token:
                return boto3.Session(region_name=region, aws_access_key_id=aws_access_key,
                                     aws_secret_access_key=aws_secret, aws_session_token=aws_session_token)
            return boto3.Session(region_name=region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
        if aws_session_token:
            return boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret, aws_session_token=aws_session_token)
        return boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
    if region:
        return boto3.Session(region_name=region)
    return boto3.Session()

def get_caller_identity(session):
    sts_client = session.client('sts')
    response = sts_client.get_caller_identity()
    return response

def build_params(args):
    """
    This function will build the params set for specific execution (based on file or cli)
    :param args:
    :return:
    """
    # Get params from file
    if args.file:
        try:
            with open(args.file, "r") as f:
                config = yaml.safe_load(f)
                return Params(config)
        except Exception as e:
            logging.error(f"Something went wrong with file reading - {e}")
    else:
        return Params(args.__dict__)

def export_data(file_name, output, export_format='JSON'):
    """
    This method responsible to export the action execution result

    :param export_format: JSON, CSV
    :param file_path: The path to the result file
    :param output: The text to save
    :return:
    """
    if export_format == 'JSON':
        with open(f"{file_name}-{str(time.time())}.json", "w") as f:
            json.dump(output, f, ensure_ascii=False, indent=4)
        logging.info(f"Save execution result to - json to path: {file_name}-{str(time.time())}.json")
    if export_format == "CSV":
        import pandas as pd
        pd.json_normalize(output).to_csv(f"{file_name}-{str(time.time())}.csv")
        logging.info(f"Save execution result to - csv to path: {file_name}-{str(time.time())}.csv")

def log_setup(log_l):
    """This method setup the logging level an params
        logs output path can be controlled by the log stdout cmd param (stdout / file)
    """
    logging.basicConfig(format='[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s')
    log_level = log_l
    logging.getLogger().setLevel(log_level)
