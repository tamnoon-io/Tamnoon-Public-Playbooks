
import botocore
import boto3
import logging
import yaml
import time
import os
import json


DEFAULT_REGION = 'us-east-1'


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
    logging.info(f"Get regions")
    if 'all' in regions_param:
        try:
            account_client = session.client('account')
            paginator = account_client.get_paginator('list_regions')
            operation_parameters = {'RegionOptStatusContains': ['ENABLED', 'ENABLED_BY_DEFAULT']}
            regions_list = [y["RegionName"] for x in paginator.paginate(**operation_parameters) for y in x.get('Regions', [])]
            logging.info(f"Got {len(regions_list)} regions")
            return regions_list
            #ec2_client = session.client('ec2')
            #response = ec2_client.describe_regions(AllRegions=True)
            #for region in response['Regions']:
            #    regions_list.append(region['RegionName'])

        except botocore.exceptions.NoRegionError as nr:
            logging.warning(f"falling back to default region - {DEFAULT_REGION}")
            account_client = session.client('account', region_name=DEFAULT_REGION)
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
        session = boto3.Session(profile_name=profile)
        if not session.region_name:
            session = boto3.Session(profile_name=profile, region_name=DEFAULT_REGION)
        return session
    if aws_access_key and aws_secret:
        if region:
            if aws_session_token:
                return boto3.Session(region_name=region, aws_access_key_id=aws_access_key,
                                     aws_secret_access_key=aws_secret, aws_session_token=aws_session_token)
            return boto3.Session(region_name=region, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
        if aws_session_token:
            session = boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret, aws_session_token=aws_session_token)
            if not session.region_name:
                session = boto3.Session(region_name=DEFAULT_REGION, aws_access_key_id=aws_access_key,
                                     aws_secret_access_key=aws_secret, aws_session_token=aws_session_token)
            return session
        session = boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
        if not session.region_name:
            session = boto3.Session(region_name=DEFAULT_REGION, aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret)
        return session
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
    if hasattr(args, "file") and args.file:
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

    strtime=str(time.time())
    if export_format == 'JSON':
        with open(f"{file_name}-{strtime}.json", "w") as f:
            json.dump(output, f, ensure_ascii=False, indent=4)
        logging.info(f"Save execution result to - json to path: {file_name}-{strtime}.json")
    if export_format == "CSV":
        import pandas as pd
        pd.json_normalize(output).to_csv(f"{file_name}-{strtime}.csv")
        logging.info(f"Save execution result to - csv to path: {file_name}-{strtime}.csv")


def log_setup(log_l):
    """This method setup the logging level an params
        logs output path can be controlled by the log stdout cmd param (stdout / file)
    """
    logging.basicConfig(format='[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s')
    log_level = log_l
    logging.getLogger().setLevel(log_level)



def is_parent_directory(directory_path, file_path):
    import os

    if directory_path == file_path:
        return True

    directory_path_match_expr = os.path.abspath(directory_path)
    file_path_match_expr = os.path.abspath(file_path)
    output_str = file_path_match_expr.replace(directory_path_match_expr, "")

    return output_str.count("/") == 1



def export_data_filename_with_timestamp(file_name, export_format):
    return f"{file_name}-{str(time.time())}.{export_format}"


def export_data_(file_name, output, export_format="JSON"):
    """
    This method responsible to export the action execution result

    :param export_format: JSON, CSV
    :param file_path: The path to the result file
    :param output: The text to save
    :return:
    """
    if export_format == "JSON":
        with open(file_name, "w") as f:
            json.dump(output, f, ensure_ascii=False, indent=4)
        logging.info(f"Save execution result to - json to path: {file_name}")
    if export_format == "CSV":
        import pandas as pd

        pd.json_normalize(output).to_csv(file_name)
        logging.info(f"Save execution result to - csv to path: {file_name}")

