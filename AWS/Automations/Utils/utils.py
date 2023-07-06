
import botocore
import boto3
import logging

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