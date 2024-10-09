import logging
import botocore.exceptions


from Automations.Utils import utils


def get_cloudtrail_bucket_name(session, trail):
    # Create a Boto3 client for CloudTrail
    cloudtrail_client = session.client('cloudtrail')

    try:
        # Retrieve the list of CloudTrail trails
        response = cloudtrail_client.describe_trails(trailNameList=[trail])

        # Iterate over each trail to get the S3 bucket name
        for trail_data in response['trailList']:
            if trail_data['Name'] == trail:
                if 'S3BucketName' in trail_data:
                    bucket_name = ''
                    if 'S3KeyPrefix' in trail_data:
                        bucket_name = trail_data['S3BucketName'] + \
                            '-' + trail_data['S3KeyPrefix']
                    else:
                        bucket_name = trail_data['S3BucketName']
                    return (True, bucket_name)
                else:
                    return (True, None)
    except Exception as e:
        print(f"Error: {e}")
    return (False, None)


def find_region_of_bucket(session, bucket_name):
    # get region of bucket
    s3_client = session.client('s3')
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        return response['LocationConstraint'] if response and 'LocationConstraint' in response and response['LocationConstraint'] else 'us-east-1'
    except botocore.exceptions.ClientError as ce:
        if ce.response["Error"]["Code"] == "InvalidAccessPointAliasError":
            logging.exception(str(ce), exc_info=True)
        else:
            logging.exception(f"Something went wrong.", exc_info=True)
    except Exception as ex:
        logging.exception(f"Something went wrong.", exc_info=True)
    s3_client.close()
    return None
