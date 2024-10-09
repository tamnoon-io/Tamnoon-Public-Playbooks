import argparse
import json
import logging
import re
import sys
import os

from Automations.Utils import utils as utils
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError, BotoCoreError, \
    PartialCredentialsError, ParamValidationError

try:
    from Automations.CloudFormation import help_jsons_data
except ModuleNotFoundError:
    pass

describe_stack_resources_security_groups = (
    help_jsons_data.describe_stack_resources_security_groups
    if hasattr(help_jsons_data, "describe_stack_resources_security_groups")
    else dict()
)
describe_stack_resources_is_created_by_cfn = (
    help_jsons_data.describe_stack_resources_is_created_by_cfn
    if hasattr(help_jsons_data, "describe_stack_resources_is_created_by_cfn")
    else dict()
)
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


def command_description():
    return (
        "\n"
        "\n "
        """

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

        """
    )


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
        "--assetIds",
        required=False,
        metavar="",
        type=str,
        default="all",
        help=args_json_data.get("assetIds")
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


def get_security_group_name(session, security_group_id):
    # Initialize a session using Amazon EC2
    ec2_client = session.client('ec2')

    try:
        # Describe the security group using its ID
        response = ec2_client.describe_security_groups(GroupIds=[security_group_id])

        # Extract the security group name from the response
        security_group_name = response['SecurityGroups'][0]['GroupName']

        return security_group_name

    except NoCredentialsError:
        logging.error("Credentials not available.")
    except ClientError as e:
        logging.error(f"ClientError when describing security-group {security_group_id}: {e}")


def get_cloudformation_stack_arn_from_resource_arn(session, resource_arn):
    result = dict()

    result[resource_arn] = dict()
    resource_name = resource_arn.split(":")[-1]
    if '/' in resource_arn:
        split_rs_arn = resource_arn.split("/")
        resource_tag = "".join(split_rs_arn[0]).split(":")[-1]
        resource_name = split_rs_arn[-1]
        resource_name = get_security_group_name(session,
                                                resource_name) if resource_tag == 'security-group' else resource_name
    try:
        cfn_client = session.client("cloudformation")
        response = cfn_client.describe_stack_resources(
            PhysicalResourceId=resource_name
        )
        if 'StackResources' in response:
            StackId = response['StackResources'][0]['StackId']
            logging.info(f"Resource ARN: {resource_arn} is created by CloudFormation Stack ARN : {StackId}")
            result[resource_arn]["CloudFormationStackARN"] = StackId
            result[resource_arn]["result"] = "This resource is created by CloudFormation Stack."
    except ClientError:
        logging.info(f"{resource_arn}: This resource does not appear to be part of a Cloudformation stack, but you "
                     f"should verify"
                     " manually.")
        result[resource_arn] = "This resource does not appear to be part of a Cloudformation stack, but you " \
                               "should verify manually."
    except ParamValidationError:
        logging.error(f"{resource_arn} : Security Group does not exists in this region.")
        result[resource_arn] = "Security Group does not exists in this region."
    except Exception as ex:
        logging.info(f"Something went wrong. Error: {str(ex)}")
        result[resource_arn] = f"Something went wrong. Error: {str(ex)}"
    return result


def describe_stack_resources_security_groups_action(session,
                                                    asset_ids,
                                                    outputDirectory,
                                                    outputType, action_params=None):
    is_all_assetIds = asset_ids == ['all']
    if is_all_assetIds:
        asset_ids = get_security_group_ids(session)
    ec2_client = session.client('ec2')
    # Describe the security group to get its tags
    result = dict()
    try:
        for security_group_id in asset_ids:
            result[security_group_id] = dict()
            try:
                response = ec2_client.describe_security_groups(GroupIds=[security_group_id])
            except Exception as e:
                logging.info(f"Invalid Security Group ID. Error : {e}")
                result[security_group_id] = f"Invalid Security Group ID or Security Group does not exists in given " \
                                            f"region."
                continue
            if 'SecurityGroups' in response and response['SecurityGroups']:
                security_group = response['SecurityGroups'][0]
                # Get security group tags
                tags = security_group.get('Tags', [])
                stack_id = ''
                stack_name = ''
                if tags:
                    logging.info("Tags for Security Group {}: ".format(security_group_id))
                    for tag in tags:
                        if tag['Key'] == 'aws:cloudformation:stack-id':
                            stack_id = tag['Value']  # CloudFormation stack id
                        if tag['Key'] == 'aws:cloudformation:stack-name':
                            stack_name = tag['Value']  # CloudFormation stack name
                        logging.info("- {}: {}".format(tag['Key'], tag['Value']))
                    result[security_group_id]["Tags"] = tags
                else:
                    result[security_group_id]["Tags"] = "No tags found for Security Group"
                    logging.info("No tags found for Security Group {}.".format(security_group_id))

                # Check if the security group is part of a CloudFormation stack

                if stack_id:
                    logging.info("Deployed by CloudFormation Stack:")
                    logging.info("- Stack Name: {}".format(stack_name))

                    # Describe the stack to get more details
                    cloudformation_client = session.client('cloudformation')
                    try:
                        stack_response = cloudformation_client.describe_stacks(StackName=stack_id)
                    except Exception as ex:
                        logging.info(f"Stack does not exists. Error: {ex}")
                        result[security_group_id]["CloudFormationStackInfo"] = "Stack details not found."
                        continue
                    cloudformation_stack_info = {}
                    if 'Stacks' in stack_response and stack_response['Stacks']:
                        stack_details = stack_response['Stacks'][0]
                        logging.info("- Stack ID: {}".format(stack_details['StackId']))
                        logging.info("- Stack Status: {}".format(stack_details['StackStatus']))
                        logging.info("- Creation Time: {}".format(stack_details['CreationTime']))
                        cloudformation_stack_info["StackID"] = stack_details['StackId']
                        cloudformation_stack_info["StackStatus"] = stack_details['StackStatus']
                        cloudformation_stack_info["CreationTime"] = stack_details['CreationTime']

                        cloudformation_stack_info["Resources"] = list()
                        resource_response = cloudformation_client.describe_stack_resources(
                            StackName=stack_id)
                        logging.info("\nResources Deployed by CloudFormation Template are :- ")
                        for resource in resource_response["StackResources"]:
                            resource_info = dict()
                            resource_info["LogicalResourceId"] = resource["LogicalResourceId"]
                            resource_info["PhysicalResourceId"] = resource["PhysicalResourceId"]
                            resource_info["ResourceType"] = resource["ResourceType"]
                            resource_info["ResourceStatus"] = resource["ResourceStatus"]

                            logging.info("Resource LogicalResourceId: {}".format(resource["LogicalResourceId"]))
                            logging.info("Resource PhysicalResourceId: {}".format(resource["PhysicalResourceId"]))
                            logging.info("Resource ResourceType: {}".format(resource["ResourceType"]))
                            logging.info("Resource ResourceStatus: {}".format(resource["ResourceStatus"]))
                            cloudformation_stack_info["Resources"].append(resource_info)
                        result[security_group_id]["CloudFormationStackInfo"] = cloudformation_stack_info
                    else:
                        result[security_group_id]["CloudFormationStackInfo"] = "Stack details not found."
                        logging.info("Stack details not found.")
                else:
                    result[security_group_id]["CloudFormationStackInfo"] = "Security Group was not deployed by " \
                                                                           "CloudFormation."
                    logging.info("Security Group was not deployed by CloudFormation.")
            else:
                result[security_group_id] = "Security Group not found."
                logging.info("Security Group {} not found.".format(security_group_id))
        filename = os.path.join(
            outputDirectory,
            utils.export_data_filename_with_timestamp(
                f"Tamnoon-CloudFormation-describe-stack-resources-security_groups-{session.region_name}-execution-result",
                outputType,
            ),
        )
        utils.export_data_(filename, result)
        return f"data exported to {filename}"
    except Exception as ex:
        logging.info("Error: {}".format(ex))


def get_security_group_ids(session):
    security_group_ids = []
    ec2_client = session.client('ec2', region_name=session.region_name)
    response = ec2_client.describe_security_groups()
    # Extract security group IDs for the current region
    security_group_ids.extend([sg['GroupId'] for sg in response['SecurityGroups']])
    return security_group_ids


def get_autoscaling_group(session, ec2_instance_id):
    ec2_client = session.client('ec2')
    try:
        response = ec2_client.describe_instances(InstanceIds=[ec2_instance_id])
        reservations = response.get('Reservations', [])
        if not reservations:
            logging.warning(f"No reservations found for instance {ec2_instance_id}")
            return None

        instances = reservations[0].get('Instances', [])
        if not instances:
            logging.warning(f"No instances found in reservations for instance {ec2_instance_id}")
            return None

        for instance in instances:
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'aws:autoscaling:groupName':
                    return tag['Value']

        logging.info(f"No Auto Scaling group found for instance {ec2_instance_id}")
        return None

    except ClientError as e:
        logging.error(f"ClientError when describing instance {ec2_instance_id}: {e}")
        return None
    except NoCredentialsError:
        logging.error("No AWS credentials found.")
        return None
    except EndpointConnectionError as e:
        logging.error(f"Endpoint connection error: {e}")
        return None
    except BotoCoreError as e:
        logging.error(f"BotoCoreError: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred for instance {ec2_instance_id}: {e}")
        return None


def determine_ec2_created_by_asg_by_cloudformation(session, ec2_instance_id_arn):
    result = dict()

    try:
        result[ec2_instance_id_arn] = dict()
        match = re.match(r'arn:aws:ec2:[^:]+:[^:]+:instance/(i-[a-fA-F0-9]+)', ec2_instance_id_arn)
        if not match:
            result[ec2_instance_id_arn] = "Invalid EC2 instance ARN."
            logging.error(f"{ec2_instance_id_arn}: Invalid EC2 instance ARN.")
            return result

        ec2_instance_id = match.group(1)
        autoscaling_group_name = get_autoscaling_group(session, ec2_instance_id)
        if autoscaling_group_name:
            logging.info(f"Instance {ec2_instance_id} is part of Auto Scaling group: {autoscaling_group_name}")
            autoscaling_client = session.client('autoscaling')
            response = autoscaling_client.describe_auto_scaling_groups(
                AutoScalingGroupNames=[autoscaling_group_name]
            )
            result[ec2_instance_id_arn]["AutoScalingGroupName"] = autoscaling_group_name
            if 'AutoScalingGroups' not in response or not response['AutoScalingGroups']:
                logging.warning(f"No Auto Scaling groups found for group name: {autoscaling_group_name}")
                result[ec2_instance_id_arn] = "No Auto Scaling groups found."

            result[ec2_instance_id_arn]["AutoScalingGroupName"] = autoscaling_group_name

            asg = response['AutoScalingGroups'][0]
            tags = asg.get('Tags', [])
            stack_id = None
            for tag in tags:
                if tag['Key'] == 'aws:cloudformation:stack-id':
                    stack_id = tag['Value']
                    break

            if stack_id:
                logging.info(
                    f"Auto Scaling group {autoscaling_group_name} is part of CloudFormation stack: {stack_id}")
                result[ec2_instance_id_arn]["CloudFormationStackARN"] = stack_id
                result[ec2_instance_id_arn]["result"] = "EC2 Instance is created by Auto Scaling group is Part " \
                                                        "of CloudFormation stack."
            else:
                logging.info(f"Auto Scaling group {autoscaling_group_name} is not part of any CloudFormation stack")
                result[ec2_instance_id_arn]["result"] = "EC2 Instance is created by Auto Scaling group but is not " \
                                                        "Part " \
                                                        "of CloudFormation stack."
        else:
            result[ec2_instance_id_arn] = "EC2 Instance is either invalid/does not exists or not part of any Auto " \
                                          "Scaling group"

    except ClientError as e:
        logging.error(f"ClientError when describing Auto Scaling group for instance {ec2_instance_id}: {e}")
        result[ec2_instance_id] = f"ClientError: {e}"
    except NoCredentialsError:
        logging.error("No AWS credentials found.")
        result["Error"] = "No AWS credentials found."
    except EndpointConnectionError as e:
        logging.error(f"Endpoint connection error: {e}")
        result[ec2_instance_id] = f"Endpoint connection error: {e}"
    except BotoCoreError as e:
        logging.error(f"BotoCoreError: {e}")
        result[ec2_instance_id] = f"BotoCoreError: {e}"
    except Exception as e:
        logging.error(f"An unexpected error occurred for instance {ec2_instance_id}: {e}")
        result[ec2_instance_id] = f"Unexpected error: {e}"

    return result


def get_ec2_instance_details(session, instance_id):
    ec2 = session.client('ec2')
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if response['Reservations']:
            return response['Reservations'][0]['Instances'][0]
        return None
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"Credentials error: {e}")
    except ClientError as e:
        logging.error(f"Client error: {e.response['Error']['Message']}")
    except EndpointConnectionError as e:
        logging.error(f"Endpoint connection error: {e}")
    except BotoCoreError as e:
        logging.error(f"BotoCore error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    return None


def get_autoscaling_group_details(session, autoscaling_group_name):
    autoscaling = session.client('autoscaling')
    try:
        response = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[autoscaling_group_name])
        if response['AutoScalingGroups']:
            return response['AutoScalingGroups'][0]
        return None
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"Credentials error: {e}")
    except ClientError as e:
        logging.error(f"Client error: {e.response['Error']['Message']}")
    except EndpointConnectionError as e:
        logging.error(f"Endpoint connection error: {e}")
    except BotoCoreError as e:
        logging.error(f"BotoCore error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    return None


def get_beanstalk_environment_details(session, environment_name):
    beanstalk = session.client('elasticbeanstalk')
    try:
        response = beanstalk.describe_environments(EnvironmentNames=[environment_name])
        if response['Environments']:
            return response['Environments'][0]
        return None
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"Credentials error: {e}")
    except ClientError as e:
        logging.error(f"Client error: {e.response['Error']['Message']}")
    except EndpointConnectionError as e:
        logging.error(f"Endpoint connection error: {e}")
    except BotoCoreError as e:
        logging.error(f"BotoCore error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    return None


def get_cloudformation_stack_details(session, stack_name):
    cloudformation = session.client('cloudformation')
    try:
        response = cloudformation.describe_stacks(StackName=stack_name)
        if response['Stacks']:
            return response['Stacks'][0]
        return None
    except (NoCredentialsError, PartialCredentialsError) as e:
        logging.error(f"Credentials error: {e}")
    except ClientError as e:
        logging.error(f"Client error: {e.response['Error']['Message']}")
    except EndpointConnectionError as e:
        logging.error(f"Endpoint connection error: {e}")
    except BotoCoreError as e:
        logging.error(f"BotoCore error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    return None


def determine_ec2_created_by_asg_created_by_ebs_by_cloudformation(session, ec2_instance_id_arn):
    result = dict()
    result[ec2_instance_id_arn] = dict()

    try:
        # Extract instance ID from ARN
        match = re.match(r'arn:aws:ec2:[^:]+:[^:]+:instance/(i-[a-fA-F0-9]+)', ec2_instance_id_arn)
        if not match:
            result[ec2_instance_id_arn] = "Invalid EC2 instance ARN."
            logging.error(f"{ec2_instance_id_arn}: Invalid EC2 instance ARN.")
            return result

        instance_id = ec2_instance_id_arn.split('/')[-1]

        # Step 1: Get EC2 instance details
        instance_details = get_ec2_instance_details(session, instance_id)
        if not instance_details:
            result[ec2_instance_id_arn] = "EC2 instance does not exists."
            return result

        # Step 2: Check if the instance is part of an Auto Scaling group
        tags = instance_details.get('Tags', [])
        autoscaling_group_name = None
        for tag in tags:
            if tag['Key'] == 'aws:autoscaling:groupName':
                autoscaling_group_name = tag['Value']
                break
        if not autoscaling_group_name:
            logging.info(f"Instance {instance_id} is not part of an Auto Scaling group.")
            result[ec2_instance_id_arn] = "Instance is not part of an Auto Scaling group."
            return result

        # Step 3: Get Auto Scaling group details
        autoscaling_group_details = get_autoscaling_group_details(session, autoscaling_group_name)
        if not autoscaling_group_details:
            logging.error(f"Auto Scaling group {autoscaling_group_name} not found.")
            result[ec2_instance_id_arn] = "Auto Scaling group not found."
            return result

        result[ec2_instance_id_arn]["AutoScalingGroupName"] = autoscaling_group_name

        # Step 4: Check if the Auto Scaling group is associated with an Elastic Beanstalk environment
        beanstalk_environment_name = None
        tags = autoscaling_group_details.get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'elasticbeanstalk:environment-name':
                beanstalk_environment_name = tag['Value']
                break

        if not beanstalk_environment_name:
            logging.info(
                f"EC2 Instance {instance_id} created by Auto Scaling group {autoscaling_group_name} is not associated with an Elastic Beanstalk environment.")
            result[ec2_instance_id_arn][
                "result"] = "EC2 Instance created by Auto Scaling group is not associated with an Elastic Beanstalk environment."
            return result

        # Step 5: Get Elastic Beanstalk environment details
        beanstalk_environment_details = get_beanstalk_environment_details(session, beanstalk_environment_name)
        if not beanstalk_environment_details:
            logging.error(
                f"EC2 Instance {instance_id} created by Auto Scaling group. For Auto Scaling group {autoscaling_group_name} Elastic Beanstalk environment {beanstalk_environment_name} not found.")
            result[ec2_instance_id_arn][
                "result"] = "EC2 Instance created by Auto Scaling group.Auto Scaling group is not associated with an Elastic Beanstalk environment."
            return result

        result[ec2_instance_id_arn]["ElasticBeanstalkEnvName"] = beanstalk_environment_name

        # Step 6: Check if the Elastic Beanstalk environment was created by a CloudFormation stack
        cloudformation_stack_id = None
        tags = beanstalk_environment_details.get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'aws:cloudformation:stack-id':
                cloudformation_stack_id = tag['Value']
                break

        if not cloudformation_stack_id:
            logging.info(
                f"EC2 Instance {instance_id} created by Auto Scaling group {autoscaling_group_name} associated with Elastic Beanstalk environment {beanstalk_environment_name} was not created by a CloudFormation stack.")
            result[ec2_instance_id_arn][
                "result"] = f"EC2 Instance created by Auto Scaling group that was associated with Elastic Beanstalk " \
                            f"environment which in turn was not created by a CloudFormation stack."
            return result

        # Step 7: Get CloudFormation stack details
        cloudformation_stack_details = get_cloudformation_stack_details(session, cloudformation_stack_id)
        if not cloudformation_stack_details:
            logging.error(f"CloudFormation stack {cloudformation_stack_id} not found or error occurred.")
            result[ec2_instance_id_arn]["result"] = "CloudFormation stack not found or error occurred."
            return result

        result[ec2_instance_id_arn]["CloudFormationStackARN"] = cloudformation_stack_id
        logging.info(f"The EC2 instance {instance_id} was created by an Auto Scaling group '{autoscaling_group_name}' "
                     f"that was created by Elastic Beanstalk environment '{beanstalk_environment_name}' "
                     f"which in turn was created by CloudFormation stack '{cloudformation_stack_id}'.")
        result[ec2_instance_id_arn]["result"] = (
            "The EC2 instance was created by an Auto Scaling group "
            "that was created by Elastic Beanstalk environment "
            "which in turn was created by CloudFormation stack."
        )
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        result[ec2_instance_id_arn]["result"] = f"An unexpected error occurred: {e}"
    return result


def is_created_by_cloudformation(session, asset_ids, outputDirectory, outputType, action_params):
    result = dict()
    try:
        if asset_ids == ['all']:
            raise ValueError("Missing AssetId. AssetId Is Mandatory.")
        for resource_arn in asset_ids:
            aws_service = resource_arn.split(":")[2]

            is_include_asg = action_params.get("include-asg")
            is_include_ebs = action_params.get("include-ebs")
            if is_include_ebs and is_include_asg:
                updated_result = determine_ec2_created_by_asg_created_by_ebs_by_cloudformation(session, resource_arn)
                result.update(updated_result)
            elif is_include_asg:
                updated_result = determine_ec2_created_by_asg_by_cloudformation(session, resource_arn)
                result.update(updated_result)
            else:
                if aws_service == 'ecs':
                    split_task_arn = resource_arn.split("/")[:-1]
                    cluster_arn = '/'.join(split_task_arn).replace(":task", ":cluster")

                    updated_result = get_cloudformation_stack_arn_from_resource_arn(session, cluster_arn)
                    result.update({
                        resource_arn: updated_result[cluster_arn]
                    })
                    if isinstance(updated_result.get(cluster_arn), dict):
                        result.update({
                            resource_arn: {
                                "ECSClusterARN": cluster_arn,
                                **updated_result[cluster_arn]
                            }
                        })
                elif aws_service in ['ec2', 'autoscaling', 's3', 'lambda']:
                    updated_result = get_cloudformation_stack_arn_from_resource_arn(session, resource_arn)
                    result.update(updated_result)
                else:
                    logging.info(f"Invalid '{aws_service}' AWS Service. Please Check Resource ARN '{resource_arn}'.")
                    result.update({
                        resource_arn:
                            f"Invalid '{aws_service}' AWS Service. Please Check Resource ARN."
                    })
    except Exception as e:
        error_message = str(e)
        if error_message == 'list index out of range':
            result.update({
                resource_arn:
                    f"Invalid Resource ARN."
            })
            logging.info(f"Invalid '{resource_arn}' ARN")
        else:
            result = f"Something went wrong. Error: {e}"
            logging.info(f"Something went wrong. Error: {e}")

    try:
        filename = os.path.join(
            outputDirectory,
            utils.export_data_filename_with_timestamp(
                f"Tamnoon-CloudFormation-describe-stack-resources-is_created_by_cfn-{session.region_name}-execution-result",
                outputType,
            ),
        )
        utils.export_data_(filename, result)
        return f"data exported to {filename}"
    except Exception as e:
        logging.error(f"Failed to export data: {e}")
        return f"Failed to export data: {e}"


def main(argv):
    parser_usage = common_json_data.get("usage", {}).get("CloudFormation", "python3 -m Automations.CloudFormation")
    usage = parser_usage + " [-h]"

    functions_mapping = {
        "describe-stack-resources": {
            "security_groups": describe_stack_resources_security_groups_action,
            "is_created_by_cfn": is_created_by_cloudformation,
        }
    }

    describe_stack_resources_help = {
        "security_groups": describe_stack_resources_security_groups,
        "is_created_by_cfn": describe_stack_resources_is_created_by_cfn
    }

    if len(sys.argv) == 2 and ("--help" in sys.argv or "-h" in sys.argv):
        utils.print_help_valid_types(common_json_data.get("help", {}).get("CloudFormation"),
                                     usage)
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description=command_description(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=parser_usage
    )
    parser._optionals.title = "arguments"
    # type parsers
    type_subparsers = parser.add_subparsers(
        title="type", dest="type", metavar="", description=""
    )
    describe_stack_resources_parser = type_subparsers.add_parser(
        name="describe-stack-resources", formatter_class=argparse.RawTextHelpFormatter
    )

    # action security groups parser
    describe_stack_resources_actions_help = {
        "security_groups": describe_stack_resources_security_groups.get("help"),
        "is_created_by_cfn": describe_stack_resources_is_created_by_cfn.get("help")
    }
    describe_stack_resources_actions = describe_stack_resources_parser.add_subparsers(metavar="",
                                                                                      dest='action',
                                                                                      description=utils.type_help(
                                                                                          describe_stack_resources_actions_help))
    describe_stack_resources_security_groups_action_parser = describe_stack_resources_actions.add_parser(
        name="security_groups"
    )
    describe_stack_resources_is_created_by_cfn_action_parser = describe_stack_resources_actions.add_parser(
        name="is_created_by_cfn"
    )

    asset_type = sys.argv[1]
    action = sys.argv[2]
    common_args(
        describe_stack_resources_security_groups_action_parser,
        describe_stack_resources_help["security_groups"].get("cli_args", {})
    )
    common_args(
        describe_stack_resources_is_created_by_cfn_action_parser,
        describe_stack_resources_help["is_created_by_cfn"].get("cli_args", {})
    )
    describe_stack_resources_is_created_by_cfn_action_parser.add_argument(
        '--actionParams',
        required=False,
        metavar='',
        type=json.loads,
        default={},
        help=describe_stack_resources_help["is_created_by_cfn"].get("cli_args", {}).get("actionParams")
    )

    if not argv:
        argv = sys.argv
    args = parser.parse_args(argv[1:])
    utils.log_setup(args.logLevel)

    params = utils.build_params(args=args)

    profile = params.get("profile")
    if params.get("assetIds") is None:
        asset_ids = ["all"]
    elif args.file is None:
        asset_ids = params.assetIds.split(",")
    else:
        asset_ids = params.get('assetIds', ["all"])
        if not isinstance(asset_ids, list):
            asset_ids = [asset_ids]

    regions = params.get("regions")
    if args.file is not None:
        regions = params.get("regions")
        if regions:
            if isinstance(regions, list):
                regions = ','.join(regions)
        else:
            regions = 'all'
    aws_access_key = params.get("awsAccessKey")
    aws_secret = params.get("awsSecret")
    aws_session_token = params.get("awsSessionToken")

    action_params = params.actionParams
    action_params = json.loads(action_params) if action_params and type(action_params) != dict else action_params

    outputDirectory = params.get("outDir", "./")
    outputType = params.get("outputType", "json")

    result = dict()
    if params.get("testId") is not None:
        result["testId"] = params.get("testId")

    try:
        session = utils.setup_session(
            profile=profile,
            aws_access_key=aws_access_key,
            aws_secret=aws_secret,
            aws_session_token=aws_session_token,
        )
        result.update({"caller-identity": utils.get_caller_identity(session=session)})

        if regions:
            list_of_regions = utils.get_regions(regions_param=regions, session=session)
        else:
            list_of_regions = [session.region_name]

        arn_regions = set()  # stores unique regions from assetIds
        arn_with_region_assetIds = []  # stores those asset_ids where region is specified region
        arn_with_region_assetIds_ = []  # stores those asset_ids where region is specified and to be used for execution using --regions function call where list_of_regions is used.
        arn_regions_mapping = dict()  # regions to asset_ids mapping
        if action == "is_created_by_cfn":
            all_valid_regions = utils.get_regions(regions_param=["all"], session=session)
            for resource_arn in asset_ids:
                try:
                    resource_region = resource_arn.split(":")[3]
                    if resource_region in all_valid_regions:
                        if regions == "all" or resource_region in list_of_regions:
                            arn_with_region_assetIds_.append(resource_arn)
                        else:
                            arn_regions.add(resource_region)
                            arn_with_region_assetIds.append(resource_arn)
                            if resource_region in arn_regions_mapping:
                                arn_regions_mapping.get(resource_region, []).append(resource_arn)
                            else:
                                arn_regions_mapping[resource_region] = [resource_arn]
                except Exception as e:
                    logging.info(f"For Resource {resource_arn}. Error Occurred: {str(e)}")
        arn_without_region_assetIds = list(
            set(asset_ids) - set(arn_with_region_assetIds) - set(arn_with_region_assetIds_)) # stores asset_ids where region not specified in their arn
        action_result = dict()
        if arn_with_region_assetIds:
            logging.info(f"Going to execute - {action} for asset type - {asset_type}")
            logging.info(f"Going to run over {regions} - region")
            # execution on regions from assetIds means assetIds having region.
            for region in arn_regions:
                logging.info(f"Working on Region - {region}")
                session = utils.setup_session(
                    profile=profile,
                    region=region,
                    aws_access_key=aws_access_key,
                    aws_secret=aws_secret,
                    aws_session_token=aws_session_token,
                )
                action_result.update(
                    {
                        region: functions_mapping[asset_type][action](
                            session=session,
                            asset_ids=arn_regions_mapping[region],
                            outputDirectory=outputDirectory,
                            outputType=outputType,
                            action_params=action_params
                        )
                    }
                )

        # execution on --regions means assetIds which does not have regions.
        for region in list_of_regions:
            logging.info(f"Working on Region - {region}")
            session = utils.setup_session(
                profile=profile,
                region=region,
                aws_access_key=aws_access_key,
                aws_secret=aws_secret,
                aws_session_token=aws_session_token,
            )
            updated_assetIds = list(arn_without_region_assetIds)
            for resource_arn in arn_with_region_assetIds_:
                resource_region = resource_arn.split(":")[3]
                if resource_region == region:
                    updated_assetIds.append(resource_arn)
            action_result.update(
                {
                    region: functions_mapping[asset_type][action](
                        session=session,
                        asset_ids=updated_assetIds,
                        outputDirectory=outputDirectory,
                        outputType=outputType,
                        action_params=action_params
                    )
                }
            )
        result.update(action_result)
    except Exception as e:
        logging.error(f"Something Went wrong!!", exc_info=True)
        result["status"] = "Error"
        result["message"] = str(e)
    filename = os.path.join(
        outputDirectory,
        utils.export_data_filename_with_timestamp(
            f"Tamnoon-CloudFormation-{asset_type}-{action}-execution-result",
            outputType,
        ),
    )
    utils.export_data_(filename, result)


if __name__ == "__main__":
    main(sys.argv)
