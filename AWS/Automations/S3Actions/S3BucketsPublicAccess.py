import json
import logging
import boto3
import requests
import textwrap
from xml.etree import ElementTree
from botocore.exceptions import ClientError
from ..Utils.utils import DEFAULT_REGION


def is_account_level_bpa_configured(config):
    """
    if config is dict, then Account level BPA is configured
    if config is string, then it is because we assigned some string
    indicating corresponding reason/error that indicates it is
    not configured

    :param config: dict or str

    :return bool:
    """

    return isinstance(config, dict)


def is_account_level_bpa_error(config):
    """
    if config is is_account_level_bpa_configured(config) is True, then Account level BPA has no error
    if config is string and value equals "NotConfigured", then there is no error and Account level BPA is not configured
    if config is string and value does not equal "NotConfigured", then config value represents reason/error

    :param config: dict or str

    :return bool:
    """
    return not is_account_level_bpa_configured(config) and config != "NotConfigured"


def get_account_level_bpa(session, account_id):
    """
    :param session: boto3 session
    :param account_id: account ID

    :return dict or str:
    """

    try:
        # find account level bpa and put into output["AccountLevelBPA"]
        # output["AccountLevelBPA"] is global for all buckets in
        # given region and for given account_id
        response = session.client(
            "s3control", region_name=DEFAULT_REGION
        ).get_public_access_block(AccountId=account_id)
        return response["PublicAccessBlockConfiguration"]
        # value of output["AccountLevelBPA"] will help us identify if we can
        # if it is string, and equals to "NotConfigured", we can ignore this
        # for finding if bucket is publically accessible or not
        # but it output["AccountLevelBPA"] is string that is anything other than "NotConfigured",
        # we cannot say for certain.
    except ClientError as ce:
        if ce.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            # error in finding account level bpa because it is not configured
            return "NotConfigured"
        elif ce.response["Error"]["Code"] == "AccessDenied":
            # error in finding account level bpa because access denied
            return "AccessDenied"
        else:
            # other errors
            return str(ce)
            logging.exception(
                f"Failed to fetch account level BPA of {account_id}.", exc_info=True
            )
    except Exception as ex:
        # unknown error
        logging.exception(
            f"Failed to fetch account level BPA of {account_id}.", exc_info=True
        )
        return str(ex)


def is_bucket_level_bpa_configured(config):
    """
    if config is dict, then Bucket level BPA is configured
    if config is string, then it is because we assigned some string
    indicating corresponding reason/error that indicates it is
    not configured

    :param config: dict or str

    :return bool:
    """

    return isinstance(config, dict)


def is_bucket_level_bpa_error(config):
    """
    if config is is_bucket_level_bpa_configured(config) is True, then Bucket level BPA has no error
    if config is string and value equals "NotConfigured", then there is no error and Bucket level BPA is not configured
    if config is string and value does not equal "NotConfigured", then config value represents reason/error

    :param config: dict or str

    :return bool:
    """
    return not is_bucket_level_bpa_configured(config) and config != "NotConfigured"


def get_bucket_level_bpa(session, bucket_name):
    """
    :param session: boto3 session
    :param bucket_name: bucket name

    :return dict or str:
    """
    try:
        response = session.client(
            "s3", region_name=DEFAULT_REGION
        ).get_public_access_block(Bucket=bucket_name)
        return response["PublicAccessBlockConfiguration"]
    except ClientError as ce:
        if ce.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            # error in finding bucket level bpa because it is not configured
            return "NotConfigured"
        elif ce.response["Error"]["Code"] == "AccessDenied":
            # error in finding bucket level bpa because access denied
            return "AccessDenied"
        else:
            # other errors
            return str(ce)
            logging.exception(
                f"Failed to fetch bucket level BPA of {bucket_name}.", exc_info=True
            )
    except Exception as ex:
        # unknown error
        logging.exception(
            f"Failed to fetch bucket level BPA of {bucket_name}.", exc_info=True
        )
        return str(ex)


def is_acl_configured(config):
    """
    if config is list, then ACL is configured
    if config is string, then it is because we assigned some string
    indicating corresponding reason/error that indicates it is
    not configured

    :param config: list or str

    :return bool:
    """

    return isinstance(config, list)


def is_acl_error(config):
    """
    if is_acl_configured(config) is True, then ACL is configured
    if config is string and its value is NoSuchBucketPolicy, then there is no error but ACL is not configured
    if config is string and its value is not NoSuchBucketPolicy, then there is error
    indicating corresponding reason/error that indicates it is
    not configured

    :param config: list or str

    :return bool:
    """
    return not is_policy_configured(config) and config != "NoSuchBucketPolicy"


def get_bucket_acl(session, bucket_name):
    """
    :param session: boto3 session
    :param bucket_name: bucket name

    :return list or str:
    """
    try:
        response = session.client("s3", region_name=DEFAULT_REGION).get_bucket_acl(
            Bucket=bucket_name
        )
        if len(response["Grants"]) > 0:
            # return ACL list
            return response["Grants"]
        else:
            return "NoACL"
    except ClientError as ce:
        if ce.response["Error"]["Code"] == "AccessDenied":
            # error in finding acl because access denied
            return "AccessDenied"
        else:
            # other errors
            logging.exception(
                f"Failed to fetch{bucket_name} bucket ACL.", exc_info=True
            )
            return str(ce)

    except Exception as ex:
        # unknown error
        logging.exception(f"Failed to fetch {bucket_name} bucket ACL.", exc_info=True)
        return str(ex)


def is_policy_configured(config):
    """
    if config is list, then Policy is configured
    if config is string, then it is because we assigned some string
    indicating corresponding reason/error that indicates it is
    not configured

    :param config: list or str

    :return bool:
    """

    return isinstance(config, list)


def is_policy_error(config):
    """
    if is_policy_configured(config) is True, then Policy is configured
    if config is string and its value is NoSuchBucketPolicy, then there is no error but policy is not configured
    if config is string and its value is not NoSuchBucketPolicy, then there is error
    indicating corresponding reason/error that indicates it is
    not configured

    :param config: list or str

    :return bool:
    """
    return not is_policy_configured(config) and config != "NoSuchBucketPolicy"


def get_bucket_policy(session, bucket_name):
    """
    :param session: boto3 session
    :param bucket_name: bucket name

    :return list or str:
    """
    try:
        policy = session.client("s3", region_name=DEFAULT_REGION).get_bucket_policy(
            Bucket=bucket_name
        )
        policy_obj = json.loads(policy["Policy"])
        if len(policy_obj["Statement"]) > 0:
            # return policies list
            return policy_obj["Statement"]
        else:
            return "NoPolicy"
    except ClientError as ce:
        if ce.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return "NoPolicy"
        if ce.response["Error"]["Code"] == "AccessDenied":
            # error in finding account_level_bpa because access denied
            return "AccessDenied"
        else:
            # other errors
            logging.exception(
                f"Failed to fetch {bucket_name} bucket policy.", exc_info=True
            )
            return str(ce)
    except Exception as ex:
        # unknown errors
        logging.exception(f"Could not get {bucket_name} bucket Policy.", exc_info=True)
        return str(ex)


def print_output_message(bucket_name, bucket_data, account_level_bpa):
    """
    :param bucket_data: dict containing bucket's output data
    :param account_level_bpa: dict containing account level bpa

    :return None:
    """
    if "PublicAccessToBucketObjects" in bucket_data and (
        bucket_data["PublicAccessToBucketObjects"] == "Prevented"
        or bucket_data["PublicAccessToBucketObjects"] == None
    ):
        if "PublicAccessAllowedBy" in bucket_data and (
            bucket_data["PublicAccessAllowedBy"] == "NotAllowed"
            or bucket_data["PublicAccessAllowedBy"] == None
        ):
            if is_account_level_bpa_configured(account_level_bpa):
                if len(list(filter(lambda item: item, account_level_bpa.values()))) > 0:
                    logging.info(
                        f"Public access to {bucket_name} bucket is prevented by Account Level BPA. "
                    )
                    logging.info(
                        f"error in Account Level BPA of {bucket_name}: {json.dumps(account_level_bpa, indent=2)}"
                    )
                    return
            elif is_account_level_bpa_error(account_level_bpa):
                logging.info(
                    f"error in Account Level BPA of {bucket_name}: {account_level_bpa}"
                )
                return
            if is_bucket_level_bpa_configured(bucket_data["BlockPublicAccess"]):
                if (
                    len(
                        list(
                            filter(
                                lambda item: item,
                                bucket_data["BlockPublicAccess"].values(),
                            )
                        )
                    )
                    > 0
                ):
                    logging.info(
                        f"Public access to {bucket_name} bucket is prevented by Bucket Level BPA. "
                    )
                    logging.info(
                        f"Bucket Level BPA of {bucket_name}: {json.dumps(bucket_data['BlockPublicAccess'], indent=2)}"
                    )
                    return
            elif is_bucket_level_bpa_error(bucket_data["BlockPublicAccess"]):
                logging.info(
                    f"error in Bucket Level BPA of {bucket_name}: {bucket_data['BlockPublicAccess']}"
                )
                return

            if is_policy_error(bucket_data["Policy"]):
                logging.info(
                    f"error in Policy of {bucket_name}: {bucket_data['Policy']}"
                )
                return
            if is_acl_error(bucket_data["ACL"]):
                logging.info(f"error in ACL of {bucket_name}: {bucket_data['ACL']}")
                return
            logging.info(
                f"Public access to {bucket_name} bucket is prevented by {bucket_data['PublicAccessAllowedBy'] if 'PublicAccessAllowedBy' in bucket_data else ''}."
            )
    else:
        logging.info(
            f"Public access to {bucket_name} bucket is allowed{' by ' + bucket_data['PublicAccessAllowedBy'] if 'PublicAccessAllowedBy' in bucket_data and bucket_data['PublicAccessAllowedBy'] != 'NotAllowed' else ''}."
        )


def find_acl_allows_public_access(account_level_bpa, bucket_level_bpa, acl):
    """
    :param account_level_bpa: dict containing account level bpa
    :param bucket_level_bpa: dict containing bucket level bpa
    :param acl: list containing acl

    :return bool:
    """

    # check for account level bpa blocks public access via acl
    if not is_account_level_bpa_configured or (
        "IgnorePublicAcls" in account_level_bpa
        and not account_level_bpa["IgnorePublicAcls"]
    ):
        # check for bucket level bpa blocks public access via acl
        if not is_bucket_level_bpa_configured(bucket_level_bpa) or (
            "IgnorePublicAcls" in bucket_level_bpa
            and not bucket_level_bpa["IgnorePublicAcls"]
        ):
            # check acl is configured
            if is_acl_configured(acl):
                # check for acl that allows public access
                for grant in acl:
                    if (
                        "Grantee" in grant.keys()
                        and "URI" in grant["Grantee"].keys()
                        and (
                            grant["Grantee"]["URI"]
                            in [
                                "http://acs.amazonaws.com/groups/global/AllUsers",
                                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                            ]
                        )
                    ):
                        return True
    return False


def find_policy_allows_public_access(
    bucket_name, account_level_bpa, bucket_level_bpa, policy_statements
):
    """
    :param bucket_data: dict containing bucket's output data
    :param account_level_bpa: dict containing account level bpa

    :return bool:
    """
    allowed = False

    # check for account level bpa blocks public access via policy
    if not is_account_level_bpa_configured or (
        "IgnorePublicAcls" in account_level_bpa
        and not account_level_bpa["IgnorePublicAcls"]
    ):
        # check for bucket level bpa blocks public access via policy
        if not is_bucket_level_bpa_configured(bucket_level_bpa) or (
            "IgnorePublicAcls" in bucket_level_bpa
            and not bucket_level_bpa["IgnorePublicAcls"]
        ):
            # check policy is configured
            if is_policy_configured(policy_statements):
                # check for policy that allows or blocks public access
                for policy_statement in policy_statements:
                    if policy_statement["Effect"] == "Deny" and (
                        policy_statement["Action"] == "s3:ListBucket"
                        or policy_statement["Action"] == "s3:*"
                    ):
                        # policy statement that blocks public access found
                        # hence allowed is False
                        allowed = False

                        # this break handles 2 cases
                        # 1. if this condition hits first and there are still more policy statements
                        # that might allow for public access, even then more restricting policy statement
                        # i.e., blocking policy statement will take precedence, and hence, no need to
                        # check further
                        # 2. if this condition hits after finding some other policy statement, that allows
                        # public access, even then, blocking policy statement will take precedence,
                        # and hence, no need to check further
                        break
                    if (
                        policy_statement["Effect"] == "Allow"
                        and (
                            (
                                "*" in policy_statement["Resource"]
                                and f"arn:aws:s3:::{bucket_name}"
                                in policy_statement["Resource"]
                            )
                            or policy_statement["Resource"]
                            == f"arn:aws:s3:::{bucket_name}"
                        )
                        and "*" in policy_statement["Principal"]
                        and (
                            policy_statement["Action"] == "s3:ListBucket"
                            or policy_statement["Action"] == "s3:*"
                        )
                        and (
                            not "Condition" in policy_statement
                            or (
                                "StringLike" in policy_statement["Condition"]
                                and policy_statement["Condition"]["StringLike"]
                                and "*" in policy_statement["Condition"]["StringLike"]
                            )
                        )
                    ):
                        # policy statement that allows public access found
                        # hence allowed is True
                        allowed = True
                        # Blocking policy statement takes precedence, therefore, even if we now
                        # have a policy statement that allows for public access, keep checking until
                        # conflicting policy statement is found, or there are no more policy statements
    return allowed


def verify_public_access(bucket_name):
    """
    verify public access to bucket contents by attempting to list them via
    GET request to "http://{bucket_name}.s3.amazonaws.com", which will have
    no association with session. This will be anonymous access attempt.

    :param bucket_name: bucket name

    :return (str,str,list or None):
        in this tuple, first string verifies that public access is "Allowed"
        or "Blocked" or error text (if any)
        second string verifies that bucket contents were "Prevented" or
        "NotPrevented" access publically
        last value is list of keys of at most 3 bucket contents if second string
        is "NotPrevented", or it will be None if second string is "Prevented"
    """
    try:
        # GET api call
        response = requests.get(f"http://{bucket_name}.s3.amazonaws.com")
        if response.ok:
            # Find Content Keys of at most 3 objects of s3 bucket
            root = ElementTree.fromstring(response.text)
            contents = []
            for child in root:
                if child.tag.endswith("Contents"):
                    for item in child:
                        if item.tag.endswith("Key"):
                            if len(contents) < 3:
                                contents.append(item.text)
                            else:
                                break
            return ("Allowed", "NotPrevented", contents)
        else:
            result["PublicAccessToBucket"] = "Blocked"
            root = ElementTree.fromstring(response.text)
            logging.exception(root.items())
            for child in root:
                if child.tag == "Code":
                    logging.exception(child.text, exc_info=False)
                    return ("Blocked", "Prevented", None)

    except Exception as e:
        logging.exception(
            f"Could not access {bucket_name} bucket contents.", exc_info=True
        )
        return (str(e), "Prevented", None)


def find_buckets_bpa(session, buckets, account_id):
    """
    :param session: boto3 session
    :param bucket_name: bucket name
    :param account_id: account ID

    :return dict():
    """

    # collect the output in dict
    output = {}
    output["AccountLevelBPA"] = get_account_level_bpa(session, account_id)

    # initialize a dict in output["Buckets"]
    # this will have individual bucket related bpa config, policies, acls & output
    output["Buckets"] = {}
    for bucket in buckets:
        bucket_name = bucket["Name"]
        # find if bucket is public
        bucket_data = {}
        bucket_data["BlockPublicAccess"] = get_bucket_level_bpa(session, bucket_name)
        bucket_data["ACL"] = get_bucket_acl(session, bucket_name)
        bucket_data["Policy"] = get_bucket_policy(session, bucket_name)
        acls_allow = find_acl_allows_public_access(
            output["AccountLevelBPA"],
            bucket_data["BlockPublicAccess"],
            bucket_data["ACL"],
        )
        policy_allow = find_policy_allows_public_access(
            bucket_name,
            output["AccountLevelBPA"],
            bucket_data["BlockPublicAccess"],
            bucket_data["Policy"],
        )

        if policy_allow and acls_allow:
            bucket_data["PublicAccessAllowedBy"] = "ACLAndPolicy"
        elif policy_allow:
            bucket_data["PublicAccessAllowedBy"] = "Policy"
        elif acls_allow:
            bucket_data["PublicAccessAllowedBy"] = "ACL"
        else:
            bucket_data["PublicAccessAllowedBy"] = "NotAllowed"

        if policy_allow or acls_allow:
            (
                bucket_data["PublicAccessToBucket"],
                bucket_data["PublicAccessToBucketObjects"],
                bucket_data["First3Objects"],
            ) = verify_public_access(bucket_name)
        else:
            if (
                is_account_level_bpa_error(output["AccountLevelBPA"])
                or is_bucket_level_bpa_error(bucket_data["BlockPublicAccess"])
                or is_acl_error(
                    bucket_data["ACL"] or is_policy_error(bucket_data["Policy"])
                )
            ):
                bucket_data["PublicAccessToBucket"] = None
                bucket_data["PublicAccessToBucketObjects"] = None
                bucket_data["First3Objects"] = None
            else:
                bucket_data["PublicAccessToBucket"] = "Blocked"
                bucket_data["PublicAccessToBucketObjects"] = "Prevented"
                bucket_data["First3Objects"] = None

        print_output_message(bucket_name, bucket_data, output["AccountLevelBPA"])
        output["Buckets"].update({bucket_name: bucket_data})

    return output
