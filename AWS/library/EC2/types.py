"""
types of EC2 automations
"""
from enum import Enum


class EC2Types(Enum):
    """
    EC2Types
    """

    SNAPSHOT = "snapshot"
    SG = "security-group"
    VPC = "vpc"
    EC2 = "ec2"
    SUBNET = "subnet"
    ALB = 'alb'


class ApplicationLoadBalancerTypeActions(Enum):
    """
    ApplicationLoadBalancerTypeActions
    """
    REDIRECT_TO_HTTPS = "redirect_to_https"


class SnapshotTypeActions(Enum):
    """
    SnapshotTypeActions
    """

    DELETE = "delete"
    LIST = "ls"
    ENCRYPT = "encrypt"


class SecurityGroupTypeActions(Enum):
    """
    SecurityGroupTypeActions
    """

    DELETE = "delete"
    CLEAN_UNUSED_SG = "clean_unused_sg"
    GET_USAGE = "get_usage"
    GET_ALL_FLOW_LOGS = "get_all_flow_logs"
    REMOVE_OR_REPLACE_RULES = "remove_or_replace_rules"


class VPCTypeActions(Enum):
    """
    VPCTypeActions
    """

    CREATE_FLOW_LOG = "create_flow_log"


class EC2TypeActions(Enum):
    """
    EC2TypeActions
    """

    GET_IMDSV1_USAGE = "get_imdsv1_usage"
    ENFROCE_IMDSV2 = "enforce_imdsv2"
    FIND_LOAD_BALANCERS = "find_load_balancers"


class SubnetTypeActions(Enum):
    """
    SubnetTypeActions
    """

    DISABLE_PUBLIC_IP_ASSIGNMENT = "disable_public_ip_assignment"
