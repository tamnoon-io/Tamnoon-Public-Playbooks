import sys
import os
import logging
from .GetCloudWatchData import get_cloudwatch_data
from .FlowlogQueryBuilder import flowlog_query_builder
from ..Utils import utils as utils

NUMBER_OF_HOURS_BACK = 720


def get_regions(session=None):
    ec2 = session.client("ec2", region_name="us-east-1")
    return [x["RegionName"] for x in ec2.describe_regions()["Regions"]]


def get_sg(session=None, region=None):
    ec2 = session.client("ec2", region_name=region)
    routeput = []
    # Describe all security groups
    paginator = ec2.get_paginator("describe_security_groups")
    secgroups = [y for x in paginator.paginate() for y in x["SecurityGroups"]]
    if len(secgroups) > 0:
        paginator = ec2.get_paginator("describe_network_interfaces")
        ENIs = [y for x in paginator.paginate() for y in x["NetworkInterfaces"]]
        secgrouprefs = ec2.describe_security_group_references(
            GroupId=[x["GroupId"] for x in secgroups]
        )["SecurityGroupReferenceSet"]
        paginator = ec2.get_paginator("describe_security_group_rules")
        sgRules = [
            y
            for x in paginator.paginate(
                Filters=[
                    {
                        "Name": "group-id",
                        "Values": [z["GroupId"] for z in secgroups],
                    },
                ]
            )
            for y in x["SecurityGroupRules"]
        ]
        for sg in secgroups:
            soutput = {
                x: sg[x] for x in ["GroupId", "GroupName", "Description", "VpcId"]
            }
            soutput["referencingPeeredVPCs"] = [
                x["ReferencingVpcId"]
                for x in secgrouprefs
                if x["GroupId"] == sg["GroupId"]
            ]
            soutput["SGRules"] = [x for x in sgRules if x["GroupId"] == sg["GroupId"]]
            ifs = []
            for inf in ENIs:
                if sg["GroupId"] in [x["GroupId"] for x in inf["Groups"]]:
                    ioutput = {
                        y: inf.get(y)
                        for y in [
                            "NetworkInterfaceId",
                            "InterfaceType",
                            "Status",
                            "Description",
                        ]
                    }
                    if "Attachment" in inf.keys():
                        ioutput["AttachmentStatus"] = inf["Attachment"]["Status"]
                        ioutput["AttachedInstanceId"] = inf["Attachment"].get(
                            "InstanceId"
                        )
                    ifs.append(ioutput)
            soutput["AssociatedInterfaces"] = ifs
            routeput.append(soutput)
    return routeput


def get_sgs(session=None, regions=None):
    output = {}
    for region in regions:
        output[region] = get_sg(session, region)
    return output


def regionhandler(
    region=None,
    session=None,
    output_directory="",
    allgroups=[],
    interestinggroups=[],
    hoursback=NUMBER_OF_HOURS_BACK,
    exclude_private_ips_from_source=False,
    exclude_src_ports=False
):
    logging.info(
        "the following groups are intereesting: \n"
        + (
            "\n".join(interestinggroups) + " out of " + "\n".join(allgroups)
            if interestinggroups.__len__() > 0
            else str(None)
        )
    )
    relevantsgs = [x for x in allgroups[region] if x["GroupId"] in interestinggroups]
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_flow_logs")
    Flowlogs = [y for x in paginator.paginate() for y in x["FlowLogs"]]
    FLresources = [x["ResourceId"] for x in Flowlogs]
    rop = []
    for sg in relevantsgs:
        sgop = dict()
        logging.info(f"handling SG {sg['GroupId']}")
        ifs = [x["NetworkInterfaceId"] for x in sg["AssociatedInterfaces"]]
        vpc = sg["VpcId"]
        if len(ifs) == 0:
            logging.info(f"{sg['GroupId']} protects no interfaces. Nothing to check")
            sgop[
                sg["GroupId"]
            ] = f"{sg['GroupId']} protects no interfaces. Nothing to check"
        else:
            gotmatch = False
            if vpc in FLresources:
                loggroup = [
                    x["LogGroupName"] if "LogGroupName" in x else "-"
                    for x in Flowlogs
                    if x["ResourceId"] == vpc
                ][0]
                response = getdata(
                    session,
                    sg["GroupId"],
                    loggroup,
                    ifs,
                    region,
                    hoursback,
                    output_directory,
                    exclude_private_ips_from_source=exclude_private_ips_from_source,
                    exclude_src_ports=exclude_src_ports
                )
                sgop[sg["GroupId"]] = "data exported to " + response
                gotmatch = True
            else:
                ZZ = {
                    x: [if1 for if1 in ifs if if1 == x["ResourceId"]]
                    for x in Flowlogs
                    if [if1 for if1 in ifs if if1 == x["ResourceId"]] != []
                }
                for zz in ZZ.keys():
                    loggroup = zz["LogGroupName"]
                    response = getdata(
                        session,
                        sg["GroupId"],
                        loggroup,
                        ZZ[zz],
                        region,
                        hoursback,
                        output_directory,
                        exclude_private_ips_from_source=exclude_private_ips_from_source,
                    )
                    sgop[sg["GroupId"]] = "data exported to " + response
                    gotmatch = True
            if not gotmatch:
                logging.info(
                    f"No log group was found for investigating sg {sg['GroupId']}"
                )
                sgop[
                    sg["GroupId"]
                ] = f"No log group was found for investigating sg {sg['GroupId']}"
        rop.append(sgop)
    return rop


def getdata(
    session,
    sgname,
    loggroup,
    ifs,
    region,
    hoursback,
    output_directory=".",
    exclude_private_ips_from_source=False,
    exclude_src_ports=False
):
    if hoursback == None:
        hoursback = NUMBER_OF_HOURS_BACK
    query = flowlog_query_builder(
        interface_ids=" ".join(ifs),
        exclude_private_ips_from_source=exclude_private_ips_from_source,exclude_src_ports=exclude_src_ports
    )
    output = get_cloudwatch_data(
        session=session,
        log_group=loggroup,
        query=query,
        hoursback=hoursback,
    )
    filename = str(os.path.join(output_directory, sgname))
    utils.export_data(filename, output, "JSON")
    return filename + ".json"


"""
to find more generally large public IP subnets allowed (mask < NN)
interestingsgs=[sg["GroupId"] for reg in allgroups.keys() for sg in allgroups[reg] if 
                len([1 for x in sg["SGRules"] if x["IsEgress"]==False and 
                     (x.get("CidrIpv4")=="0.0.0.0/0" or (not (re.match("^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*$",x.get("CidrIpv4").split("/")[0])) and int(x.get("CidrIpv4").split("/")[1])<NN)) 
                     ])>0]


"""
