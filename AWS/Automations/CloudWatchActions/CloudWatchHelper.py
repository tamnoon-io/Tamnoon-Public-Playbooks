import logging
import json
import argparse
import os
import botocore.exceptions
from datetime import datetime, timedelta
import time
import re

from ..Utils import utils


def flowlog_query_builder(dst_addr=None, interfac_ids=None, dst_port=None, exclude_private_ips_from_source=False):
    '''
    This function build cloud watch log query for vpc flow logs

    :param dst_addr: The address that the traffic was targeted to
    :param interfac_ids: The eni that this traffic was recorded on
    :param dst_port: The targeted port
    :param exclude_private_ips_from_source: A flag to mark if to exclude private ips
    :return:
    '''
    base_filter = '  filter action="ACCEPT" ' \
                 ' | filter dstPort<=1024 or (dstPort>1024 and srcPort>1024) '


    base_stat = ' | stats count(*) as count by interfaceId, srcAddr, srcPort, dstAddr, dstPort '
    base_sort = ' | sort by count desc '
    base_limit = ' | limit 10000 '

    if not dst_addr and not interfac_ids and not dst_port:
        print("no query filters were provided....quitting")
        exit()

    ips, enis, ports = None, None, None
    ip_string, eni_string, port_string = "", "", ""
    filter_string = ""

    if dst_addr:
        ips = [x.strip() for x in re.split(" |,", dst_addr) if isip(x.strip())]
        ip_string = "| filter (" + " or ".join(['dstAddr  = "' + ip + '"' for ip in ips]) + ")"
    if interfac_ids:
        enis = [x.strip() for x in re.split(" |,", interfac_ids)]
        eni_string = "| filter (" + " or ".join(['interfaceId  = "' + ip + '"' for ip in enis]) + ")"
    if dst_port:
        ports = [str(x.strip()) for x in re.split(" |,", dst_port)]
        port_string = "| filter (" + " or ".join(['dstPort  = "' + p + '"' for p in ports]) + ")"

    if ip_string:
        base_filter = base_filter + ip_string
    elif eni_string:
        base_filter = base_filter + eni_string

    if port_string:
        base_filter = base_filter + port_string

    if exclude_private_ips_from_source:
        base_filter = base_filter + " and ( srcAddr not like /^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*$/ )"

    return base_filter + base_stat + base_sort + base_limit


def get_cloudwatch_data(session, log_group=None, query=None, hoursback=240):
    if not session:
        logging.error("no botosession passed. breaking")
        exit(0)

    client = session.client('logs')
    start_time = int((datetime.today() - timedelta(hours=int(hoursback))).timestamp())
    logging.info("the query to be used is: \n" + query + "\n")
    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )
    try:
        query_id = start_query_response['queryId']
        response = None
        while response == None or response['status'] == 'Running':
            logging.info('Waiting for query to complete ...')
            time.sleep(2)
            response = client.get_query_results(queryId=query_id)
    except botocore.exceptions.ClientError as ce:
        logging.error(str(ce))
        exit()

    condensedresponse = []
    for rr in response['results']:
        condensedresponse.append({x["field"]: x["value"] for x in rr})
    return condensedresponse


# def export_data_csv(output, accountid, savepath, fileoutputstr):
#     try:
#         import pandas as pd
#     except:
#         print("pandas could not be loaded. file could not ba saved, saving as json")
#         export_data_json(output, accountid, savepath, fileoutputstr)
#         return
#     pd.DataFrame(output).to_csv(os.path.join(savepath, fileoutputstr+"_"+accountid+".csv"))
#     print("printed csv to path:" + str(os.path.join(savepath, fileoutputstr+"_"+accountid+".csv")))

# def export_data_json(output, accountid, savepath, fileoutputstr):
#     with open(os.path.join(savepath, fileoutputstr+"_"+accountid+".json"), "w") as f:
#         json.dump(output, f,ensure_ascii=False, indent=4 )
#     print("printed json to path: "+str(os.path.join(savepath, fileoutputstr+"_"+accountid+".json")) )

# def export_data(session, output, export_format, savepath, fileoutputstr):
#     if export_format==None:
#         export_format='json'
#     if savepath==None:
#         savepath=os.getcwd()
#     accountid=session.client('sts').get_caller_identity().get('Account')
#     print("got account id: "+ accountid)
#     if export_format=='csv':
#         export_data_csv(output, accountid, savepath, fileoutputstr)
#     else:
#         export_data_json(output, accountid, savepath, fileoutputstr)


def isip(s):
    import ipaddress
    try:
        a = ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _do_query_execution(session, action, asset_ids, action_params):

    hoursback = action_params['hoursback'] if 'hoursback' in action_params else None
    log_group = action_params['log_group'] if 'log_group' in action_params else None

    if action == "flow_log":
        dst_addr = action_params['dstAddr'] if 'dstAddr' in action_params else None
        dst_port = action_params['dstPort'] if 'dstPort' in action_params else None
        interfac_ids = asset_ids
        exclude_private_ips_from_source = action_params[
            'excludePrivateIPsFromSource'] if 'excludePrivateIPsFromSource' in action_params else None
        if not log_group or not (dst_addr or interfac_ids or dst_port):
            logging.error("you have to include log_group and dstAddr or interfaceId or dst_port params. Quiting")
            exit()

        query = flowlog_query_builder(dst_addr=dst_addr, interfac_ids=interfac_ids, dst_port=dst_port,
                                      exclude_private_ips_from_source=exclude_private_ips_from_source)

        output = get_cloudwatch_data(session=session, log_group=log_group, query=query,
                                     hoursback=hoursback)

        return output



def _do_action(action_type, session, dry_run, action, asset_ids, action_params):
    '''
    This function route between Cloud Watch actions
    :param action_type: The specific action type watch action to execute
    :param session: The boto session to use
    :param dry_run: dry run flag
    :param action: The sub cloud watch action to execute
    :param asset_ids: List of cloud asset ids to works on
    :param action_parmas: The specific action's parameters
    :return:
    '''

    if action_type == "query":
        return _do_query_execution(session=session, action=action, asset_ids=asset_ids, action_params=action_params)



if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--file', type=str, help='YAML file containing arguments.', default=None)
    parser.add_argument('--profile', required=False, type=str, default=None)
    parser.add_argument('--type', required=False, type=str, default="query")
    parser.add_argument('--actionParams', required=False, type=json.loads, default=None)
    parser.add_argument('--assetIds', required=False, type=str)
    parser.add_argument('--awsAccessKey', required=False, type=str, default=None)
    parser.add_argument('--awsSecret', required=False, type=str, default=None)
    parser.add_argument('--awsSessionToken', required=False, type=str, default=None)
    parser.add_argument('--outputDirectory', required=False, type=str)
    parser.add_argument('--outputType', required=False, type=str)
    parser.add_argument('--dryRun', required=False, type=bool, default=False)
    parser.add_argument('--fileoutputstr', required=False, type=str, default="TamnoonCloudWatchQuery")
    parser.add_argument('--regions', required=False, type=str, default="us-east-1")


    args = parser.parse_args()
    utils.log_setup(args.logLevel)

    params = utils.build_params(args=args)


    profile = params.profile
    action = params.action
    action_type = params.type
    regions = params.regions
    asset_ids = params.assetIds

    action_params = params.actionParams
    action_params = json.loads(action_params) if action_params and type(action_params) != dict else action_params
    aws_access_key_id = params.awsAccessKey
    aws_secret_access_key = params.awsSecret
    aws_session_token = params.awsSessionToken
    dry_run = params.dryRun
    output_type = params.outputType if params.outputType else "csv"
    output_directory = params.outputDirectory if params.outputDirectory else os.getcwd()
    fileoutputstr = params.fileoutputstr if params.fileoutputstr else 'TamnoonCloudWatchQuery'
    result = dict()

    logging.info(f"Going to run over {regions} - region")
    session = utils.setup_session(profile=profile, aws_access_key=aws_access_key_id, aws_secret=aws_secret_access_key,
                                  aws_session_token=aws_session_token)
    caller_identity = utils.get_caller_identity(session=session)
    result['caller-identity'] = caller_identity
    list_of_regions = utils.get_regions(regions_param=regions, session=session)
    for region in list_of_regions:
        logging.info(f"Working on Region - {region}")
        session = utils.setup_session(profile=profile, region=region, aws_access_key=aws_access_key_id,
                                      aws_secret=aws_secret_access_key, aws_session_token=aws_session_token)
        action_result = _do_action(action_type=action_type, session=session, dry_run=dry_run, action=action,
                                   asset_ids=asset_ids, action_params=action_params)
        logging.info(f"output record number is: {str(len(action_result))}")
        if action_result:
            result[region] = action_result
        else:
            result[region] = {}

        logging.info(f"Going to persist output to: {fileoutputstr}-{region}")
        utils.export_data(file_name=os.path.join(output_directory, f"{fileoutputstr}-{region}" + "." + output_type), output=action_result,
                          export_format=output_type.upper())


