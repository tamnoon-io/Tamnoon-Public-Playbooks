from datetime import datetime, timedelta
import logging
import botocore.exceptions
import time


def get_cloudwatch_data(session, log_group=None, query=None, hoursback=240):
    if not session:
        logging.error("no botosession passed. breaking")
        exit(0)

    client = session.client("logs")
    today = datetime.today()
    timedelta_hours = timedelta(hours=int(hoursback))
    start_time = int((today - timedelta_hours).timestamp())
    logging.info("the query to be used is: \n" + query + "\n")
    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )
    try:
        query_id = start_query_response["queryId"]
        response = None
        while response == None or response["status"] == "Running":
            logging.info("Waiting for query to complete ...")
            time.sleep(2)
            response = client.get_query_results(queryId=query_id)
    except botocore.exceptions.ClientError as ce:
        logging.error(str(ce))
        exit()

    condensedresponse = []
    for rr in response["results"]:
        condensedresponse.append({x["field"]: x["value"] for x in rr})
    return condensedresponse
