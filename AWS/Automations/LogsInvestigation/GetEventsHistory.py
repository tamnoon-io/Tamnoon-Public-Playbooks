import logging
import json
from datetime import datetime, timedelta
from Automations.Utils.utils import Params


def validate_action_params(action_params, days):
    if days < 0.01 or days > 90:
        raise ValueError(
            "days in --actionParams support values between 0.01 and 90 including 0.01 and 90"
        )
    if "AttributeKey" not in action_params:
        raise KeyError("AttributeKey is required in --actionParams")
    if "AttributeValue" not in action_params:
        raise KeyError("AttributeValue is required in --actionParams")
    return True


def parse_access_key_events(events):
    eventKeys = [
        "EventId",
        "EventName",
        "ReadOnly",
        "AccessKeyId",
        "EventTime",
        "EventSource",
        "Username",
        "Resources",
        "CloudTrailEvent",
    ]
    for event in events:
        for eventKey in eventKeys:
            if eventKey == "EventTime":
                event[eventKey] = event[eventKey].ctime()
            if eventKey == "CloudTrailEvent":
                event[eventKey] = json.loads(event[eventKey])
    return events


def parse_events(events, attribute_key):
    return parse_access_key_events(events)


def get_events_history(
        session=None,
        attribute_key=None,
        attribute_value=None,
        days=14,
        duration_end_time=datetime.utcnow(),
):
    result = []
    duration_start_time = datetime.strptime(
        duration_end_time.ctime(), "%a %b %d %H:%M:%S %Y"
    ) - timedelta(days=days)
    cloudtrail_client = session.client("cloudtrail")
    next_token = ""
    SEARCH_MORE = True
    try:
        while SEARCH_MORE:
            if SEARCH_MORE:
                logging.info(
                    f"Getting activity... from {duration_start_time.ctime()} to {duration_end_time.ctime()}\t\t{len(result)} results found"
                )
            lookup_response = Params(
                cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": attribute_key,
                            "AttributeValue": attribute_value},
                    ],
                    StartTime=duration_start_time,
                    EndTime=duration_end_time,
                    NextToken=next_token,
                )
                if next_token
                else cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": attribute_key,
                            "AttributeValue": attribute_value},
                    ],
                    StartTime=duration_start_time,
                    EndTime=duration_end_time,
                )
            )
            events = lookup_response.get("Events", [])
            events = parse_events(events, attribute_key)
            result.extend(events)
            next_token = lookup_response.get("NextToken", None)
            SEARCH_MORE = not not next_token
    except cloudtrail_client.exceptions.InvalidLookupAttributesException:
        logging.info(
            "Invalid Attribute Key. Please Check Playbook for Valid AttributeKey.")
        return "Invalid Attribute Key. Please Check Playbook for Valid AttributeKey."
    except Exception as e:
        logging.info(f"Something went wrong. {e}")
        return f"Something went wrong. {e}"
    result_len = len(result)
    if result_len == 0:
        msg = f"No activity was found for the given AttributeKey {attribute_key} in given region {session.region_name}"
        logging.info(msg)
        return msg

    result = sorted(result, key=lambda item: item["EventTime"], reverse=True)
    logging.info(f"Found total {result_len} events")
    return result
