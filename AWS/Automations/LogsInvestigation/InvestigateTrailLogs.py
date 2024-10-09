import json
import re
import logging
import time
import botocore.exceptions

schema = [
    {
        "name": "eventversion",
        "type": "STRING",
    },
    {
        "name": "useridentity",
        "type": "STRUCT<type:STRING,principalid:STRING,arn:STRING,accountid:STRING,invokedby:STRING,accesskeyid:STRING,username:STRING,sessioncontext:STRUCT<attributes:STRUCT<mfaauthenticated:STRING,creationdate:STRING>,sessionissuer:STRUCT<type:STRING,principalid:STRING,arn:STRING,accountid:STRING,username:STRING>,ec2roledelivery:STRING,webidfederationdata:map<STRING,STRING>>>",
    },
    {
        "name": "eventtime",
        "type": "STRING",
    },
    {
        "name": "eventsource",
        "type": "STRING",
    },
    {
        "name": "eventname",
        "type": "STRING"
    },
    {
        "name": "awsregion",
        "type": "STRING"
    },
    {
        "name": "sourceipaddress",
        "type": "STRING"
    },
    {
        "name": "useragent",
        "type": "STRING"
    },
    {
        "name": "errorcode",
        "type": "STRING"
    },
    {
        "name": "errormessage",
        "type": "STRING"
    },
    {
        "name": "requestparameters",
        "type": "STRING"
    },
    {
        "name": "responseelements",
        "type": "STRING"
    },
    {
        "name": "additionaleventdata",
        "type": "STRING"
    },
    {
        "name": "requestid",
        "type": "STRING"
    },
    {
        "name": "eventid",
        "type": "STRING"
    },
    {
        "name": "resources",
        "type": "ARRAY<STRUCT<arn:STRING,accountid:STRING,type:STRING>>"
    },
    {
        "name": "eventtype",
        "type": "STRING"
    },
    {
        "name": "apiversion",
        "type": "STRING"
    },
    {
        "name": "readonly",
        "type": "STRING"
    },
    {
        "name": "recipientaccountid",
        "type": "STRING"
    },
    {
        "name": "serviceeventdetails",
        "type": "STRING"
    },
    {
        "name": "sharedeventid",
        "type": "STRING"
    },
    {
        "name": "vpcendpointid",
        "type": "STRING"
    },
    {
        "name": "tlsdetails",
        "type": "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
    }
]


def replace_non_alphanumeric_with_underscore(input_string):
    """
    Replaces non alpha numeric characters with underscore "_"

    :param input_string: string to process.
    :type input_string: str

    :return: Processed string.
    :rtype: str
    """
    # Define a regular expression to match non-alphanumeric characters
    regex = re.compile("[^a-zA-Z0-9]")

    # Replace non-alphanumeric characters with underscore
    modified_string = regex.sub("_", input_string)

    return modified_string


def drop_table(athena_client, database, table_name, s3_location_output):
    """
    Drop an Athena table.

    :param athena_client: boto3 client for athena.
    :type athena_client: Athena.Client
    :param database: The name of the Athena database.
    :type database: str
    :param table_name: The name of the table to be analyzed.
    :type table_name: str
    :param s3_location_output: The S3 location where the data for the table will be stored.
    :type s3_location_output: str

    :return: True for success and False for failure.
    :rtype: bool
    """
    # Query to analyze S3 access logs for unknown IP addresses
    drop_query = f"DROP TABLE {table_name}"

    logging.info(f"drop query: {drop_query}")
    try:
        response = athena_client.start_query_execution(
            QueryString=drop_query,
            QueryExecutionContext={"Database": database},
            ResultConfiguration={"OutputLocation": s3_location_output},
        )

        query_execution_id = response["QueryExecutionId"]
        logging.info(
            f"Drop query submitted. Query execution ID: {query_execution_id}")

        # Get the query results
        count = 0
        while True:
            execution = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            logging.info(execution["QueryExecution"]["Status"]["State"])
            if execution["QueryExecution"]["Status"]["State"] not in [
                "QUEUED",
                "RUNNING",
            ]:
                return execution["QueryExecution"]["Status"]["State"] == "SUCCEEDED"
            else:
                count += 1
                time.sleep(0.1)
                if count > 600:
                    # if query is still not resolved after one minute (0.1 sleep duration *600 count seconds),
                    # then send cancel execution, and assume failure
                    athena_client.stop_query_execution(
                        QueryExecutionId=query_execution_id)
                    return False

    except botocore.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "EntityNotFoundException":
            return True
        else:
            # Handle other exceptions
            logging.exception(f"Error executing drop query: ", exc_info=True)
            return False
    except Exception as e:
        logging.exception(f"Error executing drop query: ", exc_info=True)
        return False


def delete_from_bucket(s3_client, bucket_name, key):
    """
    delets contents of bucket from inside of given key and including given key.

    :param s3_client: boto3 client for s3.
    :type s3_client: S3.Client
    :param bucket_name: The name of the s3 bucket.
    :type bucket_name: str
    :param key: The key of objects that contain logs.
    :type key: str

    :return: True for success and False for failure.
    :rtype: bool
    """
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=key)
        count = 1 + len(response.get("Contents", []))
        logging.info(
            f"Deleting {count} keys generated during automation execution as output of athena query from s3://{bucket_name}/{key}"
        )
        for obj in response.get("Contents", []):
            s3_client.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3_client.delete_object(Bucket=bucket_name, Key=key)
        logging.info(f"Delete finished")
        return True
    except Exception as ex:
        logging.exception(
            f"Failed to delete generated files from s3://{bucket_name}/{key}",
            exc_info=True,
        )
        return False


def analyze_cloudtrail_trails_logs(
        athena_client,
        table_name,
        s3_location_output,
        query_filter,
        days=1
):
    analyse_query = \
        f"""
                        SELECT *
                        FROM {table_name}
                        WHERE date_diff('day', from_iso8601_timestamp(eventtime), current_timestamp) <= {days}
                """
    resources_key_in_query_filter = False
    for tuple_data in query_filter:
        if 'resources' in tuple_data[0]:
            resources_key_in_query_filter = True
            break

    if resources_key_in_query_filter:
        analyse_query = \
            f"""
            SELECT *
            FROM {table_name}
            CROSS JOIN UNNEST(resources) AS t(filtered_resource)
            WHERE date_diff('day', from_iso8601_timestamp(eventtime), current_timestamp) <= {days}
            """

    for i in range(len(query_filter)):
        filter_keys = query_filter[i][0].split(".")
        is_field_type_array = False
        for j in range(len(schema)):
            if filter_keys[0] == schema[j]['name'] and schema[j]['type'].startswith("ARRAY"):
                is_field_type_array = True
                break
        if is_field_type_array:
            if isinstance(query_filter[i][1], list):
                analyse_query += f""" AND json_extract_scalar(CAST(t.filtered_resource AS JSON), '$.{filter_keys[1]}') IN {tuple(query_filter[i][1])}"""
            else:
                analyse_query += f""" AND json_extract_scalar(CAST(t.filtered_resource AS JSON), '$.{filter_keys[1]}')='{query_filter[i][1]}'"""
        elif filter_keys[0] in ['additionaleventdata', 'requestparameters', 'responseelements']:
            if isinstance(query_filter[i][1], list):
                analyse_query += f""" AND json_extract_scalar({filter_keys[0]}, '$.{filter_keys[1]}') IN {tuple(query_filter[i][1])}"""
            else:
                analyse_query += f""" AND json_extract_scalar({filter_keys[0]}, '$.{filter_keys[1]}')='{query_filter[i][1]}'"""
        else:
            if isinstance(query_filter[i][1], list):
                analyse_query += f""" AND {query_filter[i][0]} IN {tuple(query_filter[i][1])}"""
            else:
                analyse_query += f""" AND {query_filter[i][0]}='{query_filter[i][1]}'"""
    logging.info(f"analyse query: {analyse_query}")
    try:
        response = athena_client.start_query_execution(
            QueryString=analyse_query,
            QueryExecutionContext={"Database": "default"},
            ResultConfiguration={"OutputLocation": s3_location_output},
        )

        query_execution_id = response["QueryExecutionId"]
        logging.info(
            f"Analysis query submitted. Query execution ID: {query_execution_id}"
        )

        # Get the query results
        count = 0
        while True:
            execution = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            logging.info(execution["QueryExecution"]["Status"]["State"])
            if execution["QueryExecution"]["Status"]["State"] not in [
                "QUEUED",
                "RUNNING",
            ]:
                if execution["QueryExecution"]["Status"]["State"] == "SUCCEEDED":
                    query_results = athena_client.get_query_results(
                        QueryExecutionId=query_execution_id
                    )
                    # Convert query results to JSON
                    result_json = []
                    for row in query_results["ResultSet"]["Rows"][1:]:
                        result_json.append(
                            {
                                query_results["ResultSet"]["Rows"][0]["Data"][i][
                                    "VarCharValue"
                                ]: row["Data"][i].get("VarCharValue")
                                for i in range(len(row["Data"]))
                            }
                        )
                    result_len = len(result_json)
                    if result_len == 0:
                        msg = f"No activity was found for the given query filter {json.dumps(query_filter)}"
                        logging.info(msg)
                    logging.info(f"Found total {result_len} events")

                    return {
                        "status": execution["QueryExecution"]["Status"]["State"],
                        "data": result_json,
                    }
                else:
                    return {
                        "status": execution["QueryExecution"]["Status"]["State"],
                        "data": None,
                    }

            else:
                count += 1
                time.sleep(0.1)
                if count > 600:
                    # if query is still not resolved after one minute (0.1 sleep duration *600 count seconds),
                    # then send cancel execution, and assume failure
                    athena_client.stop_query_execution(
                        QueryExecutionId=query_execution_id)
                    return {
                        "status": "CANCELLED",
                        "data": None,
                    }
    except Exception as e:
        logging.exception(f"Error executing analysis query:", exc_info=True)
        return {
            "status": "FAILED",
            "data": str(e),
        }


def create_athena_table(
        athena_client, table_name, s3_location_input, s3_location_output
):
    """
    Create an Athena table with the specified parameters.

    :param athena_client: boto3 client for athena.
    :type athena_client: Athena.Client
    :param database: The name of the Athena database.
    :type database: str
    :param table_name: The name of the table to be created.
    :type table_name: str
    :param s3_location_input: The S3 location from where the data logs will be read by athena.
    :type s3_location_input: str
    :param s3_location_output: The S3 location where the data for the table will be stored.
    :type s3_location_output: str

    :return: True for success and False for failure.
    :rtype: bool
    """

    columns_list = ", ".join(
        [f"{column['name']} {column['type']}" for column in schema]
    )
    create_external_table_query = f"""
    CREATE EXTERNAL TABLE IF NOT EXISTS {table_name} (
        {columns_list}
    )
    ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
    STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION '{s3_location_input}'
        """

    create_query = create_external_table_query
    logging.info(f"create query: {create_query}")
    try:
        # Execute the query
        response = athena_client.start_query_execution(
            QueryString=create_query,
            QueryExecutionContext={"Database": 'default'},
            ResultConfiguration={"OutputLocation": s3_location_output},
        )

        query_execution_id = response["QueryExecutionId"]
        logging.info(
            f"Table creation query submitted. Query execution ID: {query_execution_id}"
        )

        count = 0
        while True:
            # Get the query status
            execution = athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )
            logging.info(execution["QueryExecution"]["Status"]["State"])
            if execution["QueryExecution"]["Status"]["State"] not in [
                "RUNNING",
                "QUEUED",
            ]:
                return execution["QueryExecution"]["Status"]["State"] == "SUCCEEDED"
            else:
                count += 1
                time.sleep(0.1)
                if count > 600:
                    # if query is still not resolved after one minute (0.1 sleep duration *600 count seconds),
                    # then send cancel execution, and assume failure
                    athena_client.stop_query_execution(
                        QueryExecutionId=query_execution_id)
                    return False

    except Exception as ex:
        logging.exception(f"Table creation failed. {str(ex)}", exc_info=True)


def investigate_cloudtrail_trail_logs(
        trail_bucket_name,
        query_filter,
        cleanup,
        days=1,
        session=None):

    table_name = replace_non_alphanumeric_with_underscore(
        "test_cloudtrail_investigations" + "_" + trail_bucket_name
    )

    # initialize result
    result = {"status": None, "data": None,
              "cleanup": {"athena": False, "s3": False}}

    # Initialize AWS clients
    athena_client = session.client("athena")
    s3_client = session.client("s3")
    try:
        if trail_bucket_name:
            s3_location_input = f"s3://{trail_bucket_name}/"
            s3_location_output = f"s3://{trail_bucket_name}" + \
                '/athena_queried_logs/'
            logging.info(
                f"cloudtrail trail logs of s3 bucket {trail_bucket_name} are stored at {s3_location_input}"
            )

            create_athena_table_result = create_athena_table(
                athena_client,
                table_name,
                s3_location_input,
                s3_location_output
            )
            if create_athena_table_result:
                time.sleep(1)
                analysis_result = analyze_cloudtrail_trails_logs(
                    athena_client,
                    table_name,
                    s3_location_output,
                    query_filter,
                    days=days
                )
                result["status"] = analysis_result["status"]
                result["data"] = analysis_result["data"]
            else:
                result["status"] = "FAILED"
                result["data"] = "Table Creation Failed.Please Check whether S3 bucket and trail provided are correct."
            if cleanup:
                logging.info(
                    '"cleanup" is set in action params. Starting cleanup of generated table and s3 bucket files...'
                )
                result["cleanup"]["athena"] = drop_table(
                    athena_client,
                    'default',
                    table_name,
                    s3_location_output,
                )
                result["cleanup"]["s3"] = delete_from_bucket(
                    s3_client, trail_bucket_name, 'athena_queried_logs/'
                )
                logging.info("Cleanup finished")
        else:
            result["status"] = "FAILED"
            result["data"] = f"No such {trail_bucket_name} S3 bucket found for storing cloudtrail trail logs"

            logging.info(result["data"][0])
    except Exception as ex:
        result["status"] = "FAILED"
        result["data"] = [f"Something went wrong. {str(ex)}"]
        logging.info(result["data"][0])
    return result
