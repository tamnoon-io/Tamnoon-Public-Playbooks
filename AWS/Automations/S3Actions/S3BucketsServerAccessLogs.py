""" S3BucketServerAccessLogs """
import re
import time
import logging
import math
import botocore.exceptions

QUERY_TIMEOUT = 300

schema = [
    {"name": "bucketowner", "type": "STRING"},
    {"name": "bucket_name", "type": "STRING"},
    {"name": "requestdatetime", "type": "STRING"},
    {"name": "remoteip", "type": "STRING"},
    {"name": "requester", "type": "STRING"},
    {"name": "requestid", "type": "STRING"},
    {"name": "operation", "type": "STRING"},
    {"name": "key", "type": "STRING"},
    {"name": "request_uri", "type": "STRING"},
    {"name": "httpstatus", "type": "SMALLINT"},
    {"name": "errorcode", "type": "STRING"},
    {"name": "bytessent", "type": "BIGINT"},
    {"name": "objectsize", "type": "BIGINT"},
    {"name": "totaltime", "type": "STRING"},
    {"name": "turnaroundtime", "type": "STRING"},
    {"name": "referrer", "type": "STRING"},
    {"name": "useragent", "type": "STRING"},
    {"name": "versionid", "type": "STRING"},
    {"name": "hostid", "type": "STRING"},
    {"name": "sigv", "type": "STRING"},
    {"name": "ciphersuite", "type": "STRING"},
    {"name": "authtype", "type": "STRING"},
    {"name": "endpoint", "type": "STRING"},
    {"name": "tlsversion", "type": "STRING"},
    {"name": "accesspointarn", "type": "STRING"},
    {"name": "aclrequired", "type": "STRING"},
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


def create_database(athena_client, s3_location_output, database="TamnoonAnalysis"):
    """
    Create an Athena databse with the specified parameters.

    :param athena_client: boto3 client for athena.
    :type athena_client: Athena.Client
    :param s3_location_output: The S3 location where the data for the table will be stored.
    :type s3_location_output: str
    :param database: The name of the Athena database.
    :type database: str

    :return: True for success and False for failure.
    :rtype: bool
    """
    # Define the query to create a new database
    query = f'CREATE DATABASE IF NOT EXISTS {database}'

    try:
        # Set up the parameters for the query execution
        response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={
                # The database in which the query should be run; default is fine here
                'Database': 'default'
            },
            ResultConfiguration={
                'OutputLocation': s3_location_output  # Specify your S3 bucket for query results
            }
        )

        query_execution_id = response["QueryExecutionId"]
        logging.info(
            f"Databse creation query submitted. Query execution ID: {query_execution_id}"
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
                return {
                    "status": execution["QueryExecution"]["Status"]["State"],
                    "data": execution["QueryExecution"]["Status"]["State"] == "SUCCEEDED",
                }
            else:
                count += 1
                time.sleep(0.1)
                if count > QUERY_TIMEOUT * 10:
                    # if query is still not resolved after one minute (0.1 sleep duration *600 count seconds),
                    # then send cancel execution, and assume failure
                    athena_client.stop_query_execution(
                        QueryExecutionId=query_execution_id)
                    return {
                        "status": "CANCELLED",
                        "data": f"Database creation query exceeded timeout of {QUERY_TIMEOUT}s"
                    }

    except Exception as e:
        logging.exception(f"Database creation failed", exc_info=True)
        return {
            "status": "FAILED",
            "data": f"Database creation failed. {e}"
        }


def create_athena_table(
    athena_client, database, table_name, s3_location_input, s3_location_output, s3_output_template
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
    :param s3_output_template: The S3 location template where the data for the table will be stored.
        example: <s3_location_output>/<account-id>/<region>/<source-bucket-name>/${timestamp}/
    :type s3_output_template: str

    :return: True for success and False for failure.
    :rtype: bool
    """

    # prepare columns from schema
    columns_list = ", ".join(
        [f"`{column['name']}` {column['type']}" for column in schema]
    )
    storage_template = s3_location_output + '/${timestamp}/'
    create_external_table_query = f"""
CREATE EXTERNAL TABLE IF NOT EXISTS {table_name}({columns_list})
ROW FORMAT SERDE 
 'org.apache.hadoop.hive.serde2.RegexSerDe' 
WITH SERDEPROPERTIES ( 
 'input.regex'='([^ ]*) ([^ ]*) \\\\[(.*?)\\\\] ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\"[^\"]*\"|-) (-|[0-9]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) (\\\"[^\\\"]*\\\"|-) ([^ ]*)(?: ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*))?.*$') 
STORED AS INPUTFORMAT 
 'org.apache.hadoop.mapred.TextInputFormat' 
OUTPUTFORMAT 
 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION '{s3_location_input}' 
 TBLPROPERTIES (
  'projection.enabled'='true', 
  'projection.timestamp.format'='yyyy/MM/dd', 
  'projection.timestamp.interval'='1', 
  'projection.timestamp.interval.unit'='DAYS', 
  'projection.timestamp.range'='2024/01/01,NOW', 
  'projection.timestamp.type'='date', 
  'storage.location.template'='{s3_output_template if s3_output_template else storage_template}')
    """

    create_query = create_external_table_query
    logging.info(f"create query: {create_query}")
    try:
        # Execute the query
        response = athena_client.start_query_execution(
            QueryString=create_query,
            QueryExecutionContext={"Database": database},
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
                return {
                    "status": execution["QueryExecution"]["Status"]["State"],
                    "data": execution["QueryExecution"]["Status"]["State"] == "SUCCEEDED",
                }
            else:
                count += 1
                time.sleep(0.1)
                if count > QUERY_TIMEOUT * 10:
                    # if query is still not resolved after one minute (0.1 sleep duration *600 count seconds),
                    # then send cancel execution, and assume failure
                    athena_client.stop_query_execution(
                        QueryExecutionId=query_execution_id)
                    return {
                        "status": "CANCELLED",
                        "data": f"Table creation query exceeded timeout of {QUERY_TIMEOUT}s"
                    }

    except Exception as e:
        logging.exception(f"Table creation failed", exc_info=True)
        return {
            "status": "FAILED",
            "data": f"Table creation failed. {e}"
        }


def analyze_s3_access_logs(
    athena_client,
        database,
        table_name,
        s3_location_output,
        include_rejected=False,
        include_3xx=False
):
    """
    Analyze an Athena table for server access through public IPs.

    :param athena_client: boto3 client for athena.
    :type athena_client: Athena.Client
    :param database: The name of the Athena database.
    :type database: str
    :param table_name: The name of the table to be analyzed.
    :type table_name: str
    :param s3_location_output: The S3 location where the data for the table will be stored.
    :type s3_location_output: str
    :param include_rejected: if set to true, then logs will not be filtered by httpstatus, thus showing both accepted and rejected logs. If set to false, logs will be filtered for httpstatus between 200 and 299 (an efficient and maintainable approach). Default value is false.
    :type include_rejected: bool
    :param include_3xx: if set to true, then logs will be filtered by httpstatus between 200 and 399. If set to false, logs will be filtered by httpstatus between 200 and 299. Default value is false.
    :type include_3xx: bool

    Note: include-rejected and include-3xx are mutually exclusive. 
    You can set only one of them to be true at a time. If both are set to true, include-3xx will be ignored. 
    If both include-rejected and include-3xx are false, then only filter by 2xx http status.
    If include-rejected is true, then regardless of include-3xx, all http status will be included in output.
    If only include-3xx is true, then output may have either 2xx or 3xx status logs.

    :return: a dictionary containing a string "status" and list "data".
        Here, data will be None when status is other than "SUCCEEDED".
    :rtype: dict({"status": str, data: list)
    """
    # Query to analyze S3 access logs for unknown IP addresses
    http_status_filter = ''
    if not include_rejected:
        if include_3xx:
            http_status_filter = ' AND (httpstatus BETWEEN 200 AND 399)'
        else:
            http_status_filter = ' AND (httpstatus BETWEEN 200 AND 299)'
    analyse_query = f"""
SELECT *
FROM {table_name}
WHERE (requester = '-' OR requester IS NULL) AND
    (operation IS NOT NULL) AND (operation != '-' )
    {http_status_filter}
ORDER BY requestdatetime DESC
    """

    logging.info(f"analyse query: {analyse_query}")
    # add where clause for bucket_name
    try:
        response = athena_client.start_query_execution(
            QueryString=analyse_query,
            QueryExecutionContext={"Database": database},
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
                        new_json = dict()
                        for i in range(len(row["Data"])):
                            if "".join(row["Data"][i].keys()) or "".join(row["Data"][i].values()):
                                if row["Data"][i] and row["Data"][i]["VarCharValue"]:
                                    new_json.update(
                                        {
                                            query_results["ResultSet"]["Rows"][0]["Data"][i][
                                                "VarCharValue"
                                            ]: row["Data"][i]["VarCharValue"]
                                        }
                                    )
                        if len(new_json.keys()):
                            result_json.append(new_json)
                        else:
                            logging.debug("empty record: %s",
                                          str(row["Data"][i]))
                    logging.info(
                        "total %s anonymous access records found", len(result_json))
                    return {
                        "status": execution["QueryExecution"]["Status"]["State"],
                        "data": result_json,
                    }
                else:
                    return {
                        "status": execution["QueryExecution"]["Status"]["State"],
                        "data": execution["QueryExecution"]["Status"]["AthenaError"]
                        if "AthenaError" in execution["QueryExecution"]["Status"]
                        else execution["QueryExecution"]["Status"]["StateChangeReason"]
                        if "StateChangeReason" in execution["QueryExecution"]["Status"]
                        else "Something went wrong",
                    }

            else:
                count += 1
                time.sleep(0.1)
                if count > QUERY_TIMEOUT * 10:
                    # if query is still not resolved after one minute (0.1 sleep duration *600 count seconds),
                    # then send cancel execution, and assume failure
                    athena_client.stop_query_execution(
                        QueryExecutionId=query_execution_id)
                    return {
                        "status": "CANCELLED",
                        "data": f"Table analysis query exceeded timeout of {QUERY_TIMEOUT}s"
                    }

    except Exception as e:
        logging.exception(f"Analysis query failed.", exc_info=True)
        return {
            "status": "FAILED",
            "data": f"Analysis query failed. {e}",
        }


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
                if count > QUERY_TIMEOUT * 10:
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


def determine_wait_time(s3_client, bucket_name, key):
    """
    gets some assumed time for automation to wait for athena to finish indexing depending on content in s3 buckets.

    :param s3_client: boto3 client for s3.
    :type s3_client: S3.Client
    :param bucket_name: The name of the s3 bucket.
    :type bucket_name: str
    :param key: The key of objects that contain logs.
    :type key: str

    :return: number of seconds
    :rtype: int
    """
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=key)
        bucket_content_list_length = len(response.get("Contents", []))
        logging.debug("found total %s files", bucket_content_list_length)
        return math.ceil(bucket_content_list_length * 0.001)
    except Exception as ex:
        logging.exception(
            f"Failed to cleanup generated files from bucket {bucket_name}",
            exc_info=True,
        )
        return 0


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


def check_public_access_logs(session, bucket_name, action_params, account_id):
    """
    this automation finds instances of access to s3 buckets by public IPs by using athena to read and analyze s3 bucket access logs.
    this automation finds the target s3 bucket and prefix for the athena to read the logs from.

    :param session: boto3 session.
    :type s3_client: boto3.session
    :param bucket_name: The name of the s3 bucket.
    :type bucket_name: str
    :param action_params: dictionary that specifies following:
        :param database: athena database name. Default is TamnoonAnalysis.
        :type database: str
        :param table-name-prefix: prefix to the name of table to create. Default is TamnoonAnalysis.
        :type table-name-prefix: str
        :type include_rejected: bool
        :param include_3xx: if set to true, then logs will be filtered by httpstatus between 200 and 399. If set to false, logs will be filtered by httpstatus between 200 and 299. Default value is false.
        :type include_3xx: bool

        Note: include-rejected and include-3xx are mutually exclusive. 
        You can set only one of them to be true at a time. If both are set to true, include-3xx will be ignored. 
        If both include-rejected and include-3xx are false, then only filter by 2xx http status.
        If include-rejected is true, then regardless of include-3xx, all http status will be included in output.
        If only include-3xx is true, then output may have either 2xx or 3xx status logs.

    :type key: str
    :param account_id: aws account ID.
    :type account_id: str

    :return: True for success and False for failure.
    :rtype: bool
    """
    include_rejected = 'include-rejected' in action_params and action_params['include-rejected']
    include_3xx = 'include-3xx' in action_params and action_params['include-3xx']
    database_name = action_params["database"] if "database" in action_params and action_params["database"] else "TamnoonAnalysis"
    table_name_prefix = action_params["table-name-prefix"] if "table-name-prefix" in action_params and action_params["table-name-prefix"] else "TamnoonAnalysis"
    table_name = replace_non_alphanumeric_with_underscore(
        table_name_prefix + "_" + bucket_name)
    cleanup = "cleanup" in action_params and action_params["cleanup"]

    # initialize result
    result = {"status": None, "data": None,
              "cleanup": {"athena": False, "s3": False}}

    # Initialize AWS clients
    athena_client = session.client("athena")
    s3_client = session.client("s3")
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        if "LoggingEnabled" in response:
            target_bucket = response["LoggingEnabled"]["TargetBucket"]
            target_prefix = response["LoggingEnabled"]["TargetPrefix"]
            s3_location_input = f"s3://{target_bucket}/{target_prefix}"
            s3_location_output = f"s3://{target_bucket}/athena_{target_prefix}"
            if not s3_location_output.endswith("/"):
                s3_location_output = s3_location_output + "/"
            logging.info(
                f"s3 server access logs of bucket {bucket_name} are stored at {s3_location_input}"
            )

            wait_time = determine_wait_time(
                s3_client, target_bucket, target_prefix)
            create_database_result = create_database(
                athena_client, s3_location_output, database_name
            )
            if create_database_result["status"] == "SUCCEEDED":
                s3_output_template = s3_location_output + \
                    f'{account_id}/{session.region_name}/{bucket_name}/' + \
                    '${timestamp}/'
                create_athena_table_result = create_athena_table(
                    athena_client,
                    database_name,
                    table_name,
                    s3_location_input,
                    s3_location_output,
                    s3_output_template=s3_output_template
                )
                if create_athena_table_result["status"] == "SUCCEEDED":
                    # wait a little bit between creating a table and finding data
                    logging.info(
                        f"waiting {wait_time}s to let athena index the data...")
                    time.sleep(wait_time + 1)
                    analysis_result = analyze_s3_access_logs(
                        athena_client,
                        database_name,
                        table_name,
                        s3_location_output,
                        include_rejected,
                        include_3xx
                    )
                    result["status"] = analysis_result["status"]
                    result["data"] = analysis_result["data"]
                else:
                    result["status"] = create_athena_table_result["status"]
                    result["data"] = create_athena_table_result["data"]

                if cleanup:
                    logging.info(
                        '"cleanup" is set in action params. Starting cleanup of generated table and s3 bucket files...'
                    )
                    result["cleanup"]["athena"] = drop_table(
                        athena_client,
                        database_name,
                        table_name,
                        s3_location_output,
                    )
                    result["cleanup"]["s3"] = delete_from_bucket(
                        s3_client, target_bucket, f"athena_{target_prefix}"
                    )
                    logging.info("Cleanup finished")
            else:
                result["status"] = create_database_result["status"]
                result["data"] = create_database_result["data"]
        else:
            result["status"] = "FAILED"
            result["data"] = [
                f"server access logging is not enabled in bucket {bucket_name}"
            ]
    except Exception as ex:
        result["status"] = "FAILED"
        result["data"] = [f"Something went wrong. {str(ex)}"]
    return result
