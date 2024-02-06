import logging


class SQLServerAction:
    data = None
    sql_server = None

    def __init__(
        self, subscription_id, resource_group_name, regions, sql_server_name, sql_server
    ):
        self.data = dict(
            {
                "subscription_id": subscription_id,
                "resource_group_name": resource_group_name,
                "regions": regions,
                "sql_server_name": sql_server_name,
            }
        )
        self.sql_server = sql_server

    def print(self):
        logging.info(self.data)
