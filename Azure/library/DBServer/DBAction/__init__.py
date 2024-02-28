import logging

from enum import Enum


class DBTypes(Enum):
    SQL = "sql"
    MYSQL_FLEXIBLE = "mysql_flexible"
    POSTGRE_SQL_FLEXIBLE = "postgre_sql_flexible"

    def pretty_str(self):
        value = []
        for s in self.value.split("_"):
            value.append(s.capitalize())
        return " ".join(value)


class DBAction:
    data = None
    db_server = None

    def __init__(
        self,
        subscription_id,
        resource_group_name,
        regions,
        db_server_name,
        db_server,
        db_type=DBTypes.SQL,
    ):
        self.db_type = db_type
        self.data = dict(
            {
                "subscription_id": subscription_id,
                "resource_group_name": resource_group_name,
                "regions": regions,
                f"{self.db_type}_server_name": db_server_name,
            }
        )
        self.db_server = db_server

    def print(self):
        logging.info(self.data)
