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


cli_type_mapping = {
    "sql-server": DBTypes.SQL,
    "mysql-server": DBTypes.MYSQL_FLEXIBLE,
    "postgresql-server": DBTypes.POSTGRE_SQL_FLEXIBLE,
}

inverse_cli_type_mapping = {
    DBTypes.SQL: "sql-server",
    DBTypes.MYSQL_FLEXIBLE: "mysql-server",
    DBTypes.POSTGRE_SQL_FLEXIBLE: "postgresql-server",
}


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
                f"{self.db_type.value}_server_name": db_server_name,
            }
        )
        self.db_server = db_server

    def print(self):
        logging.info(self.data)
