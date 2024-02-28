from library.Subscriptions import get_subscriptions
from library.ResourceGroups import get_resource_groups
from library.Utils.utils import get_client
from .. import SQLServerUtils
from .. import MySQLFlexibleServerUtils
from .. import PostgreSQLFlexibleServerUtils
from ..DBAction import DBAction, DBTypes


class DBActionsGenerator:
    credentials = None
    subscription_ids = ["all"]
    resource_groups = ["all"]
    regions = ["all"]
    db_server_names = ["all"]

    is_all_subscriptions = True
    is_all_resource_groups = True
    is_all_regions = True
    is_all_db_servers = True

    db_type = None

    def __init__(
        self,
        credentials,
        subscriptions=["all"],
        resource_groups=["all"],
        regions=["all"],
        db_server_names=["all"],
        db_type=DBTypes.SQL,
    ):
        self.credentials = credentials
        self.subscription_ids = subscriptions
        self.resource_groups = resource_groups
        self.regions = regions
        self.db_server_names = db_server_names
        self.db_type = db_type

        self.is_all_subscriptions = (
            subscriptions.__len__() == 1 and subscriptions[0] == "all"
        )
        self.is_all_resource_groups = (
            resource_groups.__len__() == 1 and resource_groups[0] == "all"
        )
        self.is_all_regions = regions.__len__() == 1 and regions[0] == "all"
        self.is_all_db_servers = (
            db_server_names.__len__() == 1 and db_server_names[0] == "all"
        )

    def get_db_servers(
        self,
        db_client,
        resource_group_name,
    ):
        if self.db_type == DBTypes.SQL:
            return SQLServerUtils.get_servers(
                client=db_client,
                resource_group_name=resource_group_name,
            )
        if self.db_type == DBTypes.MYSQL_FLEXIBLE:
            return MySQLFlexibleServerUtils.get_servers(
                client=db_client,
                resource_group_name=resource_group_name,
            )
        if self.db_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
            return PostgreSQLFlexibleServerUtils.get_servers(
                client=db_client,
                resource_group_name=resource_group_name,
            )
        else:
            raise TypeError(f"unknown type {self.db_type}")
        return []

    def close_db_client(self, db_client):
        if self.db_type == DBTypes.SQL:
            SQLServerUtils.close_client(db_client)
        if self.db_type == DBTypes.MYSQL_FLEXIBLE:
            MySQLFlexibleServerUtils.close_client(db_client)
        if self.db_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
            PostgreSQLFlexibleServerUtils.close_client(db_client)

    def __filter_db_servers(self, subscription_id, resource_group_name):
        db_client = None
        if self.db_type == DBTypes.SQL:
            db_client = get_client(
                self.credentials,
                "sql_server",
                dict({"subscription_id": subscription_id}),
            )
        elif self.db_type == DBTypes.MYSQL_FLEXIBLE:
            db_client = get_client(
                self.credentials,
                "mysql_flexible_server",
                dict({"subscription_id": subscription_id}),
            )
        elif self.db_type == DBTypes.POSTGRE_SQL_FLEXIBLE:
            db_client = get_client(
                self.credentials,
                "postgresql_flexible_server",
                dict({"subscription_id": subscription_id}),
            )
        else:
            raise TypeError(f"unknown type {self.db_type}")
        result = []
        for db_server in self.get_db_servers(
            db_client=db_client,
            resource_group_name=resource_group_name,
        ):
            if (
                self.is_all_db_servers
                or self.db_server_names.__contains__(db_server.name)
            ) and (
                self.is_all_regions or self.regions.__contains__(db_server.location)
            ):
                result.append(
                    DBAction(
                        subscription_id,
                        resource_group_name,
                        db_server.location,
                        db_server.name,
                        db_server,
                        db_type=self.db_type,
                    )
                )
        self.close_db_client(db_client)
        return result

    def __filter_resource_groups(self, subscription_id):
        result = []
        resource_groups_list = get_resource_groups(
            self.credentials,
            subscription_id,
            self.resource_groups,
            self.regions,
        )
        for resource_group in resource_groups_list:
            r = self.__filter_db_servers(subscription_id, resource_group.name)
            if r.__len__() > 0:
                result.extend(r)
        return result

    def __filter_subscriptions(self):
        result = []
        subscriptions_list = get_subscriptions(self.credentials)
        for subscription in subscriptions_list:
            if self.is_all_subscriptions or self.subscription_ids.__contains__(
                subscription.subscription_id
            ):
                r = self.__filter_resource_groups(subscription.subscription_id)
                if r.__len__() > 0:
                    result.extend(r)

        return result

    def generate(self):
        return self.__filter_subscriptions()


class SQLServerActionsGenerator(DBActionsGenerator):
    def __init__(
        self,
        credentials,
        subscriptions=["all"],
        resource_groups=["all"],
        regions=["all"],
        db_server_names=["all"],
    ):
        super().__init__(
            credentials=credentials,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            db_server_names=db_server_names,
            db_type=DBTypes.SQL,
        )


class MySQLFlexibleServerActionsGenerator(DBActionsGenerator):
    def __init__(
        self,
        credentials,
        subscriptions=["all"],
        resource_groups=["all"],
        regions=["all"],
        db_server_names=["all"],
    ):
        super().__init__(
            credentials=credentials,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            db_server_names=db_server_names,
            db_type=DBTypes.MYSQL_FLEXIBLE,
        )


class PostgreSQLFlexibleServerActionsGenerator(DBActionsGenerator):
    def __init__(
        self,
        credentials,
        subscriptions=["all"],
        resource_groups=["all"],
        regions=["all"],
        db_server_names=["all"],
    ):
        super().__init__(
            credentials=credentials,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            db_server_names=db_server_names,
            db_type=DBTypes.POSTGRE_SQL_FLEXIBLE,
        )
