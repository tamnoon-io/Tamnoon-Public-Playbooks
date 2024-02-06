from library.Subscriptions import get_subscriptions
from library.ResourceGroups import get_resource_groups
from library.Utils.utils import get_client
from .. import get_sql_servers, close_sql_client
from ..SQLServerAction import SQLServerAction


class SQLServerActionsGenerator:
    credentials = None
    subscription_ids = ["all"]
    resource_groups = ["all"]
    regions = ["all"]
    sql_server_names = ["all"]

    is_all_subscriptions = True
    is_all_resource_groups = True
    is_all_regions = True
    is_all_sql_servers = True

    def __init__(
        self,
        credentials,
        subscriptions=["all"],
        resource_groups=["all"],
        regions=["all"],
        sql_server_names=["all"],
    ):
        self.credentials = credentials
        self.subscription_ids = subscriptions
        self.resource_groups = resource_groups
        self.regions = regions
        self.sql_server_names = sql_server_names

        self.is_all_subscriptions = (
            subscriptions.__len__() == 1 and subscriptions[0] == "all"
        )
        self.is_all_resource_groups = (
            resource_groups.__len__() == 1 and resource_groups[0] == "all"
        )
        self.is_all_regions = regions.__len__() == 1 and regions[0] == "all"
        self.is_all_sql_servers = (
            sql_server_names.__len__() == 1 and sql_server_names[0] == "all"
        )

    def __filter_sql_servers(self, subscription_id, resource_group_name):
        sql_client = get_client(
            self.credentials, "sql_server", dict({"subscription_id": subscription_id})
        )
        result = []
        for sql_server in get_sql_servers(
            sql_client=sql_client,
            resource_group_name=resource_group_name,
        ):
            if (
                self.is_all_sql_servers
                or self.sql_server_names.__contains__(sql_server.name)
            ) and (
                self.is_all_regions or self.regions.__contains__(sql_server.location)
            ):
                result.append(
                    SQLServerAction(
                        subscription_id,
                        resource_group_name,
                        sql_server.location,
                        sql_server.name,
                        sql_server,
                    )
                )
        close_sql_client(sql_client)
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
            r = self.__filter_sql_servers(subscription_id, resource_group.name)
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
