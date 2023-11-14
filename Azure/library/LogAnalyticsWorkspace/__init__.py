from azure.mgmt.loganalytics.models import Workspace
import logging
from ..Utils.utils import get_client


def get_logs_analytics_workspace(
    credential, subscription_id, log_analytics_workspace_name, location=None
) -> Workspace:
    """
    This method finds Log Analytics Workspace with given name in given Subscritpion id.
    if not found, then it returns None

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription to find workspace in it.

    log_analytics_workspace_name -(Required) name of Log Analytics Workspace to find.

    location - (Optional) location of Log Analytics Workspace.

    :return: azure.mgmt.loganalytics.models.Workspace
    """
    try:
        log_analytics_mgmt_client = get_client(
            credential,
            "log_analytics_management",
            dict({"subscription_id": subscription_id}),
        )
        workspace_found = None
        workspaces = log_analytics_mgmt_client.workspaces.list()
        workspace_size = 0
        for workspace in workspaces:
            workspace_size += 1
            if log_analytics_workspace_name == workspace.as_dict()["name"] and (
                location == None or location == workspace.as_dict()["location"]
            ):
                workspace_found = workspace
                break
        logging.debug(
            f"log analytics workspace {'found' if workspace != None else 'not found'} out of {workspace_size} workspaces"
        )
        log_analytics_mgmt_client.close()
        return workspace_found
    except Exception as ex:
        logging.exception(ex)
    return None
