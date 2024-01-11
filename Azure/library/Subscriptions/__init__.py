from azure.mgmt.subscription.models import Subscription
import logging
from ..Utils.utils import get_client


def get_subscription(credential, subscription_id) -> Subscription:
    """
    This method finds the Subscription by its id.

    credential - (Required) Azure Credential.

    subscription_id - (Required) id of Subscription.

    :return: azure.mgmt.subscription.models.Subscription
    """
    # get subscription by its subscription_id
    try:
        subscriptions_client = get_client(
            credential, client_type="subscription_management"
        )
        subscription = subscriptions_client.subscriptions.get(
            subscription_id=subscription_id
        ).as_dict()
        subscriptions_client.close()
        return subscription
    except Exception as e:
        logging.error(e)
        return None


def get_subscriptions(credential) -> [Subscription]:
    """
    This method finds the Subscription by its id.

    credential - (Required) Azure Credential.

    :return: azure.mgmt.subscription.models.Subscription
    """
    # get subscription by its subscription_id
    try:
        subscriptions_client = get_client(
            credential, client_type="subscription_management"
        )
        subscriptions = subscriptions_client.subscriptions.list()
        subscriptions_client.close()
        return subscriptions
    except Exception as e:
        logging.error(e)
        return None
