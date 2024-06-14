import logging


def close_client(client):
    if client != None:
        client.close()


def get_servers(client, resource_group_name):
    # Return the list of MySQL Flexible servers
    return list(client.servers.list_by_resource_group(resource_group_name))


def get_server(client, resource_group_name, server_name):
    # Return the MySQL Flexible server
    return client.servers.get(resource_group_name, server_name)


def is_public_network_access_enabled(server):
    return server.network.public_network_access == "Enabled"


def disable_public_network_access(client, resource_group_name, server_name):
    # import time

    update_operation = client.servers.begin_update(
        resource_group_name,
        server_name,
        parameters={
            "properties": {
                "network": {
                    "publicNetworkAccess": "Disabled",
                },
            },
        },
    )
    while not update_operation.done():
        update_operation.wait(3)
        logging.info("waiting for update to complete")

    update_status = update_operation.status()
    if update_status == "Succeeded":
        logging.info("Update succeeded!")
    elif update_status == "Failed":
        logging.info("Update failed!")

    result = update_operation.result()
    # logging.info(f"done {result.as_dict()}")
    return result


def enable_public_network_access(client, resource_group_name, server_name):
    # import time

    update_operation = client.servers.begin_update(
        resource_group_name,
        server_name,
        parameters={"properties": {"network": {"publicNetworkAccess": "Enabled"}}},
    )
    while not update_operation.done():
        update_operation.wait(3)
        logging.info("waiting for update to complete")

    update_status = update_operation.status()
    if update_status == "Succeeded":
        logging.info("Update succeeded!")
    elif update_status == "Failed":
        logging.info("Update failed!")

    result = update_operation.result()
    # logging.info(f"done {result.as_dict()}")
    return result


def get_firewall_rules(client, resource_group_name, server_name):
    return list(client.firewall_rules.list_by_server(resource_group_name, server_name))


def remove_firewall_rule(client, resource_group_name, server_name, firewall_rule_name):
    client.firewall_rules.begin_delete(
        resource_group_name, server_name, firewall_rule_name
    ).result()


def update_firewall_rules(
    client,
    resource_group_name,
    server_name,
    firewall_rule_name="",
    new_firewall_rule_name="",
    new_start_ip_address="",
    new_end_ip_address="",
):
    from azure.mgmt.sql.models import FirewallRule

    if new_firewall_rule_name != firewall_rule_name:
        delete_operation = client.firewall_rules.begin_delete(
            resource_group_name, server_name, firewall_rule_name
        )
        while not delete_operation.done():
            delete_operation.wait(3)
            logging.info("waiting for delete to complete")

        delete_status = delete_operation.status()
        if delete_status == "Failed":
            raise Exception(
                f"Delete old firewall name failed becuase {str(delete_operation.result)}"
            )

        if delete_status == "Succeeded":
            logging.info("Delete old firewall name succeeded!")

    parameters = FirewallRule(
        start_ip_address=new_start_ip_address,
        end_ip_address=new_end_ip_address,
        name=new_firewall_rule_name,
    )

    update_operation = client.firewall_rules.begin_create_or_update(
        resource_group_name,
        server_name,
        new_firewall_rule_name,
        parameters,
    )
    while not update_operation.done():
        update_operation.wait(3)
        logging.info("waiting for update to complete")

    update_status = update_operation.status()
    if update_status == "Failed":
        raise Exception(
            f"Update firewall rule failed becuase {str(update_operation.result)}"
        )

    if update_status == "Succeeded":
        logging.info("Update firewall rule succeeded!")

    result = update_operation.result()

    return result


def is_audit_log_enabled(state):
    return state.get("value") == "ON"


def get_audit_logs_configuration(
    mysql_client=None, resource_group_name="", server_name=""
):
    return mysql_client.configurations.get(
        resource_group_name=resource_group_name,
        server_name=server_name,
        configuration_name="audit_log_enabled",
    ).as_dict()


def set_audit_logs_configuration_value(state, enabled=False):
    new_state = state.copy()
    new_state.update({"value": "ON" if enabled else "OFF"})
    return new_state


def set_audit_logs_configuration(
    mysql_client, resource_group_name, server_name, audit_log_enabled_configuration=None
):
    response = mysql_client.configurations.begin_update(
        resource_group_name=resource_group_name,
        server_name=server_name,
        configuration_name="audit_log_enabled",
        parameters=audit_log_enabled_configuration,
    )
    return response.result().as_dict()


def get_audit_log_events_configuration(
    mysql_client=None, resource_group_name="", server_name=""
):
    return mysql_client.configurations.get(
        resource_group_name=resource_group_name,
        server_name=server_name,
        configuration_name="audit_log_events",
    ).as_dict()


def is_audit_events_has_connections(state):
    return "CONNECTION" in state.get("value") and "CONNECTION_V2" in state.get("value")


def set_audit_logs_events_configuration_value(
    state, events=["CONNECTION", "CONNECTION_V2"], enabled=False
):
    new_state = state.copy()
    audit_log_events_value = new_state.get("value")
    audit_log_events_value = audit_log_events_value.upper()
    audit_log_events_value = audit_log_events_value.split(",")
    audit_log_events_value = set(audit_log_events_value)
    if enabled:
        events.sort(reverse=False)
        for value in events:
            if value not in audit_log_events_value:
                audit_log_events_value.add(value)
    else:
        events.sort(reverse=True)
        for value in events:
            if value in audit_log_events_value:
                audit_log_events_value.remove(value)

    if len(audit_log_events_value) == 0:
        audit_log_events_value.add(new_state.get("default_value"))
    audit_log_events_value = list(audit_log_events_value)
    audit_log_events_value.sort()
    audit_log_events_value = ",".join(audit_log_events_value)
    audit_log_events_value = audit_log_events_value.upper()
    new_state.update({"value": audit_log_events_value})
    return new_state


def set_audit_log_events_configuration(
    mysql_client, resource_group_name, server_name, audit_log_events_configuration=None
):
    response = mysql_client.configurations.begin_update(
        resource_group_name=resource_group_name,
        server_name=server_name,
        configuration_name="audit_log_events",
        parameters=audit_log_events_configuration,
    )
    return response.result().as_dict()


def restart_server(mysql_client, resource_group_name, server_name):
    logging.info("Restarting MySQL Flexible Server. Please wait...")
    response = mysql_client.servers.begin_restart(
        resource_group_name=resource_group_name,
        server_name=server_name,
        parameters=dict(),
    )
    while not response.done():
        response.wait(3)
        logging.info("waiting for server to start")

    update_status = response.status()
    if update_status == "Failed":
        raise Exception(
            f"MySQL Flexible Server restart failed becuase {str(response.result)}"
        )

    if update_status == "Succeeded":
        logging.info("MySQL Flexible Server has restarted successfully.")

    return


def is_audit_enabled(diagnostic_setting):
    for setting in diagnostic_setting:
        if hasattr(setting, "logs"):
            for policy in setting.logs:
                if (
                    hasattr(policy, "category_group")
                    and policy.category_group.lower() == "audit"
                ):
                    return policy.enabled
        elif "logs" in setting:
            for policy in setting["logs"]:
                if (
                    "category_group" in policy
                    and policy["category_group"].lower() == "audit"
                ):
                    return "enabled" in policy and policy["enabled"]

    return False


def get_audit_diagnostics(monitor_client, subscription_id, server_uri):
    return list(monitor_client.diagnostic_settings.list(resource_uri=server_uri))


def setup_audit_enabled(
    monitor_client,
    subscription_id,
    server_id,
    storage_account_id,
    diagnostics_setting_name,
):
    parameters = {
        "logs": [
            {
                "category_group": "audit",
                "enabled": True,
            }
        ],
        "metrics": [
            {
                "time_grain": "PT1M",
                "category": "AllMetrics",
                "enabled": True,
            }
        ],
        "storageAccountId": storage_account_id,
    }

    return monitor_client.diagnostic_settings.create_or_update(
        name=diagnostics_setting_name,
        resource_uri=server_id,
        parameters=parameters,
        content_type="application/json",
    ).as_dict()


def remove_audit_enabled(monitor_client, server_id, diagnostics_setting_name):
    monitor_client.diagnostic_settings.delete(
        resource_uri=server_id, name=diagnostics_setting_name
    )
