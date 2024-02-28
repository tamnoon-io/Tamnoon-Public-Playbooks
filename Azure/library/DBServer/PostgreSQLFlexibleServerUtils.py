def close_client(client):
    if client != None:
        client.close()


def get_servers(client, resource_group_name):
    # Return the list of PostgreSQL Flexible servers
    return list(client.servers.list_by_resource_group(resource_group_name))


def get_server(client, resource_group_name, server_name):
    # Return the PostgreSQL Flexible server
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
        print("waiting for update to complete")

    update_status = update_operation.status()
    if update_status == "Succeeded":
        print("Update succeeded!")
    elif update_status == "Failed":
        print("Update failed!")

    result = update_operation.result()
    # print(f"done {result.as_dict()}")
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
        print("waiting for update to complete")

    update_status = update_operation.status()
    if update_status == "Succeeded":
        print("Update succeeded!")
    elif update_status == "Failed":
        print("Update failed!")

    result = update_operation.result()
    # print(f"done {result.as_dict()}")
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
            print("waiting for delete to complete")

        delete_status = delete_operation.status()
        if delete_status == "Failed":
            raise Exception(
                f"Delete old firewall name failed becuase {str(delete_operation.result)}"
            )

        if delete_status == "Succeeded":
            print("Delete old firewall name succeeded!")

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
        print("waiting for update to complete")

    update_status = update_operation.status()
    if update_status == "Failed":
        raise Exception(
            f"Update firewall rule failed becuase {str(update_operation.result)}"
        )

    if update_status == "Succeeded":
        print("Update firewall rule succeeded!")

    result = update_operation.result()

    return result
