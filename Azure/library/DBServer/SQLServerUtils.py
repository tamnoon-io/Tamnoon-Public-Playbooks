import time


def close_client(client):
    if client != None:
        client.close()


def get_servers(client, resource_group_name):
    # Return the list of SQL servers
    return list(client.servers.list_by_resource_group(resource_group_name))


def get_server(client, resource_group_name, server_name):
    # Return the SQL server
    return client.servers.get(resource_group_name, server_name)


def is_public_network_access_enabled(server):
    return server.public_network_access == "Enabled"


def disable_public_network_access(
    client,
    resource_group_name,
    server_name,
):
    return client.servers.begin_update(
        resource_group_name,
        server_name,
        parameters=dict({"public_network_access": "Disabled"}),
    ).result()


def enable_public_network_access(
    client,
    resource_group_name,
    server_name,
):
    return client.servers.begin_update(
        resource_group_name,
        server_name,
        parameters=dict({"public_network_access": "Enabled"}),
    ).result()


def get_firewall_rules(client, resource_group_name, server_name):
    return list(client.firewall_rules.list_by_server(resource_group_name, server_name))


def remove_firewall_rule(client, resource_group_name, server_name, firewall_rule_name):
    client.firewall_rules.delete(resource_group_name, server_name, firewall_rule_name)


def get_vnet_firewall_rules(client, resource_group_name, server_name):
    return client.virtual_network_rules.list_by_server(resource_group_name, server_name)


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
        try:
            remove_firewall_rule(
                client, resource_group_name, server_name, firewall_rule_name
            )
            print("Delete old firewall name succeeded!")
        except Exception as ex:
            raise Exception(f"Delete old firewall name failed becuase {str(ex)}")

    parameters = FirewallRule(
        start_ip_address=new_start_ip_address,
        end_ip_address=new_end_ip_address,
        name=new_firewall_rule_name,
    )

    try:
        result = client.firewall_rules.create_or_update(
            resource_group_name,
            server_name,
            new_firewall_rule_name,
            parameters,
        )
        print("Update firewall rule succeeded!")
        return result
    except Exception as ex:
        raise Exception(f"Update firewall rule failed becuase {str(ex)}")


def update_vnet_firewall_rules(
    client, resource_group_name, server_name, vnet_subnet_id
):
    vnet_name = vnet_subnet_id.split("/")[8]
    subnet_name = vnet_subnet_id.split("/")[10]
    vnet_rule_name = f"{vnet_name} {subnet_name} rule {time.time()}"

    parameters = {
        "virtual_network_subnet_id": vnet_subnet_id,
        "ignore_missing_vnet_service_endpoint": False,
        # ignore_missing_vnet_service_endpoint False means subnet's serviceEndpoint will be enabled if it already is not
    }

    return client.virtual_network_rules.begin_create_or_update(
        resource_group_name, server_name, vnet_rule_name, parameters
    )


def is_audit_enabled(auditing_policy):
    return auditing_policy.state == "Enabled"


def is_devops_audit_enabled(client, resource_group_name, server_name):
    return get_auditing_policy(
        client, resource_group_name, server_name
    ).is_devops_audit_enabled


def get_auditing_policy(client, resource_group_name, server_name):
    return client.server_blob_auditing_policies.get(
        resource_group_name=resource_group_name, server_name=server_name
    )


def setup_auditing_with_log_analytics_workspace(
    credential,
    client,
    subscription_id,
    resource_group_name,
    server_name,
    log_analytics_workspace_name,
):
    from azure.mgmt.sql.models import ServerBlobAuditingPolicy
    from azure.mgmt.monitor.models import LogAnalyticsDestination
    from ..LogAnalyticsWorkspace import get_logs_analytics_workspace

    laws = get_logs_analytics_workspace(
        credential, subscription_id, log_analytics_workspace_name
    )

    destination = LogAnalyticsDestination(workspace_id=laws.id)

    policy = ServerBlobAuditingPolicy(
        retention_days=90,
        state="Enabled",
        is_azure_monitor_target_enabled=True,
        # use_server_default=False,
        # storageEndpoint="",
        # storage_account_subscription_id="00000000-0000-0000-0000-000000000000",
        destination_type="LogAnalytics",
        destination_details=destination,
        audit_actions_and_groups=[
            "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
            "FAILED_DATABASE_AUTHENTICATION_GROUP",
            "BATCH_COMPLETED_GROUP",
        ],
    )

    response = client.server_blob_auditing_policies.begin_create_or_update(
        resource_group_name=resource_group_name,
        server_name=server_name,
        parameters=policy,
    )

    return response.result()


def setup_auditing_with_storage_account(
    client,
    resource_group_name,
    server_name,
    storage_account_subscription_id,
    storage_account_name,
    access_key,
):
    from azure.mgmt.sql.models import ServerBlobAuditingPolicy

    policy = None
    if access_key != None:
        policy = ServerBlobAuditingPolicy(
            retention_days=90,
            state="Enabled",
            audit_actions_and_groups=[
                "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                "FAILED_DATABASE_AUTHENTICATION_GROUP",
                "BATCH_COMPLETED_GROUP",
            ],
            storage_account_subscription_id=storage_account_subscription_id,
            storage_endpoint=f"https://{storage_account_name}.blob.core.windows.net/",
            is_storage_secondary_key_in_use=True,
            storage_account_access_key=access_key,
        )
    else:
        policy = ServerBlobAuditingPolicy(
            retention_days=90,
            state="Enabled",
            audit_actions_and_groups=[
                "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                "FAILED_DATABASE_AUTHENTICATION_GROUP",
                "BATCH_COMPLETED_GROUP",
            ],
            storage_account_subscription_id=storage_account_subscription_id,
            storage_endpoint=f"https://{storage_account_name}.blob.core.windows.net/",
        )

    response = client.server_blob_auditing_policies.begin_create_or_update(
        resource_group_name=resource_group_name,
        server_name=server_name,
        parameters=policy,
    )

    return response.result()


def setup_auditing_using_policy(
    client, resource_group_name, server_name, policy, access_key
):
    is_enabled = policy["state"] == "Enabled"
    is_storage_account = is_enabled and (
        policy["storage_account_subscription_id"] != None
        and policy["storage_account_subscription_id"]
        != "00000000-0000-0000-0000-000000000000"
    )
    is_access_key = access_key != None
    if is_storage_account:
        if is_access_key:
            # access key auth
            policy["storage_account_access_key"] = access_key
            response = client.server_blob_auditing_policies.begin_create_or_update(
                resource_group_name=resource_group_name,
                server_name=server_name,
                parameters=policy,
            )
            return response.result()
        else:
            # default auth
            if (
                "storage_account_access_key" in policy
                and policy["storage_account_access_key"] != None
            ):
                policy["storage_account_access_key"] = None
                response = client.server_blob_auditing_policies.begin_create_or_update(
                    resource_group_name=resource_group_name,
                    server_name=server_name,
                    parameters=policy,
                )
            return response.result()
    else:
        response = client.server_blob_auditing_policies.begin_create_or_update(
            resource_group_name=resource_group_name,
            server_name=server_name,
            parameters=policy,
        )
        return response.result()
