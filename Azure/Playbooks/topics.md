

### blob-container - 	enable_log_analytics_logs_for_azure_storage_blobs
[TPlayBook_blob_storage_account_logging.md](../Playbooks/Storage/TPlayBook_blob_storage_account_logging.md)
  
**Topics** - Storage Account, Blob Containers, Log Analytics Workspace, Diagnostics

This playbook describes how to execute Tamnoon Azure Storage automation to enable logging of Blob Services in given Storage Accounts and show the logs in Log Analytics Workspace.  
### blob-container - 	remove_public_access_storage_containers
[TPlayBook_blob_container_public_access.md](../Playbooks/Storage/TPlayBook_blob_container_public_access.md)
  
**Topics** - Storage Account, Blob Containers, Anonymous Access, Public Access

This playbook describes how to execute Tamnoon Azure Storage automation to restrict public access.

|                                                        | Anonymous access level for the container is set to Private (default setting) | Anonymous access level for the container is set to Container                                                              | Anonymous access level for the container is set to Blob                                                                   |
|--------------------------------------------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| **Anonymous access is disallowed for the storage account** | No anonymous access to any container in the storage account.                 | No anonymous access to any container in the storage account. The storage account setting overrides the container setting. | No anonymous access to any container in the storage account. The storage account setting overrides the container setting. |
| **Anonymous access is allowed for the storage account**    | No anonymous access to this container (default configuration).               | Anonymous access is permitted to this container and its blobs.                                                            | Anonymous access is permitted to blobs in this container, but not to the container itself.                                |
|                                                        |                                                                              |                                                                                                                           |                                                                                                                           |

Click [here](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal) to learn more about anonymous read access levels of blob container 
  
### mysql-server - 	enable_auditing
[TPlayBook_mysql_server_auditing.md](../Playbooks/DBServer/TPlayBook_mysql_server_auditing.md)
  
**Topics** - Azure, SQL, MySQL Flexible Server, Auditing, Connection Logs, Logs, Enable Auditing

This playbook describes how to execute Tamnoon Azure automation to enable auditing of Connection Logs for MySQL Flexible Server. This automation will enable recording network connections for compliance and security monitoring.  
### mysql-server - 	restrict_firewall_rules
[TPlayBook_mysql_server_firewall.md](../Playbooks/DBServer/TPlayBook_mysql_server_firewall.md)
  
**Topics** - Azure, rdbms, MySQL Server, MySQL Flexible Server, Firewall Rules

This automation allows you to restrict firewall rules of MySQL Flexible Server public network access. If the MySQL Flexible Server has disabled its public network access, the automation will enable the same and it will add or modify or remove the firewall rules of the server as per given action parameters.  
  The top level parameters for this automation allow you to specify which MySQL Flexible Server instances you want to perform this action on, while the "Action Parameters" described below allow you to specify which firewall rules you want to remove or replace on these instances.  
### network-security-group - 	find_associations
[TImpact_nsg_associations.md](../Playbooks/Network/TImpact_nsg_associations.md)
  
**Topics** - Network Security Groups, Network Interfaces, Virtual Network, Subnet, Service Endpoints, Virtual Machines

This playbook describes how to execute Tamnoon Azure Network automation to find out what resources are associated with any Network Security Group (NSG).  
### network-security-group - 	remove_or_replace_security_rules
[TPlayBook_nsg_remove_or_replace_security_rules.md](../Playbooks/Network/TPlayBook_nsg_remove_or_replace_security_rules.md)
  
**Topics** - Network Security Groups, Security Rules, Virtual Networks

This playbook describes how to execute Tamnoon Azure Network automation to remove or replace the Security Rules of Network Security Groups.  
### postgresql-server - 	enable_auditing
[TPlayBook_postgresql_server_auditing.md](../Playbooks/DBServer/TPlayBook_postgresql_server_auditing.md)
  
**Topics** - Azure, SQL, PostgreSQL Flexible Server, Auditing, Connection Logs, Logs, Enable Auditing

This playbook describes how to execute Tamnoon Azure automation to enable auditing of Connection Logs for PostgreSQL Flexible Server. This automation will enable recording network connections for compliance and security monitoring.  
### postgresql-server - 	restrict_firewall_rules
[TPlayBook_postgresql_server_firewall.md](../Playbooks/DBServer/TPlayBook_postgresql_server_firewall.md)
  
**Topics** - Azure, rdbms, PostgreSQL Server, PostgreSQL Flexible Server, Firewall Rules

This automation allows you to restrict firewall rules of PostgreSQL Flexible Server public network access. If the PostgreSQL Flexible Server has disabled its public network access, the automation will enable the same and it will add or modify or remove the firewall rules of the server as per given action parameters.  
  The top level parameters for this automation allow you to specify which PostgreSQL Flexible Server instances you want to perform this action on, while the "Action Parameters" described below allow you to specify which firewall rules you want to remove or replace on these instances.  
### sql-server - 	enable_auditing
[TPlayBook_sql_server_auditing.md](../Playbooks/DBServer/TPlayBook_sql_server_auditing.md)
  
**Topics** - Azure, SQL, SQL Server, Auditing, Enable Auditing

This playbook describes how to execute Tamnoon Azure automation to enable auditing of SQL Server. This automation will also set auditing settings for storing audit logs in storage account given as actionParams  
### sql-server - 	restrict_firewall_rules
[TPlayBook_sql_server_firewall.md](../Playbooks/DBServer/TPlayBook_sql_server_firewall.md)
  
**Topics** - Azure, SQL, SQL Server, Firewall Rules

This automation allows you to restrict firewall rules of PostgreSQL Flexible Server public network access. If the SQL Server has disabled its public network access, the automation will enable the same and it will add or modify or remove the firewall rules of the server as per given action parameters.  
  The top level parameters for this automation allow you to specify which SQL Server instances you want to perform this action on, while the "Action Parameters" described below allow you to specify which firewall rules you want to remove or replace on these instances.  
### storage-account - 	remove_public_network_access
[TPlayBook_storage_account_restrict_network_access.md](../Playbooks/Storage/TPlayBook_storage_account_restrict_network_access.md)
  
**Topics** - Storage Account, Blob Containers, Anonymous Network Access, Virtual Networks, IP addresses, CIDR

This playbook describes how to execute Tamnoon Azure Storage automation to restrict network access to the storage accounts.  
