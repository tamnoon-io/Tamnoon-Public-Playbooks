
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - SQL Server Firewall Rules


## Description
This playbook describes how to execute Tamnoon Azure automation to restrict firewall rules of SQLServer public network access.
If the SQL server has disabled its public network access, remedy will enable the same and it will add or modify or remove the firewall rules of the server as per given action parameters.

## Playbook steps:
1. Clone the folder Azure
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/Azure
      git checkout

   ``````  
2. user can login using "az login" or else user may get redirected to azure login screen for getting authenticated once the script execution starts.
3. Get the Subscription ids, Resource Group Name, SQL server(s) name, Regions
4. Execute the automation from the Azure directory

``````
    python3 -m Automations.SQLServer \
        --type sql-server \
        --action restrict_firewall_rules \
        --dryRun \
        --subscription <comma separated list of subscription ID or all> \
        --resourceGroups <comma separated list of resource groups or all> \
        --regions <comma separated list of regions or all> \
        --assetIds <list of SQL servers or all> \
        --actionParams <dictionary with the specific action params> \

``````
### subscription - (Optional)
 list of Subscription ID. When given, remedy will find SQL servers in only specified Subscriptions. Otherwise default value is 'all', i.e., remedy will find SQL servers in all Subscriptions.
  
### resourceGroups - (Optional)
 list of Resource Group names. When given, remedy will find SQL servers in only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will find SQL servers in all Resource Groups available in the Subscription. 

### assetIds - (Optional)
 comma separated list of SQL Servers.

### regions - (Optional)
 regions of SQL Servers. When given, remedy will find SQL servers that have location same as any of the given regions. Otherwise default value is 'all', i.e., remedy will find SQL servers regardless of its location. 

### actionParams (Required)
   - for remedy
      1. action - (Required) - there are two actions,
         "disable-all" - if you want to disable public network access completely.
         "disable-by-firewall-rules" - if you want to provide firewall rules.
      2. remove-current-firewall-rules - (Required) - Boolean flag used to sign if you want to remove current firewall rules.
         When set to true with action set as "disable-by-firewall-rules", remedy will first remove current rules, and then create new rules as given in the actionParams
      3. firewall-rules - (Required if action is "disable-by-firewall-rules") - list of name, start_ip_address and end_ip_address. Here start_ip_address and end_ip_address are IP Addresses only. Using CIDR will not work.
         example, "firewall-rules": [{"name":"rule-1", "start_ip_address" : "ip_address_1", "end_ip_address" : "ip_address_2" }]
   - for rollback 
      1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
      2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.



## Prerequisites 
    Python v3.8  and above + following packages installed.    
      azure-core
      azure-identity
      azure-mgmt-resource
      azure-mgmt-network
      azure-mgmt-subscription
      azure-mgmt-sql

