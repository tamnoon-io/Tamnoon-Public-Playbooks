
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Enable SQL Server Auditing


## Description
This playbook describes how to execute Tamnoon Azure automation to enable auditing of SQL Server.
remedy will also set auditing settings for storing audit logs in storage account given as actionParams

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
    python3 -m Automations.DBServer \
        --type sql-server \
        --action enable_auditing \
        --dryRun \
        --subscription <comma separated list of subscription ID or all> \
        --resourceGroups <comma separated list of resource groups or all> \
        --regions <comma separated list of regions or all> \
        --assetIds <list of SQL servers or all> \
        --actionParams <dictionary with the specific action params> \

``````
### subscription (Optional)
 list of Subscription ID. When given, remedy will find SQL servers in only specified Subscriptions. Otherwise default value is 'all', i.e., remedy will find SQL servers in all Subscriptions.
  
### resourceGroups (Optional)
 list of Resource Group names. When given, remedy will find SQL servers in only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will find SQL servers in all Resource Groups available in the Subscription. 

### assetIds (Required)
 comma separated list of SQL Servers.

### regions (Optional)
 regions of SQL Servers. When given, remedy will find SQL servers that have location same as any of the given regions. Otherwise default value is 'all', i.e., remedy will find SQL servers regardless of its location. 

### actionParams (Required)
   -  for remedy
      1. storage-account-name - (Required) - name of Storage Account to same logs into  
      2. resource-group-name - (Required) - name of Resource Group of storage account  
      3. subscription-id - (Required) - Subscription ID of storage account  
      4. storage-auth-method - (Optional) - has two values. When ommitted from actionParams, default value used is "default"  
         access_key - uses Access Key of storage account as means of authenticating for storing audit logs  
         default - uses Entra ID of managed identity of SQL Server as means of authenticating for storing audit logs. For this method, few conditions should be met.
            1. SQL Server needs to have a [Managed Identity](https://learn.microsoft.com/en-gb/entra/identity/managed-identities-azure-resources/overview). 
            2. Storage Account's IAM access control must have given a role "Storage Blob Data Contributor" or a role with similar permissions to the managed identity of SQL Server.  
   - for rollback 
      1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
      2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.



## Prerequisites 
    Python v3.8  and above + following packages installed.    
      azure-core
      azure-identity
      azure-mgmt-subscription
      azure-mgmt-resource
      azure-mgmt-sql
      azure-mgmt-storage

