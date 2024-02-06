
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Enable Logging in Storage Accounts configuration.


## Description
This playbook describes how to execute Tamnoon Azure Storage automation to enable 
logging of Blob Services in given Storage Accounts and show the logs in Log Analytics Workspace.


## Playbook steps:
1. Clone the folder Azure
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/Azure
      git checkout

   ``````  
2. user can login using "az login" or else user may get redirected to azure login screen for getting authenticated once the script execution starts.
3. Get the Subscription ids, Storage Account names, Log Analytics Workspace name, Regions
4. Execute the automation from the Azure directory

``````
    python3 -m Automations.Storage --type blob-container --action enable_log_analytics_logs_for_azure_storage_blobs  --dryRun --subscriptions <comma separated list of subscription ids or all> --resourceGroups <comma separated list of resource groups or all> --storageAccounts <comma separated list of storage accounts or all>  --regions <comma separated list of regions or all>  --actionParams <dictionary with the specific action params>
``````

### subscriptions - (Optional)
list of Subscription ids. If not given then default value is 'all', i.e., remedy will search for Storage Accounts in all the Subscriptions available in the Tenant.  

### resourceGroups - (Optional)
list of Resource Group names. When given, remedy will configure only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will search for Storage Accounts in all Resource Groups available in the Subscription. 

### storageAccounts - (Optional)
list of Storage Account names. If not given then default value is 'all', i.e., remedy will configure all the Storage Accounts available in the Resource Group.

### regions - (Optional)
list of Regions used to find Storage Accounts by location and create Log Analytics Workspace.
If not given then default value is 'all', i.e., remedy will search for Storage Accounts in all the Storage Accounts without checking its regions.
If provided, then logging is enabled in all given Storage Accounts in given Subscriptions which are found with any of the given regions. Same region is used to create Log Analytics Workspace, if required in given Subscriptions.

### actionParams for remedy:
1. log-analytics-workspace-name - (Required) - name of log analytics workspace, where 
   you want your storage account to direct its logs to
2. create-la-ws - (Optional) - Boolean flag to create workspace with
   log-analytics-workspace-name, if it is not found in given subscription

### actionParams for rollback:
1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.

   
## Prerequisites 
    Python v3.8  and above + following packages installed.    
      azure-core
      azure-identity
      azure-mgmt-monitor
      azure-mgmt-subscription
      azure-mgmt-resource
      azure-mgmt-loganalytics
      azure-storage-blob
