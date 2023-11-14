
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Enable Logging in Storage Accounts configuration.


## Description
This playbook describes how to execute Tamnoon Azure Storage automation to enable 
logging of Blob Services in given Storage Accounts and show the logs in Log Analytics Workspace.


## Playbook steps:
1. Clone the folder Azure
2. Get the Subscription ids, Storage Account names, Log Analytics
Workspace name, Regions
3. Execute the automation from the Azure directory

``````
    python3 -m Automations.BlobStorage.Storage \
        --type blob-container \
        --action enable-log-analytics-logs-for-azure-storage-blobs \
        --dryRun \
        --assetIds <list of storage accounts to remediate> \
        --actionParams <dictionary with the specific action params> \
        --regions <list of regions>
``````

    actionParams for enabling logging:
    1. subscriptions - (Required) - comma separated list of subscription ids.
    2. log-analytics-workspace-name - (Required) - name of log analytics workspace, where 
       you want your storage account to direct its logs to
    3. create-la-ws - (Optional) - Boolean flag to create workspace with
       log-analytics-workspace-name, if it is not found in given subscription

    actionParams for rollback:
    1. rollBack - (Optional) - Boolean flag to sign if this is a rollback call (required the
       existing of state file)
    2. lastExecutionResultPath (Optional) - The path for the last execution that we want to 
       roll-back from - if roll-back provided this parameter become mandatory

    assetIds - (Required) - comma separated list of storage accounts.

    regions - (Optional) - used to find Storage Accounts by location and create Log Analytics
        Workspace.
            If provided, then logging is enabled in all given Storage Accounts in given 
        Subscriptions which are found with any of the given regions. Same region is used to
        create Log Analytics Workspace, if required
        in given Subscriptions

## Prerequisites 
    Python v3.8  and above + following packages installed.    
      azure-core
      azure-identity
      azure-mgmt-monitor
      azure-mgmt-subscription
      azure-mgmt-resource
      azure-mgmt-loganalytics
      azure-storage-blob
