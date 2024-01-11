
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Remove Blob Container public access configuration.

## Description
This playbook describes how to execute Tamnoon Azure Storage automation to restrict public access.

## Playbook steps:
1. Clone the folder Azure
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/Azure
      git checkout

   ``````  
2. user can login using "az login" or else user may get redirected to azure login screen for getting authenticated once the script execution starts.
3. Get The Subscription Ids for the specific storage account you want to remediate
4. Execute the automation from the /Azure directory

```sh
    python3.9 -m Automations.Storage.Storage --type blob-container --action remove-public-access-storage-containers --actionParams <dictionary with the specific action params> --dryRun
```



### actionParams for remedy:
1. anonymous-access-level - (Required) - access level of blob containers will be set to this value.
User can provide either "container" or "blob" or "none", where "none" access level means Private.
2. subscriptions - (Optional) - list of Subscription ids. If not given, remedy will configure all 
the Subscriptions available in the Tenant
3. resource-groups - (Optional) - list of Resource Group names. When given, remedy will configure
only specified Resource Groups, otherwise available in the Subscription.
4. storage-accounts - (Optional) - list of Storage Account names. If not given, remedy will configure
all the Subscriptions available in the Resource Group.
5. blob-containers - (Optional) - list of Blob Container names. If not given, remedy will configure 
all the Blob Containers available in the Storage Account.
6. exclude-storage-containers - (Optional) - list of Blob Container names in Storage Accounts. When
given, remedy will configure all the Blob Containers available in the Storage Account except 
those provided with this option.
Please note that to exclude a Blob Container, it should be mentioned with its
storage account name, separated by dot. 
Example, "storage_account_1.blob_container_1"

### actionParams for rollback
1. rollBack - (Optional) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Optional) - The path for the last execution that we want to roll-back from - if roll-back provided this parameter become mandatory


## Prerequisites 
1. The user must have an Azure role assigned that includes the Azure RBAC action [Microsoft.Storage/storageAccounts/listkeys/action](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal). Because [get and set acl operation are not supported with default credential](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#permissions-for-blob-service-operations), we need to use BlobServiceClient with accessKey for Shared Key Authentication.  
    For example IAM role Storage Account Contributor supports Microsoft.Storage/storageAccounts/listkeys/action.   
2. Python v3.9  and above + following packages installed.  
      azure-core  
      azure-identity  
      azure-mgmt-monitor  
      azure-mgmt-subscription  
      azure-mgmt-resource  
      azure-storage-blob  
