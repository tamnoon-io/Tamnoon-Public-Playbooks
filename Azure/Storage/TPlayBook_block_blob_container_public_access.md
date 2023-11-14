
<img src="../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Remove Blob Container public access configuration.

## Description
This playbook describes how to execute Tamnoon Azure Storage automation to block public access.

The execution is based on Azure credentials configuration - Shared Key: https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key

Need to provide to the script:
1. Storage account name
2. Shared storage account key


After authentication via Azure API, the script execution will run on the same Azure storage account of those credentials defined (above)

## Playbook steps:
1. Clone the folder Azure/Automation/BlobStorage
2. Get The shared account for the specific storage account you want to remediate
3. Execute the automation from the /Azure directory


    python3 -m Automations.BlobStorage.Storage  --type blob-container --action remove-public  --assetIds <list of blob containers to remediate> --authParams <Dictionary with auth parameters> --actionParams <dictionary with the specific action params> --dryRun 
    
authParams:
1. StorageAccountName - (Required) - The storage account name to work on.
2. accessKey (Required) - The shared access key of the storage account.

actionParmas:
1. rollBack - (Optional) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Optional) - The path for the last execution that we want to roll-back from - if roll-back provided this parameter become mandatory


## Prerequisites 
1. Azure Credentials - Shared key
2. Python v3.8  and above + azure-identity, azure-storage-blob packages installed.


