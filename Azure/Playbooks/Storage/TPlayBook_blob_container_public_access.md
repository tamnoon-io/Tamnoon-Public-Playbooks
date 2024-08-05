
[comment]: <> (This is a readonly file, do not edit directly, to change update the blob_container_remove_public_access_storage_containers.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure - Remove Blob Container public access configuration.
## Description

This playbook describes how to execute Tamnoon Azure Storage automation to restrict public access.

|                                                        | Anonymous access level for the container is set to Private (default setting) | Anonymous access level for the container is set to Container                                                              | Anonymous access level for the container is set to Blob                                                                   |
|--------------------------------------------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| **Anonymous access is disallowed for the storage account** | No anonymous access to any container in the storage account.                 | No anonymous access to any container in the storage account. The storage account setting overrides the container setting. | No anonymous access to any container in the storage account. The storage account setting overrides the container setting. |
| **Anonymous access is allowed for the storage account**    | No anonymous access to this container (default configuration).               | Anonymous access is permitted to this container and its blobs.                                                            | Anonymous access is permitted to blobs in this container, but not to the container itself.                                |
|                                                        |                                                                              |                                                                                                                           |                                                                                                                           |

Click [here](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal) to learn more about anonymous read access levels of blob container 
  
## Prerequisites
1. Python v3.10  and above + following packages installed.

	azure-core  
	  azure-identity  
	  azure-mgmt-monitor  
	  azure-mgmt-subscription  
	  azure-mgmt-resource  
	  azure-storage-blob  

2. The user must have an Azure role assigned that includes the Azure RBAC action [Microsoft.Storage/storageAccounts/listkeys/action](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-data-operations-portal). Because [get and set acl operation are not supported with default credential](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#permissions-for-blob-service-operations), we need to use BlobServiceClient with accessKey for Shared Key Authentication.  
    For example IAM role Storage Account Contributor supports Microsoft.Storage/storageAccounts/listkeys/action.  
## Playbook Steps: 


1. Clone the Repository
	``````
	git clone --branch main --single-branch https://github.com/tamnoon-io/Tamnoon-Public-Playbooks.git
	``````

2. Move to Azure Folder
	``````
	cd TamnoonPlaybooks/Azure
	``````

3. User can login using "az login" or else user may get redirected to azure login screen for getting authenticated once the script execution starts.

4. Get The Subscription Ids for the specific storage account you want to remediate

5. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````
		python3 -m Automations.Storage \
		blob-container \
		remove_public_access_storage_containers \
		--subscriptions subscription-id \
		--resourceGroups sample-resource-group \
		--storageAccounts samplestorageaccount \
		--regions eastus \
		--assetIds blobcontainer \
		--actionParams '{"anonymous-access-level": "container"}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		subscriptions:
		  - subscription-id
		resourceGroups:
		  - sample-resource-group
		storageAccounts:
		  - samplestorageaccount
		regions:
		  - eastus
		assetIds:
		  - blobcontainer
		actionParams:
		  anonymous-access-level: blob
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.Storage \
		blob-container \
		remove_public_access_storage_containers \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		"subscriptions": ["subscription-id"],
		"resourceGroups": ["sample-resource-group"],
		"storageAccounts": ["samplestorageaccount"],
		"regions": ["eastus"],
		"assetIds": ["blobcontainer"],
		"actionParams": {"anonymous-access-level": "blob"}
		}
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.Storage \
		blob-container \
		remove_public_access_storage_containers \
		--file path-to-json-file
		``````
### subscriptions - (Optional)
list of Subscription ids. If not given then default value is 'all', i.e., remedy will search for Blob Containers in all the Subscriptions available in the Tenant.
### resourceGroups - (Optional)
list of Resource Group names. When given, remedy will configure only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will search for Blob Containers in all Resource Groups available in the Subscription.
### storageAccounts - (Optional)
list of Storage Account names. If not given then default value is 'all', i.e., remedy will search for Blob Containers in all the Storage Accounts available in the Resource Group.
### regions - (Optional)
list of Regions. If not given then default value is 'all', i.e., remedy will search for Blob Containers in all the Storage Accounts without checking its regions.
### assetIds - (Optional)
list of Blob Container names. If not given then default value is 'all', i.e., remedy will configure all the Blob Containers available in the Storage Account.
### actionParams
For Remedy:
 1. anonymous-access-level - (Required) - access level of blob containers will be set to this value.
    User can provide either "container" or "blob" or "none", where "none" access level means Private.
2. exclude-storage-containers - (Optional) - list of Blob Container names in Storage Accounts. When
    given, remedy will configure all the Blob Containers available in the Storage Account except 
    those provided with this option.
    Please note that to exclude a Blob Container, it should be mentioned with its
    storage account name, separated by dot. 
    Example, "storage_account_1.blob_container_1" 

For Rollback:
1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.

