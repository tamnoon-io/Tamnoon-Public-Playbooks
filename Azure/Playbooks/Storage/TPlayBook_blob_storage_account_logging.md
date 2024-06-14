
[comment]: <> (This is a readonly file, do not edit directly, to change update the blob_container_enable_log_analytics_logs_for_azure_storage_blobs.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure  - Enable Logging in Storage Accounts configuration.
## Description

This playbook describes how to execute Tamnoon Azure Storage automation to enable logging of Blob Services in given Storage Accounts and show the logs in Log Analytics Workspace.  
## Prerequisites
1. Python v3.9  and above + following packages installed.

	azure-core  
	  azure-identity  
	  azure-mgmt-monitor  
	  azure-mgmt-subscription  
	  azure-mgmt-resource  
	  azure-mgmt-loganalytics  
	  azure-storage-blob  
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

4. Get the Subscription ids, Storage Account names, Log Analytics Workspace name, Regions

5. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````sh
		python3 -m Automations.Storage \
		blob-container \
		enable_log_analytics_logs_for_azure_storage_blobs  \
		--subscriptions subscription-id \
		--resourceGroups sample-resource-group \
		--storageAccounts samplestorageaccount \
		--regions eastus \
		--actionParams '{"log-analytics-workspace-name": "log-analytics-workspace-1", "create-la-ws" : true}'
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
		actionParams:
		  log-analytics-workspace-name: "log-analytics-workspace-1"
		  create-la-ws: true
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.Storage \
		blob-container \
		enable_log_analytics_logs_for_azure_storage_blobs \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "subscriptions": [
		    "subscription-id"
		  ],
		  "resourceGroups": [
		    "sample-resource-group"
		  ],
		  "storageAccounts": [
		    "samplestorageaccount"
		  ],
		  "regions": [
		    "eastus"
		  ],
		  "actionParams": {
		    "log-analytics-workspace-name": "log-analytics-workspace-1",
		    "create-la-ws": true
		  }
		}
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.Storage \
		blob-container \
		enable_log_analytics_logs_for_azure_storage_blobs \
		--file path-to-json-file
		``````
### subscriptions - (Optional)
list of Subscription ids. If not given then default value is 'all', i.e., remedy will search for Storage Accounts in all the Subscriptions available in the Tenant.
### resourceGroups - (Optional)
list of Resource Group names. When given, remedy will configure only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will search for Storage Accounts in all Resource Groups available in the Subscription.
### storageAccounts - (Optional)
list of Storage Account names. If not given then default value is 'all', i.e., remedy will configure all the Storage Accounts available in the Resource Group.
### regions - (Optional)
list of Regions used to find Storage Accounts by location and create Log Analytics Workspace. If not given then default value is 'all', i.e., remedy will search for Storage Accounts in all the Storage Accounts without checking its regions. If provided, then logging is enabled in all given Storage Accounts in given Subscriptions which are found with any of the given regions. Same region is used to create Log Analytics Workspace, if required in given Subscriptions.
### actionParams
For remedy:
1. log-analytics-workspace-name - (Required) - name of log analytics workspace, where 
   you want your storage account to direct its logs to
2. create-la-ws - (Optional) - Boolean flag to create workspace with
   log-analytics-workspace-name, if it is not found in given subscription

For Rollback:
1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.
