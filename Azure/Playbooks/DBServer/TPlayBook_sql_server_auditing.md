
[comment]: <> (This is a readonly file, do not edit directly, to change update the sql_server_enable_auditing.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure  - Enable SQL Server Auditing
## Description

This playbook describes how to execute Tamnoon Azure automation to enable auditing of SQL Server. This automation will also set auditing settings for storing audit logs in storage account given as actionParams  
## Prerequisites
1. Python v3.9  and above + following packages installed.

	azure-core  
	   azure-identity  
	   azure-mgmt-subscription  
	   azure-mgmt-resource  
	   azure-mgmt-sql  
	   azure-mgmt-storage  
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

4. Get the Subscription id, Resource Group Name, SQL server(s) name, Regions

5. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````sh
		python3 -m Automations.DBServer \
		sql-server \
		enable_auditing \
		--assetIds sql-server-name \
		--dryRun \
		--actionParams '{ "storage-auth-method": "access_key", "storage-account-name": "storageaccountname", "resource-group-name": "resource-group-name", "subscription-id": "subscritpion-id"}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		subscription: subscription-id  
		resourceGroups:    
		  - sample-resource-group  
		assetIds:    
		  - sql-server-name
		actionParams:    
		  storage-account-name: samplestorageaccount    
		  resource-group-name: sample-resource-group    
		  subscription-id: subscription-id
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.DBServer \
		sql-server \
		enable_auditing \
		--file path-to-yml-file
		``````

	3. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "subscription": "subscription-id",   
		  "resourceGroups": ["sample-resource-group"],   
		  "assetIds": ["sql-server-name"],   
		  "actionParams": {   
		    "storage-account-name": "samplestorageaccount",   
		    "resource-group-name": "sample-resource-group",   
		    "subscription-id": "subscription-id"   
		  }
		}   
		
		``````
		Run the execution:  
		``````sh
		python3 -m Automations.DBServer \
		sql-server \
		enable_auditing \
		--file path-to-json-file
		``````
### subscription - (Required)
Subscription ID. Automation will find SQL servers in only specified Subscription.
### resourceGroups - (Optional)
list of Resource Group names. When given, automation will find SQL servers in only specified Resource Groups. Otherwise default value is 'all', i.e., automation will find SQL servers in Resource Groups available in the Subscription.
### assetIds - (Required)
comma separated list of SQL Servers.
### regions - (Optional)
regions of SQL Servers. When given, automation will find SQL servers that have location same as any of the given regions. Otherwise default value is 'all', i.e., automation will find SQL servers regardless of its location.
### actionParams - (Required)
- for automation  
1. storage-account-name - (Required) - name of storage account sink where diagnostic logs should be archived  
2. resource-group-name - (Optional) - name of resource group that has this storage account. If not specified, default will be same resource group that has corresponding SQL Server.  
3. subscription-id - (Optional) - subscription-id of storage account. If not specified, default will be same subscription that has corresponding SQL Server.  
4. storage-auth-method - (Optional) - has two values. When ommitted from actionParams, default value used is "default".  
         access_key - uses Access Key of storage account as means of authenticating for storing audit logs  
         default - uses Entra ID of managed identity of SQL Server as means of authenticating for storing audit logs. For this method, few conditions should be met.
            1. SQL Server needs to have a [Managed Identity](https://learn.microsoft.com/en-gb/entra/identity/managed-identities-azure-resources/overview). 
            2. Storage Account's IAM access control must have given a role "Storage Blob Data Contributor" or a role with similar permissions to the managed identity of SQL Server.  
 - for rollback 
      1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
      2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.
