
[comment]: <> (This is a readonly file, do not edit directly, to change update the storage_account_remove_public_network_access.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure - Remove Blob Container public access configuration.

## Description

This playbook describes how to execute Tamnoon Azure Storage automation to restrict network access to the storage accounts.  
## Prerequisites
1. Python v3.9  and above + following packages installed.

	azure-core  
	  azure-identity  
	  azure-mgmt-storage  
	  azure-mgmt-network  
	  azure-mgmt-subscription  
	  azure-mgmt-resource  
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

4. Get The Subscription Ids (optional), Resource Group names (optional), Storage Accounts names (optional) for the specific storage account you want to remediate. Also you can mention Storage Account names you do not want to remediate. See actionParams for details.

5. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````sh
		python3 -m Automations.Storage \
		storage-account \
		remove_public_network_access \
		--subscriptions <comma separated list of subscription ids or all> \
		--resourceGroups <comma separated list of resource groups or all> \
		--storageAccounts <comma separated list of storage accounts or all> \
		--regions <comma separated list of regions or all> \
		--actionParams <dictionary with the specific action params>
		
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
		  access-level: "enabled-from-selected-virtual-networks-and-ip-addresses"
		  vnets:
		    - name: "vnet1"
		      allow: true
		    - name: "vnet2"
		      allow: false
		  ip:
		    - value: "117.0.0.0/24"
		      allow: true
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.Storage \
		storage-account \
		remove_public_network_access \
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
		    "access-level": "enabled-from-selected-virtual-networks-and-ip-addresses",
		    "vnets": [
		      {"name": "vnet1", "allow": true},
		      {"name": "vnet2", "allow": false}
		    ],
		    "ip": [
		      {"value": "117.0.0.0/24", "allow": true}
		    ]
		}
		}
		
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.Storage \
		storage-account \
		remove_public_network_access \
		--file path-to-json-file
		``````
### subscriptions - (Optional)
list of Subscription ids. If not given then default value is 'all', i.e., remedy will configure all the Subscriptions available in the Tenant.
### resourceGroups - (Optional)
list of Resource Group names. When given, remedy will configure only specified Resource Groups. otherwise default value is 'all', i.e., remedy will configure all Resource Groups available in the Subscription.
### storageAccounts - (Optional)
list of Storage Account names. If not given then default value is 'all', i.e., remedy will configure all the Storage Accounts available in the Resource Group.
### regions - (Optional)
list of Regions. If not given then default value is 'all', i.e., remedy will configure all the Storage Accounts without checking its regions.
### actionParams
For Remedy:
1. access_level - (Required) - value can be only on of enabled-from-all-networks,
    enabled-from-selected-virtual-networks-and-ip-addresses and disabled.

    1. enabled-from-all-networks - any network can access containers of storage accounts. Does not need
        any additional action params

        example:

            --actionParams '{"access-level": "enabled-from-all-networks"}'
    2. enabled-from-selected-virtual-networks-and-ip-addresses  -   Some selected networks can access 
        containers of storage accounts. 
            For this access_level, you need following additional access params
        
        1. vnets - (Optional) - list of dictionary of virtual network name and boolean value allow.
            Example, [{"name": "virtual-network-1", "allow": true}, {"name": "virtual-network-2", "allow": false}]
        2. ip - (Optional) - list of dictionary of ip address or CIDR range value and boolean value allow.
            Example, [{"value":"117.0.0.0/24","allow":true}, {"value":"117.100.0.0/24","allow":false}]
            
            example:

                --actionParams '{"access-level": "enabled-from-selected-virtual-networks-and-ip-addresses", "vnets":[{"name":"vnet1","allow":true},{"name":"vnet2","allow":false}],"ip":[{"value":"117.0.0.0/24","allow":true}]}'
    3. disabled - no network can access containers of storage accounts. Does not need
        any additional action params

        example:

            --actionParams '{"access-level": "disabled"}'

For Rollback:
1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.

