
[comment]: <> (This is a readonly file, do not edit directly, to change update the network_security_group_find_associations.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure  - Find NSG associations
## Description

This playbook describes how to execute Tamnoon Azure Network automation to find out what resources are associated with any Network Security Group (NSG).  
## Prerequisites
1. Python v3.9  and above + following packages installed.

	azure-core  
	  azure-identity  
	  azure-mgmt-resource  
	  azure-mgmt-storage  
	  azure-storage-blob  
	  azure-mgmt-network  
	  azure-mgmt-loganalytics  
	  azure-mgmt-compute  
	  azure-mgmt-monitor  
	  azure-mgmt-subscription  
	  azure-mgmt-cosmosdb  
	  azure-mgmt-sql  
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

4. Get the Subscription ids, Resource Group Name, Network Security Group name, Regions

5. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````sh
		python3 -m Automations.Network \
		network-security-group \
		find_associations \
		--subscription subscription-id \
		--resourceGroups sample-resource-group,resource_grp2 \
		--assetIds nsg-001
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		subscription: subscription-id
		resourceGroups:  
		  - sample-resource-group  
		  - resource_grp2
		regions:  
		  - eastus
		assetIds:  
		  - nsg-001
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.Network \
		network-security-group \
		find_associations \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		"subscription": "subscription-id",
		"resourceGroups": ["sample-resource-group","resource_grp2"],
		"regions": ["eastus"],
		"assetIds": ["nsg-001"]
		}
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.Network \
		network-security-group \
		find_associations \
		--file path-to-json-file
		``````
### subscription - (Mandatory)
The automation will find and evaluate Network Security Groups in the given subscription.
### resourceGroups - (Optional)
list of Resource Group names. When given, the automation will find and evaluated Network Security Groups only within the specified Resource Groups. Otherwise default value is 'all', i.e., the automation will find Network Security Groups in all Resource Groups available in the Subscription.
### assetIds - (Optional)
comma-separated list of Network Security Groups. The automation will evaluate only the specified NSGs.
### regions - (Optional)
comma-separated list of regions. The automation will find and evaluate NSGs only in the regions specified
