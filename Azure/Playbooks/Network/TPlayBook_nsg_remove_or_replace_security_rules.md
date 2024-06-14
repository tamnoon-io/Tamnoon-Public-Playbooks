
[comment]: <> (This is a readonly file, do not edit directly, to change update the network_security_group_remove_or_replace_security_rules.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure  - Remove or Replace Security Rules
## Description

This playbook describes how to execute Tamnoon Azure Network automation to remove or replace the Security Rules of Network Security Groups.  
## Prerequisites
1. Python v3.8  and above + following packages installed.

	azure-core  
	  azure-identity  
	  azure-mgmt-subscription  
	  azure-mgmt-resource  
	  azure-mgmt-network  
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

4. Get the Subscription id, names of Resource Groups, names of Network Security Groups, names of Virtual Networks, Regions ro find NSGs by.

5. Prepare the action_params as mentioned in example below

6. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````sh
		python3 -m Automations.Network \
		network-security-group \
		remove_or_replace_security_rules \
		--subscription subscription-id \
		--resourceGroups sample-resource-group \
		--vnets vnet1,vnet2,vnet3 \
		--assetIds network-security-group-name \
		--actionParams '{"Name":"AllowAnyCustom8080Inbound","Direction":"Inbound","Access":"Allow","Protocol":"*","SourceAddressPrefix":["ip or cidr or asg or service tag or * for any"],"SourcePortRange":["*"],"DestinationAddressPrefix":["ip or cidr or asg or service tag or * for any"],"DestinationPortRange":["8080"],"Replace":true,"ReplaceName":"ReplaceName","ReplacePriority":0,"ReplaceDescription":"","ReplaceSourceAddressPrefix":["ip or cidr or asg or service tag or * for any"],"ReplaceDestinationAddressPrefix":["ip or cidr or asg or service tag or * for any"]}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		subscription: subscription-id
		resourceGroups: 
		  - sample-resource-group
		actionParams: 
		  Name: "AllowAnyCustom8080Inbound2_replaced" 
		  Direction: "Inbound" 
		  Access: "Allow" 
		  Protocol: "*"  
		  SourceAddressPrefix:
		    - "*"
		  SourcePortRange:
		    - "8080"
		  Replace: true
		  ReplaceName: "AllowAnyCustom8080Inbound2_replaced_v2"
		  ReplacePriority: 144
		  ReplaceDescription: "replaced AllowAnyCustom8080Inbound2"
		  ReplaceSourceAddressPrefix: "*"
		  ReplaceDestinationAddressPrefix: "*"
		
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.Network \
		network-security-group \
		remove_or_replace_security_rules \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "subscription": "subscription-id",
		  "resourceGroups": [
		    "sample-resource-group"
		  ],
		  "actionParams": {
		    "Name": "AllowAnyCustom8080Inbound2_replaced",
		    "Direction": "Inbound",
		    "Access": "Allow",
		    "Protocol": "*",
		    "SourceAddressPrefix": ["*"],
		    "SourcePortRange": ["8080"],
		    "Replace": true,
		    "ReplaceName": "AllowAnyCustom8080Inbound2_v2",
		    "ReplacePriority": 144,
		    "ReplaceDescription": "replaced AllowAnyCustom8080Inbound2",
		    "ReplaceSourceAddressPrefix": "*",
		    "ReplaceDestinationAddressPrefix": "*"
		}
		}
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.Network \
		network-security-group \
		remove_or_replace_security_rules \
		--file path-to-json-file
		``````

Note: In above example, * for any means, those security rules will be matched, where their value is also "Any" (i.e., * ) in the Azure. Do not mistake it for being matched with security rules regardless of its address prefix value.  


For example, "SourceAddressPrefix": ["*"] in the actionParams will not match security rule with SourceAddressPrefix "20.0.2.20". It will match only if security rule has exactly same value * for its SourceAddressPrefix.  
### subscription - (Optional)
Subscription ID
### resourceGroups - (Optional)
list of Resource Group names. When given, remedy will find Network Security Groups in only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will find Network Security Groups in all Resource Groups available in the Subscription.
### regions - (Optional)
comma separated list of regions of Network Security Groups. Default value is 'all'
### vnets - (Optional)
comma separated list of virtual networks names that are associated with Network Security Groups. Default value is 'all'
### assetIds - (Optional)
 comma separated list of Network Security Groups. Default value is 'all'
### actionParams - (Required)
- In either case of remove or replace security rules, you will need following information:
   - Name - Name of the secuirity rule. Optional.
   - Direction - "Inbound" or "Outbound". Default is "Inbound".
    - Access - "Allow"ed or "Deny"ed. Default is “Allow”.
    - Protocol - TCP, UDP, ICMP, Any. For matching "Any" protocol, use "*".
    - SourceAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group, * for any. Mandatory if Direction is "Inbound" or not specificied. Otherwise, when not specified, and when rule is outbound we match on anything
    - SourcePortRange - list of numeric (22) or ranges (80-81), optional, if not specied we match on anything
    - DestinationAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group, * for any. Mandatory if Direction is "Outbound". Otherwise, if not specified, we match on anything
    - DestinationPortRange - list of numeric (22) or ranges (80-81), optional, if not specied we match on anything
    - replace - true/false, default is false. When true, remedy will replace the security rules details as mentioned below. 

- If you want to replace security rules, then following information is also required:
  - ReplaceName - string, optional, if not specified and replacement is True, the replacement name will be the original rule's name + "TamnoonReplacement"
  - ReplacePriority - numeric, optional. If not specified, same as original rule
  - ReplaceDescription optional, string, if not specified the description in the replaced rule is "Replacement Rule by Tamnoon. Set on date <todays date>"
  - ReplaceSourceAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group, * for any. Mandatory if replacing Inbound rules. Otherwise same as original rule.
  - replaceDestinationAddressPrefix - list of Any, or an individual IP address, classless inter-domain routing (CIDR) block (10.0.0.0/24, for example), service tag, or application security group, * for any. Mandatory if Direction is "Outbound" and Replace is True. Otherwise if not specified, same as original rule

  Note - Port range is kept as it is when replacing the Security Rules
