
[comment]: <> (This is a readonly file, do not edit directly, to change update the postgresql_server_restrict_firewall_rules.json)
<img src='../../../../TamnoonPlaybooks/images/icons/Tamnoon.png' width = '200' />

# Tamnoon Playbook: Azure  - Postgre SQL Server Firewall Rules
## Description

This automation allows you to restrict firewall rules of PostgreSQL Flexible Server public network access. If the PostgreSQL Flexible Server has disabled its public network access, the automation will enable the same and it will add or modify or remove the firewall rules of the server as per given action parameters.  
  The top level parameters for this automation allow you to specify which PostgreSQL Flexible Server instances you want to perform this action on, while the "Action Parameters" described below allow you to specify which firewall rules you want to remove or replace on these instances.  
## Prerequisites
1. Python v3.9  and above + following packages installed.

	azure-core  
	   azure-identity  
	  azure-mgmt-resource  
	   azure-mgmt-network  
	   azure-mgmt-subscription  
	  azure-mgmt-rdbms  
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

4. Get the Subscription ID, Resource Group Name, SQL server(s) name, Regions

5. Execute the automation from the /Azure directory

	1. Using CLI parameters :
		``````sh
		python3 -m Automations.DBServer \
		postgresql-server \
		restrict_firewall_rules \
		--subscription subscription-id \
		--resourceGroups sample-resource-group \
		--regions all \
		--assetIds sample-test-flexible-server-postgresql \
		--actionParams '{"remove_rule_name":"rule-2"}'
		``````

	2. Using YAML file: a yaml file is a text file with a "yml" or "yaml" extension whose content is in the format:
		``````yaml
		subscription: 
		  - subscription-id
		resourceGroups: 
		  - sample-resource-group
		assetIds: 
		  - sample-test-flexible-server-postgresql
		actionParams:
		  remove_rule_range: "2.23.45.6-3.87.65.4"
		  replace: true
		  replacement_ranges:
		    - "5.23.45.6-11.87.65.4"
		``````

	3. Run the execution:
		``````sh
		python3 -m Automations.DBServer \
		postgresql-server \
		restrict_firewall_rules \
		--file path-to-yaml-file
		``````

	4. Using JSON file: a json file is a text file with a "json" extension whose content is in the format:
		``````json
		{
		  "subscription": ["subscription-id"],
		  "resourceGroups": ["sample-resource-group"],
		  "assetIds": ["sample-test-flexible-server-postgresql"],
		  "actionParams": {
		    "remove_rule_range": "5.23.45.6-11.87.65.4",
		    "replace": true,
		    "replacement_ranges": ["6.23.45.6-12.87.65.4"]
		  }
		}
		
		``````

	5. Run the execution:
		``````sh
		python3 -m Automations.DBServer \
		postgresql-server \
		restrict_firewall_rules \
		--file path-to-json-file
		``````
### subscription - (Required)
Subscription ID. When given, the automation will find Postgre SQL Flexible Servers in the specified Subscription.
### resourceGroups - (Optional)
list of Resource Group names. When given, the automation will find Postgre SQL Flexible Servers in only specified Resource Groups. Otherwise default value is 'all', i.e., the automation will find Postgre SQL Flexible Servers in all Resource Groups available in the Subscription.
### assetIds - (Optional)
comma separated list of Postgre SQL Flexible Servers.
### regions - (Optional)
regions of Postgre SQL Flexible Servers. When given, the automation will find Postgre SQL Flexible Servers that have location same as any of the given regions. Otherwise default value is 'all', i.e., the automation will find Postgre SQL Flexible Servers regardless of its location.
### actionParams - (Required)
- for the automation
    1. remove_rule_name - (Optional*) name of firewall rule to remove or replace. This will be used to find firewall rule that can be removed or replaced.
    2. remove_rule_range - (Optional*) ip address range*** of firewall rule to remove or replace. It should be in the form of &lt;start_ip_address&gt;-&lt;end_ip_address&gt;. This will be used to find firewall rule that can be removed or replaced. Example, "0.0.0.0-255.255.255.255"
    3. replace - (Optional) true if you want to replace rule, false if you want to remove only. If you do not provide this action param, then default will be false.
    4. replacement_rule_name - (Optional**) new name you want to replace. If not provided, then default will be Tamnoon-replacement-&lt;datetime&gt;. if replacement_rule_ranges have multiple ranges, then after first replacement, every replacement will have &lt;replacement_rule_name&gt;-&lt;n&gt; or Tamnoon-replacement-&lt;n&gt;-&lt;datetime&gt; where &lt;n&gt; is number of replacement range. &lt;datetime&gt; will be in format yyyy-mm-dd-HH-MM-SS.
    5. replacement_ranges - (Optional**) - list of ip address ranges***. Example
        ["0.0.0.0-99.99.99.255","100.100.100.0-200.200.200.255"]

    \* at least one of remove_rule_name and remove_rule_range are required  
    ** if replace is true, then replacement_ranges is required with optional replacement_rule_name  
    *** Here start_ip_address and end_ip_address are IP Addresses only. Using CIDR will not work.

    Examples,  
    - to remove:  
        ```
        --actionParams = '{"remove_rule_name":"rule-1"}'
        ```  
        or  
        ```
        --actionParams = '{"remove_rule_range":"0.0.0.0-255.255.255.255"}'
        ```  
        or  
        ```
        --actionParams = '{"remove_rule_name":"rule-1", "remove_rule_range":"0.0.0.0-255.255.255.255"}'
        ```
    - to replace:
        ```
        --actionParams = '{"remove_rule_name":"rule-1", "replace": true, "replacement_ranges": ["0.0.0.0-99.99.99.255","100.100.100.0-200.200.200.255"]}'
        ```  
        or  
        ```
        --actionParams = '{"remove_rule_name":"rule-1", "replace": true, "replacement_rule_name": "rule-2", "replacement_ranges": ["0.0.0.0-99.99.99.255","100.100.100.0-200.200.200.255"]}'
        ```  

 - for rollback 
    1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
    2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.
