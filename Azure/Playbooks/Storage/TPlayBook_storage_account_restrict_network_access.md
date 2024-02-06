
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Remove Blob Container public access configuration.

## Description
This playbook describes how to execute Tamnoon Azure Storage automation to restrict network access to the storage accounts.

## Playbook steps:
1. Clone the folder Azure
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/Azure
      git checkout

   ``````  
2. user can login using "az login" or else user may get redirected to azure login screen for getting authenticated once the script execution starts.
3. Get The Subscription Ids (optional), Resource Group names (optional), Storage Accounts names (optional) for the specific storage account you want to remediate. Also you can mention Storage Account names you do not want to remediate. See actionParams for details.
4. Execute the automation from the /Azure directory


    python3 -m Automations.Storage  --type storage-account --action remove_public_network_access  --subscriptions <comma separated list of subscription ids or all> --resourceGroups <comma separated list of resource groups or all> --storageAccounts <comma separated list of storage accounts or all>  --regions <comma separated list of regions or all> --actionParams <dictionary with the specific action params> --dryRun 

### subscriptions - (Optional)
list of Subscription ids. If not given then default value is 'all', i.e., remedy will configure all the Subscriptions available in the Tenant.  

### resourceGroups - (Optional)
list of Resource Group names. When given, remedy will configure only specified Resource Groups.
otherwise default value is 'all', i.e., remedy will configure all Resource Groups available in the Subscription. 

### storageAccounts - (Optional)
list of Storage Account names. If not given then default value is 'all', i.e., remedy will configure all the Storage Accounts available in the Resource Group.

### regions - (Optional)
list of Regions. If not given then default value is 'all', i.e., remedy will configure
all the Storage Accounts without checking its regions.

### actionParams for remedy:
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


### actionParams for rollback
1. rollBack - (Required) - Boolean flag to sign if this is a rollback call (required the existing of state file)
2. lastExecutionResultPath (Required) - The path for the last execution that we want to roll-back from.

## Prerequisites 
1. Python v3.9  and above + following packages installed.  
    azure-core  
    azure-identity  
    azure-mgmt-storage  
    azure-mgmt-network
    azure-mgmt-subscription  
    azure-mgmt-resource    


