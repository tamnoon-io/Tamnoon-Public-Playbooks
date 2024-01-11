
<img src="../../images/icons/Tamnoon.png" width="200"/>

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


    python3.9 -m Automations.Storage.Storage  --type storage-account --action remove-public-network-access  --actionParams <dictionary with the specific action params> --dryRun 

### actionParams for remedy:
1. vnets - (Required) - list of dictionary of virtual network name and boolean value allow.
    Example, [{"name": "virtual-network-1", "allow": true}, {"name": "virtual-network-2", "allow": false}]
2. ip - (Required) - list of dictionary of ip address or CIDR range value and boolean value allow.
    Example, [{"value":"117.0.0.0/24","allow":true}, {"value":"117.100.0.0/24","allow":false}]
3. subscriptions - (Optional) - list of Subscription ids. If not given then default value is 'all',
    i.e., remedy will configure all the Subscriptions available in the Tenant.  
4. resource-groups - (Optional) - list of Resource Group names. When given, remedy will configure
    only specified Resource Groups. Otherwise default value is 'all', i.e., remedy will configure
    all Resource Groups available in the Subscription. 
5. storage-accounts - (Optional) - list of Storage Account names. If not given then default value
    is 'all', i.e., remedy will configure all the Storage Accounts available in the Resource Group.
6. exclude-storage-accounts - (Optional) - list of Storage Account names. When given, remedy
    will configure all the Storage Accounts except those provided with this option. When not used,
    remedy will not exclude any Storage Accounts

## Prerequisites 
1. Python v3.9  and above + following packages installed.  
    azure-core  
    azure-identity  
    azure-mgmt-storage  
    azure-mgmt-network
    azure-mgmt-subscription  
    azure-mgmt-resource    


