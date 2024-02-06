
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: Azure  - Find NSG associations


## Description
This playbook describes how to execute Tamnoon Azure Network automation to find out what resources are associated with any Network Security Group (NSG).


## Playbook steps:
1. Clone the folder Azure
   ``````
      git clone  --branch main --single-branch --no-checkout git@github.com:tamnoon-io/Tamnoon-Service.git
      cd Tamnoon-Service/
      git sparse-checkout set TamnoonPlaybooks/Azure
      git checkout

   ``````  
2. user can login using "az login" or else user may get redirected to azure login screen for getting authenticated once the script execution starts.
3. Get the Subscription ids, Resource Group Name, Network Security Group name, Regions
4. Execute the automation from the Azure directory

``````
    python3 -m Automations.Network \
        --type network-security-group \
        --action find_associations \
        --subscription <subscription-id> \
        --resourceGroups <comma-separated list of resource groups or all> \
        --regions <comma-separated list of regions or all> \
        --assetIds <comma-separated list of nsgs or all> \
``````
   subscription - (Mandatory)
    The automation will find and evaluate Network Security Groups in the given subscription.
  
   resourceGroups - (Optional) - list of Resource Group names. When given, the automation will find and evaluated Network Security Groups only within the specified Resource Groups. Otherwise default value is 'all', i.e., the automation will find Network Security Groups in all Resource Groups available in the Subscription. 

   assetIds - (Optional) - comma-separated list of Network Security Groups. The automation will evaluate only the specified NSGs.

   regions - (Optional) - comma-separated list of regions. The automation will find and evaluate NSGs only in the regions specified

## Prerequisites 
    Python v3.9  and above + following packages installed.    
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

