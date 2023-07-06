
<img src="../../../images/icons/Tamnoon.png" width="200"/>

# Tamnoon Playbook: automatically exclude CloudGuard alerts.

## Description
This playbook describe how to execute cloudGuard exclusions.
The execution is based on CloudGuard Dome9 APIs:
https://api-v2-docs.dome9.com/?python#schemadome9-web-api-compliance-exclusion-exclusionpostrequestmodel

## Playbook steps:
1. Use the script - d9ExclusionScript.py
2. This script will help you to send list of rule to be excluded from dome9 system
The script high level logic
      ```
      if specific ruleSetId is used, the script will exclude all teh assets and the rules from that ruleset
      if ruleSetId set to All, the script will iterate over all the exsiiting rule sets and will exclude the rules that are existis on that rule set
      based on thier Dome9 ruleId. Only rule ids from the paramete RuleIds that exisits on the ruleset will be excluded

      
## Prerequisites 
1. CloudGuard Dome9 Authz keys
2. Python v3.6  and above + boto3 package installed ( pip install boto3)

## Notes:
Currently, when the script is executed with multi assets it will generate exclusion per rule,ruleset,asset 
Soon we will support of executing one exclusion per multi assets 


## Script help page 

                         ___                                                                                           
                        (   )                                                                            .-.           
                         | |_       .---.   ___ .-. .-.    ___ .-.     .--.     .--.    ___ .-.         ( __)   .--.   
                        (   __)    / .-, \ (   )   '   \  (   )   \   /    \   /    \  (   )   \        (''")  /    \  
                         | |      (__) ; |  |  .-.  .-. ;  |  .-. .  |  .-. ; |  .-. ;  |  .-. .         | |  |  .-. ; 
                         | | ___    .'`  |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
                         | |(   )  / .'| |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
                         | | | |  | /  | |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
                         | ' | |  ; |  ; |  | |  | |  | |  | |  | |  | '  | | | '  | |  | |  | |   .-.   | |  | '  | | 
                         ' `-' ;  ' `-'  |  | |  | |  | |  | |  | |  '  `-' / '  `-' /  | |  | |  (   )  | |  '  `-' / 
                          `.__.   `.__.'_. (___)(___)(___)(___)(___)  `.__.'   `.__.'  (___)(___)  `-'  (___)  `.__.'  
                                                                                                                   
                         Welcome To Dome9 Exclusion script 

                         Dependencies:
                                 
                         This script will help you to send list of rule to be excluded from dome9 system                         
                         The script will check if the exclusion needs to be execute - based on exisitng exclusions (ruleSet, list of rules and excluded asset)
                         The script is based on Dome9 API and documentation 
                                 https://api-v2-docs.dome9.com/?python#schemadome9-web-api-compliance-exclusion-exclusionpostrequestmodel


                         Executions Examples:
                                 python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId -5 --ruleIds "D9.AWS.IAM.34,D9.AWS.IAM.28" 
                                 python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId All --ruleIds "D9.AWS.IAM.34,D9.AWS.IAM.28" 
                                 python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId All --ruleIds "D9.AWS.IAM.34,D9.AWS.IAM.28" --asset a1,a2,a3


                         Parameter Usage:
                                 logLevel - The logging level (optional). Default = Info
                                 ruleSetId - list of the rule sets ids to exclude the rule from - (Could be "All" and then the script will run against all rule sets)
                                 ruleIds - A comma seperated string for ids to exclude - for example "D9.AWS.NET.AG2.3.Instance.9000,D9.AWS.NET.AG2.3.Instance.22"
                                 assetIds - A comma seperated string for asset ids to exclude for example "i-12345,i-67893"
                                 comments - (optional) The comment to add to the exclusion
                                 dateRangeFrom  - The start time for the exclusion date range for exaple - "2022-06-19T10:09:37Z"
                                 dateRangeTo - The end time for the exclusion date range for exaple - "2022-06-19T10:09:37Z"

