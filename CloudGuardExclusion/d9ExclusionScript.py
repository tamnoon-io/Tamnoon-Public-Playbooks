import argparse
import json
import requests
import logging
import sys



def log_setup(log_l):
    """
        This method setup the logging level an params
        logs output path can be controlled by the log stdout cmd param (stdout / file)
    """
    logging.basicConfig(format='[%(asctime)s -%(levelname)s] (%(processName)-10s) %(message)s')
    log_level = log_l
    logging.getLogger().setLevel(log_level)




def print_help():
    text = (
        '\n'
        '\n '
        '''
        
\t\t\t ___                                                                                           
\t\t\t(   )                                                                            .-.           
\t\t\t | |_       .---.   ___ .-. .-.    ___ .-.     .--.     .--.    ___ .-.         ( __)   .--.   
\t\t\t(   __)    / .-, \ (   )   '   \  (   )   \   /    \   /    \  (   )   \        (''")  /    \  
\t\t\t | |      (__) ; |  |  .-.  .-. ;  |  .-. .  |  .-. ; |  .-. ;  |  .-. .         | |  |  .-. ; 
\t\t\t | | ___    .'`  |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | |(   )  / .'| |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | | | |  | /  | |  | |  | |  | |  | |  | |  | |  | | | |  | |  | |  | |         | |  | |  | | 
\t\t\t | ' | |  ; |  ; |  | |  | |  | |  | |  | |  | '  | | | '  | |  | |  | |   .-.   | |  | '  | | 
\t\t\t ' `-' ;  ' `-'  |  | |  | |  | |  | |  | |  '  `-' / '  `-' /  | |  | |  (   )  | |  '  `-' / 
\t\t\t  `.__.   `.__.'_. (___)(___)(___)(___)(___)  `.__.'   `.__.'  (___)(___)  `-'  (___)  `.__.'  
                                                                                                                   
        '''
        '\t\t Welcome To Dome9 Exclusion script \n'
        '\n'
        '\t\t\t Dependencies:\n'
        '\t\t\t\t \n'
        '\t\t\t This script will help you to send list of rule to be excluded from dome9 system'
        '\t\t\t The script will check if the exclusion needs to be execute - based on exisitng exclusions (ruleSet, list of rules and excluded asset)'
        '\n'
        '\t\t\t\t The script is based on Dome9 API and documentation \n'
        '\t\t\t\t https://api-v2-docs.dome9.com/?python#schemadome9-web-api-compliance-exclusion-exclusionpostrequestmodel\n'
        '\n\n'
        '\t\t\t Executions Examples:\n'
        '\t\t\t\t python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId -5 --ruleIds "D9.AWS.IAM.34,D9.AWS.IAM.28" \n'
        '\t\t\t\t python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId All --ruleIds "D9.AWS.IAM.34,D9.AWS.IAM.28" \n'
        '\t\t\t\t python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId All --ruleIds "D9.AWS.IAM.34,D9.AWS.IAM.28" --asset a1,a2,a3\n'
        '\t\t\t\t python3 d9ExclusionScript.py --d9key <key> --d9secret <secret> --ruleSetId "830467" --ruleIds "D9.AWS.IAM.35" --rulesNames "Ensure that S3 Bucket policy doesn\'t allow actions from all principals without a condition,Ensure AWS Redshift clusters are not publicly accessible,Ensure that S3 bucket ACLs don\'t allow \'READ\' access for anonymous / AWS authenticated users" --comments "Excluded by Tamnoon Service since the website needs to be public"'
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t ruleSetId - list of the rule sets ids to exclude the rule from - (Could be "All" and then the script will run against all rule sets)'
        '\t\t\t\t\t Can be also a list of rule sets to ignore (exclude all except those rule sets) - use ^ as first char - ^-5,-3,-2 ---> all excpet -5,-3,-2\n'
        '\t\t\t\t ruleIds - A comma seperated string for ids to exclude - for example "D9.AWS.NET.AG2.3.Instance.9000,D9.AWS.NET.AG2.3.Instance.22"\n'
        '\t\t\t\t rulesNames - A comma seperated string for rules names to exclude - for example - "Ensure that S3 Bucket policy doesnt allow actions from all principals without a condition, Ensure that S3 bucket ACLs don\'t allow \'FULL_CONTROL\' access for anonymous / AWS authenticated users"  '
        '\t\t\t\t assetIds - A comma seperated string for asset ids to exclude for example "i-12345,i-67893"\n'
        '\t\t\t\t comments - (optional) The comment to add to the exclusion\n'
        '\t\t\t\t dateRangeFrom  - The start time for the exclusion date range for exaple - "2022-06-19T10:09:37Z"\n'
        '\t\t\t\t dateRangeTo - The end time for the exclusion date range for exaple - "2022-06-19T10:09:37Z"\n'
        '\n\n'

    )
    print(text)


exsiting_excluded_rules = None

def extract_rules(rule_ids, rule_Set_id, rule_names):
    '''
    Thie function get the ruleSet by its id and get the relevant rules to exclude metadata
    :param rule_ids: The rules to exclude
    :param rule_names: The rule names to exclude
    :param rule_Set_id: The rule set id to exclude from
    :return:
    '''

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Get the rule set rules
    r = requests.get(f'https://api.dome9.com/v2/Compliance/Ruleset/{rule_Set_id}', headers=headers, auth=(d9key, d9secret))
    r.raise_for_status()
    extracted_rules = r.json()
    result = []
    rules_ids_as_a_list= []
    rule_names_as_a_list = []
    if rule_ids:
        rules_ids_as_a_list = rule_ids.split(',')
    if rule_names:
        rule_names_as_a_list = rule_names.split(',')


    if not rule_ids and not rule_names:
        for extracted_rule in extracted_rules['rules']:
                result.append({
                    "id": extracted_rule['ruleId'],
                    "logicHash": extracted_rule['logicHash'],
                    "name": extracted_rule['name']
                })

        return result
    else:


        rules_as_a_list = rules_ids_as_a_list + rule_names_as_a_list

        for rule in rules_as_a_list:
            for extracted_rule in extracted_rules['rules']:
                if rule == extracted_rule['ruleId'] or rule.lower() == extracted_rule['name'].lower():
                    result.append({
                        "id": extracted_rule['ruleId'],
                        "logicHash": extracted_rule['logicHash'],
                        "name": extracted_rule['name']
            })

        return result

def get_all_rule_sets():
    results_ids = []
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    r = requests.get(f'https://api.dome9.com/v2/Compliance/Ruleset', headers=headers,
                     auth=(d9key, d9secret))
    r.raise_for_status()
    rule_sets = r.json()

    for res_entry in rule_sets:
        results_ids.append(res_entry['id'])
    return results_ids


def _delete_exclsuion(exclusion_id):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    r = requests.delete(f'https://api.dome9.com/v2/Compliance/Exclusion?id={exclusion_id}', headers=headers,
                     auth=(d9key, d9secret))
    r.raise_for_status()


def need_to_run_exclusion(asset, rule_set, rules):
    rule_names = list()
    for rule in rules:
        if rule['name']:
            rule_names.append(rule['name'])

    # get the exclusion for the same rule_set and asset
    sub_set = list()
    for exclusion in exsiting_excluded_rules:
        if exclusion["rulesetId"] == int(rule_set):
            if asset:
                logic_expressions_split = exclusion["logicExpressions"][0].split(" ") if exclusion["logicExpressions"] else None
                # the tamnoon exclusion always will be for specific asset so the length of the split should be in size 3
                if (logic_expressions_split and len(logic_expressions_split) == 3):
                    # If the exclusion is for the same rule set and the same asset or doesn't have asset
                    if ((asset and asset == logic_expressions_split[2].replace("'","")) ):
                        sub_set.append(exclusion)
            else:
                if not exclusion["logicExpressions"]:
                    sub_set.append(exclusion)
    if len(sub_set) == 0:
        # no potential exclusion found return true
        return True
    for exclusion in sub_set:
        curr_rule_ids = list()
        curr_rule_names = list()
        if not exclusion['rules']:
            logging.info(
                f"No need to run Exclusion for {rule_set} for rules - {rule_names} and asset - {asset}, There is Exclusion for the entire ruleset!")
            return False
        for curr_rule in exclusion['rules']:
            curr_rule_ids.append(curr_rule['id'])
            curr_rule_names.append((curr_rule['name']))


        # if all curr rule names in the potential exclusion request
        if all(item in rule_names for item in curr_rule_names):
            if len(rule_names)>len(curr_rule_names):
                # need to replace the exclusion
                _delete_exclsuion(exclusion['id'])
                return True
            else:
                logging.info(
                    f"No need to run Exclusion for {rule_set} for rules - {rule_names} and asset - {asset}, The exclusion already exist!")
                return False
        else:
            logging.info(
                f"No need to run Exclusion for {rule_set} for rules - {rule_names} and asset - {asset}, The exclusion already exist!")
            return False



def run_exclusion(rule_ids, rule_set, asset_ids, rule_names):
    logging.info(f"Going to extract the rules meta data for rule set {rule_set}")
    rules = extract_rules(rule_ids=rule_ids, rule_Set_id=rule_set, rule_names=rule_names)
    if len(rules)>0:
        if asset_ids:
            for asset in asset_ids.split(','):
                if need_to_run_exclusion(asset, rule_set, rules):
                    logic_expressions = [f"name like '{asset}'"]
                    _run_exclusion(logic_expressions, rule_set, rules)
        else:
            if need_to_run_exclusion(None, rule_set, rules):
                _run_exclusion(None, rule_set, rules)
    else:
        logging.info(f"No specific rules found for - Bundle {rule_set}")


def _run_exclusion(logic_expressions, rule_set, rules):
    logging.info(f"Going to build the body for the request")
    body = {
        "rules": rules,
        "rulesetId": rule_set,
        "comment": comments,
        "logicExpressions": logic_expressions,
        "cloudAccountIds": None,
        "id": None,
        "dateRange": None,
        "organizationalUnitIds": None
    }
    if date_range_to and date_range_from:
        body['dateRange'] = dict()
        body['dateRange']['from'] = date_range_from
        body['dateRange']['to'] = date_range_to
    logging.info(f"Going to run exclusion request")
    logging.info(f"body -{body}")
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    try:
        r = requests.post('https://api.dome9.com/v2/Compliance/Exclusion', data=json.dumps(body), headers=headers,
                          auth=(d9key, d9secret))
        r.raise_for_status()
        print(r.json())
    except Exception as e:
        if r.status_code == 409:
            logging.warning("Skip insertion of existing exclusion")



if __name__ == '__main__':

    # TODO - Work on desc for params
    parser = argparse.ArgumentParser()
    parser.add_argument('--logLevel', required=False, type=str, default="INFO")
    parser.add_argument('--ruleSetId', required=True, type=str)
    parser.add_argument('--ruleIds', required=False, type=str,default=None)
    parser.add_argument('--rulesNames', required=False, type=str, default=None)
    parser.add_argument('--assetIds', required=False, type=str, default=None)
    parser.add_argument('--comments', required=False, type=str,  default="Exclusions by Tamnoon Service")
    parser.add_argument('--dateRangeFrom', required=False, default="2022-06-19T10:09:37Z")
    parser.add_argument('--dateRangeTo', required=False, default="2022-06-19T10:09:37Z")
    parser.add_argument('--d9key', required=True)
    parser.add_argument('--d9secret', required=True)

    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        sys.exit(1)

    print_help()
    args = parser.parse_args()



    d9key = args.d9key
    d9secret = args.d9secret

    rule_set_id = args.ruleSetId
    rule_ids = args.ruleIds
    rule_names = args.rulesNames
    asset_ids = args.assetIds
    comments = args.comments
    date_range_from = None
    if args.dateRangeFrom:
        date_range_from = args.dateRangeFrom
    date_range_to = None
    if args.dateRangeTo:
        date_range_from = args.dateRangeTo

    log_setup(args.logLevel)

    # build exclusion cache
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    logging.info(f"Building the exclusion cache by getting all defined exclusion from Dome9")
    r = requests.get('https://api.dome9.com/v2/Compliance/Exclusion', headers=headers,
                     auth=(d9key, d9secret))
    r.raise_for_status()
    exsiting_excluded_rules = r.json()


    if rule_set_id == 'All':
        # get all the rule sets ids in the system
        rule_sets_ids = get_all_rule_sets()
        for rule_set in rule_sets_ids:
            run_exclusion(rule_ids=rule_ids, rule_set=rule_set, asset_ids=asset_ids, rule_names=rule_names)
    else:
        try:
            if rule_set_id[0] == '^':
                rule_set_id_to_ignore = [int(number_rule_set_id) for number_rule_set_id in rule_set_id[1:len(rule_set_id)].split(',')]
                rule_set_id = list()
                all_rule_sets_ids = get_all_rule_sets()
                for rule_set in all_rule_sets_ids:
                    if rule_set not in rule_set_id_to_ignore:
                        rule_set_id.append(rule_set)
                rule_set_id = ','.join([str(i)for i in rule_set_id])

            if ',' not in rule_set_id:
                # Only one rule set execution
                run_exclusion(rule_ids=rule_ids, rule_set=rule_set_id, asset_ids=asset_ids, rule_names=rule_names)
            else:
                # list of rule sets to exclude
                rule_sets = rule_set_id.split(',')
                for rule_set in rule_sets:
                    run_exclusion(rule_ids=rule_ids, rule_set=rule_set.replace(" ",""), asset_ids=asset_ids, rule_names=rule_names)
        except Exception as e:
            logging.error(f"Something went wrong - {e}")
