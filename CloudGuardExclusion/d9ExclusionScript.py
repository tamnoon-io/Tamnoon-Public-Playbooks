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
        '\n\n'
        '\t\t\t Parameter Usage:\n'
        '\t\t\t\t logLevel - The logging level (optional). Default = Info\n'
        '\t\t\t\t ruleSetId - list of the rule sets ids to exclude the rule from - (Could be "All" and then the script will run against all rule sets)\n'
        '\t\t\t\t ruleIds - A comma seperated string for ids to exclude - for example "D9.AWS.NET.AG2.3.Instance.9000,D9.AWS.NET.AG2.3.Instance.22"\n'
        '\t\t\t\t assetIds - A comma seperated string for asset ids to exclude for example "i-12345,i-67893"\n'
        '\t\t\t\t comments - (optional) The comment to add to the exclusion\n'
        '\t\t\t\t dateRangeFrom  - The start time for the exclusion date range for exaple - "2022-06-19T10:09:37Z"\n'
        '\t\t\t\t dateRangeTo - The end time for the exclusion date range for exaple - "2022-06-19T10:09:37Z"\n'
        '\n\n'

    )
    print(text)


exsiting_excluded_rules = None

def extract_rules(rule_ids, rule_Set_id):
    '''
    Thie function get the ruleSet by its id and get the relevant rules to exclude metadata
    :param rule_ids: The rules to exclude
    :param rule_Set_id: The rule set id to exclude from
    :return:
    '''

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    r = requests.get(f'https://api.dome9.com/v2/Compliance/Ruleset/{rule_Set_id}', headers=headers, auth=(d9key, d9secret))
    r.raise_for_status()
    extracted_rules = r.json()
    result = []
    rules_as_a_list = rule_ids.split(',')

    for rule in rules_as_a_list:
        for extracted_rule in extracted_rules['rules']:
            if rule == extracted_rule['ruleId']:
                result.append({
                    "id": rule,
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


def need_to_run_exclusion(asset, rule_set, rules):
    rule_ids = list()
    for rule in rules:
        rule_ids.append(rule["id"])

    # get the exclusion for the same rule_set and asset
    # sub_set = list()
    for exclusion in exsiting_excluded_rules:
        logic_expressions_split = exclusion["logicExpressions"][0].split(" ") if exclusion["logicExpressions"] else None
        # the tamnoon exclusion always will be for specific asset so the length of the split should be in size 3
        if logic_expressions_split and len(logic_expressions_split) == 3 or not logic_expressions_split:
            # If the exclusion is for the same rule set and the same asset or doesn't have asset
            if exclusion["rulesetId"] == rule_set:
                if ((asset and asset == logic_expressions_split[2].replace("'","")) or (not asset)):
                    rule_that_not_exist = False
                    # todo - impliment replace exclusion logic - delete and create new one
                    for rule in exclusion["rules"]:
                        if rule["id"] not in rule_ids:
                            rule_that_not_exist = True
                            break
                    if not rule_that_not_exist:
                        logging.info(f"No need to run Exclusion for {rule_set} for ids - {rule_ids} and asset - {asset}, The exclusion already exist!")
                        return False
    return True



def run_exclusion(rule_ids, rule_set, asset_ids):
    logging.info(f"Going to extract the rules meta data for rule set {rule_set}")
    rules = extract_rules(rule_ids=rule_ids, rule_Set_id=rule_set)
    if len(rules)>0:
        if asset_ids:
            for asset in asset_ids.split(','):
                logic_expressions = [f"name like '{asset}'"]
                _run_exclusion(logic_expressions, rule_set, rules)
        else:
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
    parser.add_argument('--ruleIds', required=True, type=str,default='All')
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


    r = requests.get('https://api.dome9.com/v2/Compliance/Exclusion', headers=headers,
                     auth=(d9key, d9secret))
    r.raise_for_status()
    exsiting_excluded_rules = r.json()


    if rule_set_id == 'All':
        # get all the rule sets ids in the system
        rule_sets_ids = get_all_rule_sets()

        for rule_set in rule_sets_ids:
            run_exclusion(rule_ids=rule_ids, rule_set=rule_set, asset_ids=asset_ids)
    else:
        try:
            if ',' not in rule_set_id:
                run_exclusion(rule_ids=rule_ids, rule_set=rule_set_id, asset_ids=asset_ids)
            else:
                rule_sets = rule_set_id.split(',')
                for rule_set in rule_sets:
                    run_exclusion(rule_ids=rule_ids, rule_set=rule_set.replace(" ",""), asset_ids=asset_ids)
        except Exception as e:
            logging.error(f"Something went wrong - {e}")
