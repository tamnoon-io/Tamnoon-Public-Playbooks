

import json
import logging
from botocore.exceptions import ClientError

LISTENER_PORT = 80


def validate_action_params(action_params):
    if "rollBack" in action_params:
        if "statePath" not in action_params:
            raise Exception(
                "You are trying to execute roll back with no 'statePath' parameter, the script have to know the previous saved state"
            )

    return True


def get_alb_listener_rules(session, alb_name):
    """
    find application load balancer's listener rules and put into a json file
    """
    elb = session.client('elbv2')
    # Get the ALB by name
    alb_response = elb.describe_load_balancers(Names=[alb_name])
    alb_arn = alb_response['LoadBalancers'][0]['LoadBalancerArn']

    # Get the listener for the specified port
    listener_response = elb.describe_listeners(LoadBalancerArn=alb_arn)
    listener = next(
        (l for l in listener_response['Listeners'] if l['Port'] == LISTENER_PORT), None)

    if listener:
        # Get the rules for the listener
        rules_response = elb.describe_rules(
            ListenerArn=listener['ListenerArn'])
        rules = rules_response['Rules']

        # Create a dictionary with the listener and rule configurations
        config = {
            "LoadBalancerName": alb_name,
            "ListenerPort": LISTENER_PORT,
            "ListenerArn": listener['ListenerArn'],
            "DefaultActions": listener['DefaultActions'],
            "Rules": rules
        }

        # Save the configuration to a JSON file
        with open(f"{alb_name}_listener_{LISTENER_PORT}_config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
        logging.info(
            f"Saved configuration to {alb_name}_listener_{LISTENER_PORT}_config.json")
    else:
        logging.info(
            f"No listener found on port {LISTENER_PORT} for ALB {alb_name}")
    elb.close()


def do_redirect_to_http(session, alb_names, dry_run=True):
    """
    modify application load balancer's listener rules and put into a json file
    """

    # Create an Elastic Load Balancing client
    elb = session.client('elbv2')
    result: dict = {}

    is_all_albs = alb_names == ['all']
    load_balancers = []
    # find all load balancers
    load_balancers_response = elb.describe_load_balancers()
    load_balancers = load_balancers_response['LoadBalancers']
    albs = dict()
    for load_balancer in load_balancers:
        load_balancer_name = load_balancer.get("LoadBalancerName")
        load_balancer_type = load_balancer.get("Type")
        load_balancer_arn = load_balancer.get('LoadBalancerArn')
        # check if assetIds has specified current load balancer or if all load balancers are to be used
        if is_all_albs or load_balancer_name in alb_names:
            # check if load balancer is "application" load balancer
            if load_balancer_type == 'application':
                # use this application load balancer in automation
                albs.update({load_balancer_name: load_balancer_arn})
            else:
                # do not use this load balancer in automation, and show correspondig message
                lb_type_mismatch_message = ""
                if not is_all_albs and load_balancer_name in alb_names:
                    lb_type_mismatch_message = f"Given load balancer name is of type {load_balancer_type}, and hence ignored in this automation. This automation is only for application load balancers."
                else:
                    lb_type_mismatch_message = f"{load_balancer_name} is of type {load_balancer_type}, and hence ignored in this automation. This automation is only for application load balancers."
                result.update(
                    {
                        load_balancer_name: lb_type_mismatch_message
                    }
                )
                logging.info(lb_type_mismatch_message)

    if not is_all_albs:
        for alb_name in alb_names:
            if alb_name not in albs.keys():
                # if some assetIds (alb_names) were not found, then show appropriate message in result
                # this is only applicable when alb_names is not specified to be "all", in which case,
                # only existing application load balancers will be used.
                lb_not_found_message = "Application Load Balancer not found with this name"
                result.update({alb_name: lb_not_found_message})
                logging.info(lb_not_found_message)
    for alb_name in albs.keys():
        new_listener = {}
        new_rules: list = []

        # Get the listener for port 80
        listener_response = elb.describe_listeners(
            LoadBalancerArn=albs[alb_name])
        listener = next(
            (l for l in listener_response['Listeners'] if l['Port'] == LISTENER_PORT), None)

        if listener:

            logging.info("listener default actions")
            # update default actions of listener - if "forward" - to "redirect"
            # get default ruls from rules
            if len(listener.get("DefaultActions", [])) > 0:
                could_update_listener = False
                # conditions to find actions that are defined in rule are of type "forward".
                new_default_actions: list = []
                for action in listener.get("DefaultActions"):
                    if action['Type'] == 'forward':
                        if dry_run:
                            # dry run result
                            logging.info(
                                "Could update default action of listener to redirect")
                        else:
                            # modify listener's default actions result
                            logging.info(
                                "Updating default action of listener to redirect")
                            could_update_listener = True
                            new_default_actions.append({
                                'Type': 'redirect',
                                'RedirectConfig': {
                                        'Protocol': 'HTTPS',
                                        'Port': '443',
                                        'StatusCode': 'HTTP_301'
                                }
                            }.copy())
                    else:
                        new_default_actions.append(action.copy())
                if could_update_listener:
                    # modify listener if default actions can be updated
                    try:
                        response = elb.modify_listener(
                            ListenerArn=listener['ListenerArn'],
                            DefaultActions=new_default_actions
                        )
                    except ClientError as ce:
                        logging.error(
                            "Modify listener failed. %s", ce, exc_info=True)
                    except Exception as ex:
                        logging.error(
                            "Something went wrong. %s", ex, exc_info=True)

                    # get updated value for result
                    new_listener = response['Listeners'][0].copy()

            # Get the rules for the listener
            rules_response = elb.describe_rules(
                ListenerArn=listener['ListenerArn'])
            rules = rules_response['Rules']

            # remove default rules from list, we don't need to process this since we have
            # already updated default actions of listener
            rules = list(filter(lambda rule: rule is not None, [
                None if rule['IsDefault'] else rule for rule in rules]))

            # Iterate through the rules and update any "forward" actions to "redirect"
            for rule in rules:
                if not rule:
                    continue
                could_update = False
                actions = rule['Actions']
                new_actions: list = []
                for action in actions:
                    new_action: dict = action.copy()
                    if action['Type'] == 'forward':
                        # modify rule's action if it has type "forward"
                        could_update = True
                        new_action.update({'Type': 'redirect'})
                        new_action.update({'RedirectConfig': {
                            'Protocol': 'HTTPS',
                            'Port': '443',
                            'Host': '#{host}',
                            'Path': '/#{path}',
                            'Query': '#{query}',
                            'StatusCode': 'HTTP_301'
                        }})
                        del new_action['TargetGroupArn']
                        del new_action['ForwardConfig']
                    else:
                        pass
                    new_actions.append(new_action)

                if could_update:
                    if dry_run:
                        logging.info("Could update rule action to redirect")
                    else:
                        logging.info(
                            f"Updating rule action to redirect")

                        # Update the rule with the modified actions
                        try:
                            response = elb.modify_rule(
                                RuleArn=rule['RuleArn'],
                                Actions=new_actions
                            )
                            new_rules.extend(response['Rules'])
                        except ClientError as ce:
                            logging.error(
                                "Modify rule failed. %s", ce, exc_info=True)
                        except Exception as ex:
                            logging.error(
                                "Something went wrong. %s", ex, exc_info=True)
                else:
                    logging.info("forward rule action not found")
            # update result dictionary
            result.update(
                {
                    alb_name: {
                        'prev_state': {
                            'listener': listener,
                            'rules': rules
                        },
                        'current_state': {
                            'listener': "Could update default action of listener to redirect" if dry_run else new_listener,
                            'rules': "Could update rule action to redirect" if dry_run else new_rules
                        }
                    }
                }
            )
        else:
            logging.info(f"No listener found on port 80 for ALB {alb_name}")
            result.update(
                {alb_name: {'prev_state': {'listener': listener, 'rules': rules}, 'current_state': {'listener': None, 'rules': None}}})
    # return final result
    return result


def clean_conditions(conditions):
    """
    can be used to sanitize conditions when updating rules
    """
    for condition in conditions:
        field = condition.get('Field')
        if field == 'path-pattern' and 'PathPatternConfig' in condition:
            condition.pop('Values', None)
        elif field == 'host-header' and 'HostHeaderConfig' in condition:
            condition.pop('Values', None)
        elif field == 'http-header' and 'HttpHeaderConfig' in condition:
            condition.pop('Values', None)
        elif field == 'http-request-method' and 'HttpRequestMethodConfig' in condition:
            condition.pop('Values', None)
        elif field == 'query-string' and 'QueryStringConfig' in condition:
            condition.pop('Values', None)
        elif field == 'source-ip' and 'SourceIpConfig' in condition:
            condition.pop('Values', None)
    return conditions


def rollback_do_redirect_to_https(session, last_execution_state_path, dry_run=True):
    """
    rollBack/undo modify application load balancer's listener rules
    """

    # Load the original configuration from the JSON file
    with open(last_execution_state_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    # Create an Elastic Load Balancing client
    elb = session.client('elbv2')
    result: dict = {}

    for alb_name in config[session.region_name]:
        new_listener: dict = {}
        new_rules: list = []
        alb_config = config[session.region_name].get(alb_name)
        rules_data = alb_config.get('prev_state').get('rules')
        prev_listener_data = alb_config.get('prev_state').get('listener')
        # Get the ALB by name
        alb_response = elb.describe_load_balancers(Names=[alb_name])
        alb_arn = alb_response['LoadBalancers'][0]['LoadBalancerArn']

        # Get the listener for the specified port
        listener_response = elb.describe_listeners(LoadBalancerArn=alb_arn)
        listener = next(
            (l for l in listener_response['Listeners'] if l['Port'] == LISTENER_PORT), None)

        if listener:
            # revert the default actions to forward, if they were updated to redirect
            if dry_run:
                logging.info(
                    "Could revert default action of listener %s to forward", listener['ListenerArn'])
                new_listener = prev_listener_data.copy()
            else:
                logging.info(
                    "Reverting default action of listener %s to forward", listener['ListenerArn'])
                try:
                    response = elb.modify_listener(
                        ListenerArn=prev_listener_data['ListenerArn'],
                        DefaultActions=prev_listener_data["DefaultActions"]
                    )
                    new_listener = response['Listeners'][0].copy()
                except ClientError as ce:
                    logging.error(
                        "Modify rule failed. %s", ce, exc_info=True)
                except Exception as ex:
                    logging.error(
                        "Something went wrong. %s", ex, exc_info=True)

            # Revert the rules to the original configuration
            for rule in rules_data:
                if not rule['IsDefault']:
                    if dry_run:
                        logging.info("Could revert rule %s and set to forward",
                                     {rule['RuleArn']})
                        new_rules.extend(rule)
                    else:
                        logging.info("Reverting rule %s", {rule['RuleArn']})
                        try:
                            response = elb.modify_rule(
                                RuleArn=rule['RuleArn'],
                                Actions=rule['Actions'],
                            )
                            new_rules.extend(response['Rules'])
                        except ClientError as ce:
                            logging.error(
                                "Modify rule failed. %s", ce, exc_info=True)
                        except Exception as ex:
                            logging.error(
                                "Something went wrong. %s", ex, exc_info=True)

                else:
                    logging.info(f"Skipping default rule {rule['RuleArn']}")
            result.update(
                {
                    alb_name: {
                        'prev_state': {
                            'listener': listener,
                            'rules': rules_data
                        },
                        'current_state': {
                            'listener':
                            "Could update default action of listener to redirect" if dry_run else new_listener,
                            'rules': "Could update rule action to redirect" if dry_run else new_rules
                        }
                    }
                }
            )
        else:
            logging.info(
                f"No listener found on port {LISTENER_PORT} for ALB {alb_name}")
            result.update(
                {alb_name: {'prev_state': {'listener': listener, 'rules': rules_data}, 'current_state': {'listener': None, 'rules': None}}})
    return result
