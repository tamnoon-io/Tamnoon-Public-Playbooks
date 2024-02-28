import argparse
import json
import logging
import sys
import os
import datetime


from library.Utils import utils as utils
from library.DBServer.DBAction import DBTypes
from . import RestrictFirewallRules


def print_help(asset_type="", action=""):
    if asset_type == "sql-server" and action == "enable_auditing":
        from .SQLServer import EnableAuditing

        EnableAuditing.print_help()

    elif action == "restrict_firewall_rules":
        if asset_type == "sql-server":
            return RestrictFirewallRules.print_help(DBTypes.SQL)
        elif asset_type == "mysql-server":
            return RestrictFirewallRules.print_help(DBTypes.MYSQL_FLEXIBLE)
        elif asset_type == "postgresql-server":
            return RestrictFirewallRules.print_help(DBTypes.POSTGRE_SQL_FLEXIBLE)

    text = (
        "\n"
        "\n "
        """

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

        """
        "\t\t Welcome To Tamnoon Azure DB Server - The script that will help you with your Database Server Actions \n"
        "\n"
        "\t\t\t Dependencies:\n"
        "\t\t\t\t \n"
        "\t\t\t Authentication:\n"
        "\t\t\t\t The script support the fallback mechanism auth based on azure-identity DefaultAzureCredential \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/identity/azure-identity#install-the-package"
        "\t\t\t Supported Actions:\n"
        "\t\t\t\t 1. SQL Server:"
        "\t\t\t\t\t Restrict Firewall rules of public network access of the SQL Server - \n"
        "\t\t\t\t\t Enables Auditing Logs of the SQL Server - \n"
        "\t\t\t\t 2. MySQL Flexible Server:"
        "\t\t\t\t\t Restrict Firewall rules of public network access of the SQL Server - \n"
        "\n"
        "\t\t\t\t The script is based on Azrue Python SDK and documentation \n"
        "\t\t\t\t https://github.com/Azure/azure-sdk-for-python/tree/main\n"
        "\n\n"
        "\t\t\t Parameter Usage:\n"
        "\t\t\t\t logLevel - The logging level (optional). Default = Info\n"
        "\t\t\t\t subscriptions (optional) -   The Azure Subscription ID to use to execute this script (specific subscription ID, comma separated list of subscription IDs, or All)\n"
        "\t\t\t\t resourceGroups (optional) -   The Azure Resource Groups to use to execute this script (specific Resource Group, comma separated list of Resource Groups, or All)\n"
        "\t\t\t\t regions (optional) -   The Azure regions to use to execute this script (specific region, list of regions, or All)\n"
        "\t\t\t\t type -     The Azure Resource type - for example - sql-server, mysql-server ....\n"
        "\t\t\t\t action -   The Azure SQL Server API action to execute - (restrict_firewall_rules, enable_auditing)\n"
        '\t\t\t\t actionParmas (optional)  - A key value Dictionary of action params. each " should be \\" for exampel {\\"key1\\":\\"val1\\"}\n'
        '\t\t\t\t assetIds (optional) - List of assets ids (string seperated by commas)"\n'
        '\t\t\t\t dryRun (optional) - Flag that mark if this is a dry run"\n'
        '\t\t\t\t file (optional) - the path to a yml file that contain all the script input parameters"\n'
        '\t\t\t\t outputType (optional) - the type of output of script exucution. available options are json (default) and csv "\n'
        '\t\t\t\t outDir (optional) - the path to store output of script exucution. default is current working directory "\n'
        "\n\n"
    )
    print(text)


def do_postgresql_server_actions(
    credential,
    action,
    subscriptions,
    resource_groups,
    regions,
    asset_ids,
    action_params,
    dry_run,
):
    """
    This function execute blob container actions
    :param creds: the AZ authentication creds
    :param action: The action to execute
    :param asset_ids: The specific assets
    :param action_params: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    """

    if action == "restrict_firewall_rules":
        if RestrictFirewallRules.validate_action_params(action_params):
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                return RestrictFirewallRules.rollback_restrict_firewall_rules(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_params["lastExecutionResultPath"],
                    server_type=DBTypes.POSTGRE_SQL_FLEXIBLE,
                )
            return RestrictFirewallRules.restrict_firewall_rules(
                credential=credential,
                action_params=action_params,
                subscriptions=subscriptions,
                resource_groups=resource_groups,
                regions=regions,
                server_names=asset_ids,
                server_type=DBTypes.POSTGRE_SQL_FLEXIBLE,
                dry_run=dry_run,
            )

    return []


def do_mysql_server_actions(
    credential,
    action,
    subscriptions,
    resource_groups,
    regions,
    asset_ids,
    action_params,
    dry_run,
):
    """
    This function execute blob container actions
    :param creds: the AZ authentication creds
    :param action: The action to execute
    :param asset_ids: The specific assets
    :param action_params: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    """

    if action == "restrict_firewall_rules":

        if RestrictFirewallRules.validate_action_params(action_params):
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                return RestrictFirewallRules.rollback_restrict_firewall_rules(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_params["lastExecutionResultPath"],
                    server_type=DBTypes.MYSQL_FLEXIBLE,
                )
            return RestrictFirewallRules.restrict_firewall_rules(
                credential=credential,
                action_params=action_params,
                subscriptions=subscriptions,
                resource_groups=resource_groups,
                regions=regions,
                server_names=asset_ids,
                server_type=DBTypes.MYSQL_FLEXIBLE,
                dry_run=dry_run,
            )

    return []


def do_sql_server_actions(
    credential,
    action,
    subscriptions,
    resource_groups,
    regions,
    asset_ids,
    action_params,
    dry_run,
):
    """
    This function execute blob container actions
    :param creds: the AZ authentication creds
    :param action: The action to execute
    :param asset_ids: The specific assets
    :param action_params: specific action's params if needed
    :param dry_run: dry run flag
    :return:
    """

    if action == "restrict_firewall_rules":

        if RestrictFirewallRules.validate_action_params(action_params):
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                return RestrictFirewallRules.rollback_restrict_firewall_rules(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_params["lastExecutionResultPath"],
                    server_type=DBTypes.SQL,
                )
            return RestrictFirewallRules.restrict_firewall_rules(
                credential=credential,
                action_params=action_params,
                subscriptions=subscriptions,
                resource_groups=resource_groups,
                regions=regions,
                server_names=asset_ids,
                server_type=DBTypes.SQL,
                dry_run=dry_run,
            )

    if action == "enable_auditing":
        from .SQLServer import EnableAuditing

        if EnableAuditing.validate_action_params(action_params):
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                is_roll_back = "rollBack" in action_params and action_params["rollBack"]
            if is_roll_back:
                return EnableAuditing.rollback_enable_auditing(
                    credential=credential,
                    dry_run=dry_run,
                    last_execution_result_path=action_params["lastExecutionResultPath"],
                )
            return EnableAuditing.enable_auditing(
                credential=credential,
                action_params=action_params,
                subscriptions=subscriptions,
                resource_groups=resource_groups,
                regions=regions,
                sql_server_names=asset_ids,
                dry_run=dry_run,
            )

    return []


def _do_action(
    credential,
    asset_type,
    subscriptions,
    resource_groups,
    regions,
    dry_run,
    action,
    action_params,
    asset_ids,
):
    if asset_type == "sql-server":
        return do_sql_server_actions(
            credential=credential,
            action=action,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            asset_ids=asset_ids,
            action_params=action_params,
            dry_run=dry_run,
        )
    if asset_type == "mysql-server":
        return do_mysql_server_actions(
            credential=credential,
            action=action,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            asset_ids=asset_ids,
            action_params=action_params,
            dry_run=dry_run,
        )
    if asset_type == "postgresql-server":
        return do_postgresql_server_actions(
            credential=credential,
            action=action,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            asset_ids=asset_ids,
            action_params=action_params,
            dry_run=dry_run,
        )
    return {}


if __name__ == "__main__":
    # TODO - Work on desc for params
    parser = argparse.ArgumentParser(
        add_help=False,
        conflict_handler="resolve",
    )
    parser.add_argument("--type", required=False, type=str)
    parser.add_argument("--action", required=False, type=str)

    parser.add_argument("--subscriptions", required=False, type=str, default="all")
    parser.add_argument("--subscription", required=False, type=str, default=None)
    parser.add_argument("--resourceGroups", required=False, type=str, default="all")
    parser.add_argument("--storageAccounts", required=False, type=str, default="all")
    parser.add_argument("--regions", required=False, type=str, default="all")
    parser.add_argument("--assetIds", required=False, type=str, default="all")

    parser.add_argument(
        "--actionParams",
        required=False,
        type=utils.TypeActionParams,
        default=dict(),
    )
    parser.add_argument(
        "--authParams", required=False, type=utils.TypeActionParams, default=None
    )

    parser.add_argument("--logLevel", required=False, type=str, default="INFO")
    parser.add_argument("--dryRun", default=False, action="store_true")
    parser.add_argument("-h", "--help", default=False, action="store_true")

    parser.add_argument("--file", required=False, type=str, default=None)
    parser.add_argument("--outputType", required=False, type=str, default="json")
    parser.add_argument("--outDir", required=False, type=str, default="./")
    parser.add_argument("--testId", required=False, type=str)

    args = parser.parse_args()
    params = utils.build_params(args=args)
    action = params.action
    asset_type = params.type

    if len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv:
        print_help(asset_type, action)
        sys.exit(1)

    print_help()
    result = None

    asset_ids = params.assetIds
    asset_ids = asset_ids.split(",") if asset_ids else None

    action_params = params.actionParams
    auth_params = None
    if params.authParams != None:
        auth_params = (
            json.loads(params.authParams)
            if params.authParams and type(params.authParams) != dict
            else params.authParams
        )
    action_params = (
        json.loads(action_params)
        if action_params and type(action_params) != dict
        else action_params
    )
    dry_run = params.dryRun
    output_type = params.outputType.upper()
    output_dir = params.outDir

    subscriptions = []
    if params.subscription != None:
        subscriptions = [params.subscription]
    else:
        subscriptions = params.subscriptions
        subscriptions = subscriptions.split(",")

    resource_groups = params.resourceGroups
    resource_groups = resource_groups.split(",")

    storage_accounts = params.storageAccounts
    storage_accounts = storage_accounts.split(",")

    # todo - figure regional work
    regions = params.regions
    regions = regions.split(",")

    utils.log_setup(params["logLevel"])

    result = dict(
        {
            "executionDate": datetime.datetime.now().ctime(),
            "executionType": asset_type,
            "executionAction": action,
            "executionResult": [],
            "actionParams": action_params,
        }
    )

    credential = None
    if auth_params != None:
        credential = utils.setup_session("shared-key", auth_params)
    else:
        credential = utils.setup_session("default")
    # utils.setup_session("credential", auth_params)
    result["executionResult"] = _do_action(
        credential=credential,
        asset_type=asset_type,
        action=action,
        subscriptions=subscriptions,
        resource_groups=resource_groups,
        regions=regions,
        asset_ids=asset_ids,
        action_params=action_params,
        dry_run=dry_run,
    )

    result_type = "dryrun" if dry_run else "execution"
    if params.testId:
        result["testId"] = params.testId
    if not output_dir.endswith("/"):
        output_dir = output_dir + "/"
    result["stateFile"] = utils.export_data_filename_with_timestamp(
        f"{output_dir}Tamnoon-Azure-Storage-{asset_type if asset_type != None else ''}-{action.replace('_', '-') if action != None else ''}-{result_type}-result.{output_type}",
        output_type,
    )
    utils.export_data(
        result["stateFile"],
        result,
        export_format=(output_type),
    )
    print()
    print(f"find logs in {os.path.abspath(result['stateFile'])}")
