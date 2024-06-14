import argparse
import json
import logging
import sys
import os
import datetime

from library.Utils import utils as utils
from library.DBServer.DBAction import DBTypes, cli_type_mapping
from . import RestrictFirewallRules


try:
    from Azure.Automations.DBServer import help_jsons_data as help_jsons_data
except ModuleNotFoundError:
    help_jsons_data = {}
mysql_server_enable_auditing = (
    help_jsons_data.mysql_server_enable_auditing
    if hasattr(help_jsons_data, "mysql_server_enable_auditing")
    else dict()
)
mysql_server_restrict_firewall_rules = (
    (help_jsons_data.mysql_server_restrict_firewall_rules)
    if hasattr(help_jsons_data, "mysql_server_restrict_firewall_rules")
    else dict()
)
sql_server_enable_auditing = (
    help_jsons_data.sql_server_enable_auditing
    if hasattr(help_jsons_data, "sql_server_enable_auditing")
    else dict()
)
sql_server_restrict_firewall_rules = (
    help_jsons_data.sql_server_restrict_firewall_rules
    if hasattr(help_jsons_data, "sql_server_restrict_firewall_rules")
    else dict()
)
postgresql_server_restrict_firewall_rules = (
    (help_jsons_data.postgresql_server_restrict_firewall_rules)
    if hasattr(help_jsons_data, "postgresql_server_restrict_firewall_rules")
    else dict()
)
postgresql_server_enable_auditing = (
    (help_jsons_data.postgresql_server_enable_auditing)
    if hasattr(help_jsons_data, "postgresql_server_enable_auditing")
    else dict()
)
common_json_data = (
    help_jsons_data.common_json_data
    if hasattr(help_jsons_data, "common_json_data")
    else dict()
)


def do_restrict_firewall_rules_action(
    credential,
    subscriptions,
    resource_groups,
    regions,
    asset_ids,
    action_params,
    dry_run,
    server_type=DBTypes.SQL,
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

    if RestrictFirewallRules.validate_action_params(action_params):
        is_roll_back = "rollBack" in action_params and action_params["rollBack"]
        if is_roll_back:
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
        if is_roll_back:
            return RestrictFirewallRules.rollback_restrict_firewall_rules(
                credential=credential,
                dry_run=dry_run,
                last_execution_result_path=action_params["lastExecutionResultPath"],
                server_type=server_type,
            )
        if subscriptions == [None]:
            raise ValueError("--subscription is required")
        return RestrictFirewallRules.restrict_firewall_rules(
            credential=credential,
            action_params=action_params,
            subscriptions=subscriptions,
            resource_groups=resource_groups,
            regions=regions,
            server_names=asset_ids,
            server_type=server_type,
            dry_run=dry_run,
        )


def do_enable_auditing_action(
    credential,
    subscriptions,
    resource_groups,
    regions,
    asset_ids,
    action_params,
    dry_run,
    server_type=DBTypes.SQL,
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
    from . import EnableAuditing

    if EnableAuditing.validate_action_params(server_type, action_params):
        is_roll_back = "rollBack" in action_params and action_params["rollBack"]
        if is_roll_back:
            is_roll_back = "rollBack" in action_params and action_params["rollBack"]
        if is_roll_back:
            return EnableAuditing.rollback_enable_auditing(
                credential=credential,
                dry_run=dry_run,
                last_execution_result_path=action_params["lastExecutionResultPath"],
            )
        if subscriptions == [None]:
            raise ValueError("--subscription is required")
        if hasattr(
            EnableAuditing,
            f'enable_auditing_{server_type.value.replace("-", "_")}_server',
        ):
            enable_auditing = getattr(
                EnableAuditing,
                f'enable_auditing_{server_type.value.replace("-", "_")}_server',
            )
            return enable_auditing(
                credential=credential,
                action_params=action_params,
                subscriptions=subscriptions,
                resource_groups=resource_groups,
                regions=regions,
                server_names=asset_ids,
                dry_run=dry_run,
            )

    return []


def common_args(parser, args_json_data):
    parser.add_argument(
        "--subscription",
        required=False,
        metavar="",
        help=args_json_data.get("subscription"),
        type=str,
        default=None
    )
    parser.add_argument(
        "--resourceGroups",
        required=False,
        metavar="",
        help=args_json_data.get("resourceGroups"),
        type=str,
        default="all",
    )
    parser.add_argument(
        "--regions",
        required=False,
        metavar="",
        help=args_json_data.get("regions"),
        type=str,
        default="all",
    )
    parser.add_argument(
        "--assetIds",
        required=False,
        metavar="",
        help=args_json_data.get("assetIds"),
        type=str,
        default="all",
    )

    parser.add_argument(
        "--actionParams",
        required=False,
        metavar="",
        help=args_json_data.get("actionParams"),
        type=utils.TypeActionParams,
        default=dict(),
    )

    parser.add_argument(
        "--logLevel",
        required=False,
        metavar="",
        help=args_json_data.get("logLevel"),
        type=str,
        default="INFO",
    )
    parser.add_argument(
        "--dryRun",
        required=False,
        help=args_json_data.get("dryRun"),
        action="store_true",
        default=False,
    )

    parser.add_argument(
        "--file",
        required=False,
        metavar="",
        help=args_json_data.get("file"),
        type=str,
        default=None,
    )
    parser.add_argument(
        "--outputType",
        required=False,
        metavar="",
        help=args_json_data.get("outputType"),
        type=str,
        default="json",
    )
    parser.add_argument(
        "--outDir",
        required=False,
        metavar="",
        help=args_json_data.get("outDir"),
        type=str,
        default="./",
    )
    parser.add_argument(
        "--testId",
        required=False,
        metavar="",
        help=args_json_data.get("testId"),
        type=str,
    )


def main(argv=[]):
    functions_mapping = {
        "sql-server": {
            "enable_auditing": do_enable_auditing_action,
            "restrict_firewall_rules": do_restrict_firewall_rules_action,
        },
        "mysql-server": {
            "enable_auditing": do_enable_auditing_action,
            "restrict_firewall_rules": do_restrict_firewall_rules_action,
        },
        "postgresql-server": {
            "enable_auditing": do_enable_auditing_action,
            "restrict_firewall_rules": do_restrict_firewall_rules_action,
        },
    }

    help_mapping = {
        "sql-server": {
            "restrict_firewall_rules": sql_server_restrict_firewall_rules.get("help"),
            "enable_auditing": sql_server_enable_auditing.get("help"),
        },
        "mysql-server": {
            "enable_auditing": mysql_server_enable_auditing.get("help"),
            "restrict_firewall_rules": mysql_server_restrict_firewall_rules.get("help"),
        },
        "postgresql-server": {
            "enable_auditing": postgresql_server_enable_auditing.get("help"),
            "restrict_firewall_rules": postgresql_server_restrict_firewall_rules.get(
                "help"
            ),
        },
    }

    # usage text in cli help
    parser_usage = common_json_data.get("usage", {}).get(
        "DBServer", "python3 -m Automations.DBServer"
    )
    usage = parser_usage + " [-h]"

    # command line arguments
    if argv == []:
        argv = sys.argv
    if len(argv) == 2 and ("--help" in argv or "-h" in argv):
        # default help if no arguments are provided in command
        utils.print_help_valid_types(
            common_json_data.get("help", {}).get("DBServer"), usage
        )
        sys.exit(1)

    # create a argument parser
    parser = argparse.ArgumentParser(usage=parser_usage)

    # define asset type here
    type_subparsers = parser.add_subparsers(
        title="type", metavar="", dest="type")
    sql_server_parser = type_subparsers.add_parser(
        name="sql-server", formatter_class=argparse.RawTextHelpFormatter
    )
    mysql_server_parser = type_subparsers.add_parser(
        name="mysql-server", formatter_class=argparse.RawTextHelpFormatter
    )
    postgresql_server_parser = type_subparsers.add_parser(
        name="postgresql-server", formatter_class=argparse.RawTextHelpFormatter
    )

    # define actions of sql-server asset type here
    sql_server_actions = sql_server_parser.add_subparsers(
        title="action",
        metavar="",
        dest="action",
        description=utils.type_help(help_mapping["sql-server"]),
    )
    # sql-server restrict_firewall_rules command line arguments
    sql_server_action_restrict_firewall_rules = sql_server_actions.add_parser(
        name="restrict_firewall_rules",
        description=sql_server_restrict_firewall_rules.get("help"),
    )
    sql_server_action_restrict_firewall_rules._optionals.title = "arguments"
    common_args(
        sql_server_action_restrict_firewall_rules,
        sql_server_restrict_firewall_rules.get("cli_args", {})
    )
    # sql-server enable_auditing command line arguments
    sql_server_action_enable_auditing = sql_server_actions.add_parser(
        name="enable_auditing", description=sql_server_enable_auditing.get("help")
    )
    sql_server_action_enable_auditing._optionals.title = "arguments"
    common_args(
        sql_server_action_enable_auditing,
        sql_server_enable_auditing.get("cli_args", {})
    )

    # define actions of mysql-server asset type here
    mysql_server_actions = mysql_server_parser.add_subparsers(
        title="action",
        metavar="",
        dest="action",
        description=utils.type_help(help_mapping["mysql-server"]),
    )
    # mysql-server restrict_firewall_rules command line arguments
    mysql_server_action_restrict_firewall_rules = mysql_server_actions.add_parser(
        name="restrict_firewall_rules",
        description=mysql_server_restrict_firewall_rules.get("help"),
    )
    mysql_server_action_restrict_firewall_rules._optionals.title = "arguments"
    common_args(
        mysql_server_action_restrict_firewall_rules,
        mysql_server_restrict_firewall_rules.get("cli_args", {})
    )
    # mysql-server enable_auditing command line arguments
    mysql_server_action_enable_auditing = mysql_server_actions.add_parser(
        name="enable_auditing",
        description=mysql_server_enable_auditing.get("help"),
    )
    mysql_server_action_enable_auditing._optionals.title = "arguments"
    common_args(
        mysql_server_action_enable_auditing,
        mysql_server_enable_auditing.get("cli_args", {})
    )

    # define actions of postgresql-server asset type here
    postgresql_server_actions = postgresql_server_parser.add_subparsers(
        title="action",
        metavar="",
        dest="action",
        description=utils.type_help(help_mapping["postgresql-server"]),
    )
    # postgresql-server restrict_firewall_rules command line arguments
    postgresql_server_action_restrict_firewall_rules = (
        postgresql_server_actions.add_parser(
            name="restrict_firewall_rules",
            description=postgresql_server_restrict_firewall_rules.get("help"),
        )
    )
    postgresql_server_action_restrict_firewall_rules._optionals.title = "arguments"
    common_args(
        postgresql_server_action_restrict_firewall_rules,
        postgresql_server_restrict_firewall_rules.get("cli_args", {})
    )
    # postgresql-server enable_auditing command line arguments
    postgresql_server_action_enable_auditing = postgresql_server_actions.add_parser(
        name="enable_auditing",
        description=postgresql_server_enable_auditing.get("help"),
    )
    postgresql_server_action_enable_auditing._optionals.title = "arguments"
    common_args(
        postgresql_server_action_enable_auditing,
        postgresql_server_enable_auditing.get("cli_args", {})
    )

    # initialize args
    cli_args = parser.parse_args(argv[1:])
    params = utils.build_params(args=cli_args)

    asset_type = cli_args.type
    action = cli_args.action
    asset_ids = (
        params.assetIds.split(",")
        if cli_args.file is None
        else params.get("assetIds", ["all"])
    )

    action_params = (
        params.actionParams if cli_args.file is None else params.get(
            "actionParams", {})
    )
    if isinstance(action_params, str):
        action_params = json.loads(action_params)
    elif action_params is None:
        action_params = {}
    dry_run = (
        params.dryRun if cli_args.file is None else params.get("dryRun", "")
    )
    output_type = (
        params.outputType if cli_args.file is None else params.get(
            "outputType", "JSON")
    )
    output_dir = params.outDir if cli_args.file is None else params.get(
        "outDir", "./")
    subscription = params.subscription if cli_args.file is None else params.get(
        "subscription", "")
    resource_groups = (
        params.resourceGroups.split(",")
        if cli_args.file is None
        else params.get("resourceGroups", ["all"])
    )
    test_id = params.testId if cli_args.file is None else params.get("testId")

    regions = (
        params.regions.split(",")
        if cli_args.file is None
        else params.get("regions", ["all"])
    )

    # setup log
    log_level = params.logLevel if cli_args.file is None else params.get(
        "logLevel", "INFO")
    utils.log_setup(log_level)
    # setup session
    credential = utils.setup_session("default")
    # initialize result
    result = dict(
        {
            "executionDate": datetime.datetime.now().ctime(),
            "executionType": asset_type,
            "executionAction": action,
            "executionResult": [],
            "actionParams": action_params,
        }
    )
    if test_id:
        result["testId"] = test_id

    do_action = functions_mapping[asset_type][action]
    result["executionResult"] = do_action(
        credential=credential,
        subscriptions=[subscription],
        resource_groups=resource_groups,
        regions=regions,
        asset_ids=asset_ids,
        action_params=action_params,
        dry_run=dry_run,
        server_type=cli_type_mapping[asset_type],
    )

    # prepare filepath and filename to store output
    result_type = "dryrun" if dry_run else "execution"
    if not output_dir.endswith("/"):
        output_dir = output_dir + "/"
    result["stateFile"] = utils.export_data_filename_with_timestamp(
        f"{output_dir}Tamnoon-Azure-Storage-{asset_type if asset_type is not None else ''}-{action.replace('_', '-') if action != None else ''}-{result_type}-result.{output_type}",
        output_type,
    )
    utils.export_data(
        result["stateFile"],
        result,
        export_format=(output_type),
    )
    logging.info(f"find logs in {os.path.abspath(result['stateFile'])}")


if __name__ == "__main__":
    main(sys.argv)
