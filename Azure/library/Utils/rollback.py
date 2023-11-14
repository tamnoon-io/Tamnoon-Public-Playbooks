import logging


def serialize_rollback_actions(actions) -> [dict]:
    """
    depth first function
    the last deepest result should get rollback/revert/undo first
    so as to not losing them in the hierarchy of Cloud Resources.

    :return: [dict]
    """
    rollback_actions = []
    for action in actions:
        if action != None:
            # first process ExecutionResultData, then process current action data
            if ("ExecutionResultData" in action) and (
                action["ExecutionResultData"] != None
            ):
                if ("ResultType" in action["ExecutionResultData"]) and (
                    action["ExecutionResultData"]["ResultType"] == "list"
                ):
                    jsonResult = action["ExecutionResultData"]["Result"]
                    jsonResult.reverse()
                    rollback_actions.extend(serialize_rollback_actions(jsonResult))
                    action["ExecutionResultData"] = None
                elif ("ResultType" in action["ExecutionResultData"]) and action[
                    "ExecutionResultData"
                ]["ResultType"] == "object":
                    # assuming that object does not have nested "ExecutionResultData"
                    rollback_actions.append(action)
                elif ("ResultType" in action["ExecutionResultData"]) and action[
                    "ExecutionResultData"
                ]["ResultType"] == "string":
                    # skipping execution result which is string
                    action["ExecutionResultData"]["Result"]

            elif (
                ("Asset" in action)
                and ("Type" in action["Asset"])
                and action["Asset"]["Type"] == "assetId"
            ):
                rollback_actions.extend(
                    serialize_rollback_actions(action["ExecutionResultData"])
                )
    return rollback_actions
