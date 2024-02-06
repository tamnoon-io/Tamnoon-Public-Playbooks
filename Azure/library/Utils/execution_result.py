class ExecutionResult:
    asset = None
    status = None
    result_type = None
    result = None
    dry_run = True

    def load(value):
        result = ExecutionResult(
            value["Asset"]["Id"],
            value["Asset"]["Name"],
            value["Asset"]["Type"],
            value["Asset"]["Action"],
            value["Asset"]["CloudAccountId"],
            value["Asset"]["CloudProvider"],
            value["Asset"]["Region"],
        )
        result.status = value["ActionStatus"]
        result.result_type = value["ExecutionResultData"]["ResultType"]
        if result.result_type == "string" or result.result_type == "object":
            result.result_type = value["ExecutionResultData"]["Result"]
        elif result.resource_type == "list":
            result.result.extend(
                list(map(lambda result_item: ExecutionResult.load(result_item)))
            )
            if result.status != value["ActionStatus"]:
                # warning: loaded value do not represent correct status or result
                pass
        return result

    def __init__(
        self,
        resource_id,
        resource_name,
        resource_type,
        action,
        cloud_account_id,
        cloud_provider,
        region,
        dry_run=True,
    ):
        self.asset = dict(
            {
                "Id": resource_id,
                "Name": resource_name,
                "Type": resource_type,
                "Action": action,
                "CloudAccountId": cloud_account_id,
                "CloudProvider": cloud_provider,
                "Region": region,
            }
        )
        self.dry_run = dry_run
        self.status = "dryrun" if dry_run else "success"

    def set_asset(
        self,
        resource_id,
        resource_name,
        resource_type,
    ):
        self.asset["Id"] = resource_id
        self.asset["Name"] = resource_name
        self.asset["Type"] = resource_type

    def get_execution_result_data(
        self,
    ):
        return dict(
            {
                "ResultType": self.result_type,
                "Result": list(map(lambda item: item.as_dict(), self.result))
                if self.result_type == "list"
                else self.result,
            }
        )

    def set_string_result(self, status, message):
        self.result_type = "string"
        self.status = status
        self.result = message

    def set_dict_result(self, status, prev_state, current_state):
        self.result_type = "object"
        self.status = status
        self.result = dict(
            {
                "prev_state": prev_state,
                "current_state": current_state,
            }
        )

    def append_result_to_list(self, value):
        if self.dry_run:
            self.status = "dryrun"
        else:
            self.status = (
                "success"
                if value.status == "success" or self.get_status() == "success"
                else "fail"
            )
        if self.result_type != "list":
            self.result = []
        self.result_type = "list"
        if self.result == None:
            self.result = [value]
        else:
            self.result.append(value)

    def extend_result_to_list(self, value):
        for i in value:
            self.append_result_to_list(value)

    def as_dict(
        self,
    ):
        return dict(
            {
                "Asset": self.asset,
                "ActionStatus": self.status,
                "ExecutionResultData": self.get_execution_result_data(),
            }
        )

    def get_status(self):
        if self.dry_run:
            self.status = "dryrun"
            return self.status
        if self.result_type == "string" or self.result_type == "object":
            return self.status
        if self.result_type == "list":
            is_success = True
            for i in self.result:
                is_success = is_success and i.get_status() == "success"
                if not is_success:
                    return "fail"
            return "success"


class AzureExecutionResult(ExecutionResult):
    def __init__(self, id, name, type, action, cloud_account_id, region, dry_run=True):
        super().__init__(
            id, name, type, action, cloud_account_id, "azure", region, dry_run
        )

    def load(value):
        result = ExecutionResult.load(value)
        result.__class__ = AzureExecutionResult
        return result
