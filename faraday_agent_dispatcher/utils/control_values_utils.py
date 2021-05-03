def control_int(nullable=False):
    def control(field_name, value):
        if value is None and nullable:
            return
        if value is None:
            raise ValueError(f"Trying to parse {field_name} with None value and should be " "an int")
        try:
            int(value)
        except ValueError:
            raise ValueError(f"Trying to parse {field_name} with value {value} and should " "be an int")

    return control


def control_str(nullable=False):
    def control(field_name, value):
        if value is None and nullable:
            return
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")

    return control


def control_host(field_name, value):
    control_str()(field_name, value)


def control_list(can_repeat=True):
    def control(field_name, value):
        if not isinstance(value, str):
            raise ValueError(f"Trying to parse {field_name} with value {value} and should " "be a list")
        listt = value.split(",")
        if len(listt) != len(set(listt)):
            raise ValueError(f"Trying to parse {field_name} with value {value} and " f"contains repeated values")

    return control


def control_bool(field_name, value):
    if str(value).lower() not in ["true", "false", "t", "f"]:
        raise ValueError(f"Trying to parse {field_name} with value {value} and should be a " f"bool")


def control_registration_token(field_name: str, value: str):
    if value is None:
        raise ValueError("No connected before, provide a token. For more help see `faraday-dispatcher run --help`")
    if not value.isnumeric():
        raise ValueError(f"{field_name} must be a number")
    control_token(field_name, 6, value)


def control_agent_token(field_name, value):
    if value is not None:
        control_token(field_name, 64, value)


def control_token(field_name, size: int, value: str):
    if not value.isalnum():
        raise ValueError(f"{field_name} must be alphanumeric")
    if len(value) != size:
        raise ValueError(f"{field_name} must be {size} character length")


def control_executors(field_name, value):
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a dictionary")

    for e_name, e_value in value.items():

        if "max_size" not in e_value:
            raise ValueError(f"Missing max_size in {e_name}")
        if "repo_executor" not in e_value and "cmd" not in e_value:
            raise ValueError(f"repo_executor or cmd missing in {e_value}")
        if "varenvs" not in e_value:
            raise ValueError(f"varenvs section missing in {e_value}")
        if "params" in e_value:
            control_param(e_value["params"])
        else:
            raise ValueError(f"params section missing in {e_value}")


def control_param(params):
    for param, param_val in params.items():
        if not isinstance(param_val, dict):
            raise ValueError(f"{param} must be a dictionary")
        if not isinstance(param_val.get("mandatory"), bool):
            raise ValueError(f"{param} mandatory field missing or not boolean")
        if not isinstance(param_val.get("type"), str):
            raise ValueError(f"{param} type field missing or not string")
