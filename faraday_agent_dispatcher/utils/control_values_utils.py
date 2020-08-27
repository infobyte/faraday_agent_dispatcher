def control_int(nullable=False):
    def control(field_name, value):
        if value is None and nullable:
            return
        if value is None:
            raise ValueError(
                f"Trying to parse {field_name} with None value and should be "
                "an int"
            )
        try:
            int(value)
        except ValueError:
            raise ValueError(
                f"Trying to parse {field_name} with value {value} and should "
                "be an int")

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
            raise ValueError(
                f"Trying to parse {field_name} with value {value} and should "
                "be a list"
            )
        listt = value.split(",")
        if len(listt) != len(set(listt)):
            raise ValueError(
                f"Trying to parse {field_name} with value {value} and "
                f"contains repeated values"
            )

    return control


def control_bool(field_name, value):
    if str(value).lower() not in ["true", "false", "t", "f"]:
        raise ValueError(
            f"Trying to parse {field_name} with value {value} and should be a "
            f"bool"
        )


def control_registration_token(field_name, value):
    if value is None:
        raise ValueError(
            f'"{field_name}" option is required in the configuration file'
        )
    control_token(field_name, 25, value)


def control_agent_token(field_name, value):
    if value is not None:
        control_token(field_name, 64, value)


def control_token(field_name, size: int, value: str):
    if not value.isalnum():
        raise ValueError(f"{field_name} must be alphanumeric")
    if len(value) != size:
        raise ValueError(f"{field_name} must be {size} character length")
