
def control_int(field_name,value):
    try:
        int(value)
    except ValueError:
        raise ValueError(f"Trying to parse {field_name} with value {value} and should be an int")


def control_str(field_name, value):
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


def control_host(field_name, value):
    control_str(field_name, value)


def control_registration_token(field_name, value):
    if value is None:
        raise ValueError(f'"{field_name}" option is required in the configuration '
                         f"file")
    control_token(field_name, 25, value)


def control_agent_token(field_name, value):
    if value is not None:
        control_token(field_name, 64, value)


def control_token(field_name, size: int, value: str):
    if not value.isalnum():
        raise ValueError(f"{field_name} must be alphanumeric")
    if len(value) != size:
        raise ValueError(f"{field_name} must be {size} character length")
