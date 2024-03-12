from marshmallow import fields, schema, ValidationError, validates_schema


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
        if not isinstance(value, list):
            raise ValueError(f"Trying to parse {field_name} with value {value} and should " "be a list")
        if len(value) != len(set(value)) and not can_repeat:
            raise ValueError(f"Trying to parse {field_name} with value {value} and " f"contains repeated values")

    return control


def control_bool(field_name, value):
    if str(value).lower() not in ["true", "false", "t", "f"]:
        raise ValueError(f"Trying to parse {field_name} with value {value} and should be a " f"bool")


def control_registration_token(field_name: str, value: str):
    if value is None:
        raise ValueError("No connected before, provide a token. For more " "help see `faraday-dispatcher run --help`")
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
    for executor in value.values():
        errors = ExecutorSchema().validate(executor)
        if errors:
            raise ValueError(errors)


class ParamsField(fields.Field):
    def _deserialize(self, value, attr, data, **kwargs):
        if not isinstance(value, dict):
            raise ValidationError(f"{value} must be a dictionary")
        for param, param_val in value.items():
            if not isinstance(param_val, dict):
                raise ValidationError(f"{param} must be a dictionary")
            if not isinstance(param_val.get("mandatory"), bool):
                raise ValidationError(f'{param} - "mandatory" field missing or not boolean')
            if not isinstance(param_val.get("type"), str) and not isinstance(param_val.get("type"), list):
                raise ValidationError(f'{param} - "type" field missing or not string/list')
            if not isinstance(param_val.get("base"), str):
                raise ValidationError(f'{param} - "base" field missing or not string')


class ExecutorSchema(schema.Schema):
    max_size = fields.Integer(required=True)
    repo_executor = fields.String()
    repo_name = fields.String()
    cmd = fields.String()
    varenvs = fields.Dict(required=True)
    params = ParamsField(required=True)

    @validates_schema
    def validate_cmd_repo(self, data, **kwargs):
        if "cmd" not in data and "repo_executor" not in data:
            raise ValidationError('"repo_executor" or "cmd" field needed')


class ParamsSchema(schema.Schema):
    params = ParamsField(required=True)
