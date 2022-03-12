import db_exceptions as exc

def validate(keys, dict):
    for key in keys:
        value = dict.get(key, None)

        if value is None or value == "":
            raise exc.MissingValue(key)