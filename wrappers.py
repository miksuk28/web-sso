from functools import wraps
from flask import jsonify, request
from jsonschema import validate, ValidationError

def json_validator(schema, *args, **kwargs):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            json_data = request.get_json()

            if json_data == {}:
                return jsonify({"error": "No JSON data"}), 400
            
            try:
                validate(instance=json_data, schema=schema)
            except ValidationError as e:
                return jsonify({"error": "JSON validation error", "errorMessage": e.message, "expectedSchema": schema}), 400

            return f(*args, **kwargs)

        return wrapper

    return decorator


def authentcate(admin=False, *args, **kwargs):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("token")

            if token is None or token == "":
                return jsonify({"error": "Token header is missing"})
            
            