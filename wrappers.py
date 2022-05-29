from functools import wraps
from flask import jsonify, request
from jsonschema import validate, ValidationError
from datetime import datetime, timezone

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


def authenticate(db, *args, **kwargs):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("token")

            if token is None or token == "":
                return jsonify({"error", "Token header is missing"}), 400
            else:

                db_token = db.validate_token(token)
                if db_token is None:
                    return jsonify({"error": "Token is not valid"}), 401

                if db_token["expiration"].timestamp() <= datetime.now(timezone.utc).timestamp():
                    return jsonify({"error": "Token has expired. Please sign in again"}), 401
                else:
                    return f(access_token=token, user=db_token["username"], *args, **kwargs)
        
        return wrapper
    return decorator


def require_admin(db, *args, **kwargs):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("token")

            if token is None or token == "":
                return jsonify({"error": "Token header is missing"}), 400
            else:

                db_token = db.validate_token(token)
                if db_token is None:
                    return jsonify({"error": "Token is not valid"}), 401

                if db_token["expiration"].timestamp() <= datetime.now(timezone.utc).timestamp():
                    return jsonify({"error": "Token has expired. Please sign in again"}), 401
                else:
                    if db._is_admin(db_token["username"]):
                        return f(access_token=token, user=db_token["username"], admin=True,*args, **kwargs)
                    else:
                        return jsonify({"error": "Access denied"}), 403
        return wrapper
    return decorator
