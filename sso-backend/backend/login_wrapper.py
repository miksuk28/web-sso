from functools import wraps
from config import config
from secret_config import secrets
from flask import request, jsonify
from db.db_exceptions import *
from db.db import UsersDatabaseWrapper

db = UsersDatabaseWrapper(config=config, secret_config=secrets)

# Authentication decorator
def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("token")

        try:
            payload = db.auth(token)

        except TokenExpired:
            return jsonify({"error": "Token expired. Please login again"}), 401

        except TokenInvalid:
            return jsonify({"error": "Token invalid. Please login again"}), 401

        # Catch all
        except Exception as e:
            print(e)
            return jsonify({"error": "An internal server error has occured. Please contact the admin"}), 500

        if config["debug"]:
            print(f"\nPayload: {payload}\n")
            print(f"Expiration: {payload['expiration']}")
        
        kwargs["payload"] = payload
        kwargs["headers"] = request.headers

        # Data gets passed back into public original function and run
        return func(*args, **kwargs)
    
    return decorated_function
