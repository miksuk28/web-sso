from flask import Flask, request, jsonify, abort
from waitress import serve
from secret_config import secrets
from config import config
from db import UsersDatabaseWrapper
import db_exceptions as exc
import verification
from psycopg2 import Error

from wrappers import json_validator
from json_schemas import JSONSchemas

app = Flask(__name__)

db = UsersDatabaseWrapper(
    token_validity=config["token_validity"],
    username=secrets["pg_db_user"],
    password=secrets["pg_db_user_password"],
    address=secrets["pg_ip"],
    database=secrets["pg_db"],
    secret_key=secrets["SECRET_KEY"],
    global_token_block=config["global_token_block"]
)

@app.route("/login", methods=["POST"])
@json_validator(schema=JSONSchemas.login)
def login():
    data = request.get_json()

    try:
        token, expiration = db.login(username=data["username"], password=data["password"])
        return jsonify({"token": token, "exp": expiration})

    except exc.UserDoesNotExist:
        return jsonify({"error": "User does exist"}), 404
    
    except exc.IncorrectPassword:
        return jsonify({"error": "Incorrect password"}), 403

    except Error as e:
        print(e)
        return abort(500)


# Only to be called by backends
@app.route("/validate", methods=["GET"])
def validate_token():
    token = request.headers.get("token", None)

    if request.headers.get("X-Forwarded-For", None) is not None:
        return abort(403)

    if token is None or token == "":
        return jsonify({"error": "token header is missing"}), 400
    
    try:
        payload = db._decode_token(token)
        return jsonify({"message": "Token is valid", "payload": payload}), 200

    except exc.ExpiredToken:
        return jsonify({"error": "Access token has expired"}), 401

    except exc.InvalidToken:
        return jsonify({"error": "Invalid token"}), 401

    except Error as e:
        print(e)
        return abort(500)


@app.route("/user", methods=["POST"])
@json_validator(schema=JSONSchemas.register)
def create_user():
    token = request.headers.get("token", None)

    if request.headers.get("X-Forwarded-For", None) is not None:
        return abort(403)

    elif token is None or token == "":
        return jsonify({"error": "token header is missing"}), 400


    try:
        payload = db._decode_token(token)
        
        if payload["admin"] != True or 1:
            return abort(403)
        else:
            pass

    except exc.ExpiredToken:
        return jsonify({"error": "Access token has expired"}), 401

    except exc.InvalidToken:
        return jsonify({"error": "Invalid token"}), 401

    except Error as e:
        print(e)
        return abort(500)



@app.route("/user/<user_id>", methods=["GET"])
def get_ser(user_id):
    if request.headers.get("X-Forwarded-For", None) is not None:
        return abort(403)
    else:
        if request.headers.get("USER_INFO_KEY", None) != secrets["USER_INFO_KEY"]:
            return jsonify({"error": "USER_INFO_KEY header missing or incorrect"}), 403
            
        else:
            try:
                user_info = db.get_user(user_id)

                return jsonify(user_info)

            except exc.UserDoesNotExist:
                return jsonify({"error": f"User with id {user_id} does not exist"}), 404
            
            except Error as e:
                print(e)
                return abort(500)



@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed for this endpoint"}), 405

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request. Does the body contain valid JSON?"}), 400

@app.errorhandler(403)
def access_denied(e):
    return jsonify({"error": "Access denied"}), 403


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "An unknown error has occured. Please try again"})


if __name__ == "__main__":
    if config["debug"]:
        print("RUNNING WITH DEBUG SERVER - DO NOT USE IN PRODUCTION\n")
        app.run(debug=config["debug"], host=config["address"], port=config["port"])
    else:
        print("Auth Server running With Production Server")
        serve(app, host=config["address"], port=config["port"])