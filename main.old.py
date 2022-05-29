from flask import Flask, request, jsonify, abort
from waitress import serve
from secret_config import secrets
from config import config
from db import UsersDatabaseWrapper
import db_exceptions as exc
from psycopg2 import Error
from datetime import datetime, timezone
from wrappers import json_validator, require_admin
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


@app.route("/authenticate", methods=["POST"])
@json_validator(schema=JSONSchemas.login)
def authenticate():
    data = request.get_json()

    try:
        access_token, expiration = db.login(username=data["username"], password=data["password"])
        return jsonify({"token": access_token, "exp": expiration})

    except exc.UserDoesNotExist:
        return jsonify({"error": "User does not exist"}), 404
    
    except exc.IncorrectPassword:
        return jsonify({"error": "Incorrect password"}), 403

    except Exception as e:
        print(e)
        return abort(500)


@app.route("/user", methods=["POST"])
@json_validator(schema=JSONSchemas.register)
@require_admin(db)
def create_user(*args, **kwargs):
    data = request.get_json()

    if not db._check_if_user_exists(data["username"]):
        if data["username"] not in config["disallowed_usernames"]:
            if data.get("blockLogin") is None:
                data["blockLogin"] = False

            if data.get("blockLoginReason") is None:
                data["blockLoginReason"] = False

            db.create_user(
                username=data["username"],
                password=data["password"],
                fname=data.get("fname"),
                lname=data.get("lname"),
                block_login=data.get("blockLogin"),
                block_login_reason=data.get("blockLoginReason")
            )

            return jsonify({"message": f"User {data['username']} created successfully"}), 201

        else:
            return jsonify({"error": f"Username {data['username']} is not allowed"}), 409
    else:
        return jsonify({"error": f"User {data['username']} already existss"}), 409


@app.route("/user/<user_id>", methods=["GET"])
@require_admin(db)
def get_user(user_id, *args, **kwargs):
    if request.method == "GET":
        try:
            user_info = db.get_user(user_id)

            return jsonify(user_info)

        except exc.UserDoesNotExist:
            return jsonify({"error": f"User with id {user_id} does not exist"}), 404
        
        except Exception as e:
            print(e)
            return abort(500)


@app.route("/user/<user_id>", methods=["DELETE"])
@require_admin(db)
def delete_user(user_id, *args, **kwargs):
    try:
        db.delete_user(user_id)

        return jsonify({"message": f"User {user_id} has been deleted"}), 200
    except exc.UserDoesNotExist:
        return jsonify({"error": f"Usere {user_id} does not exist"}), 404


@app.route("/users", methods=["DELETE"])
@json_validator(schema=JSONSchemas.delete_users)
@require_admin(db)
def delete_users(*args, **kwargs):
    users = request.get_json().get("usersToDelete")

    not_exist = []
    deleted = []
    for user in users:
        try:
            db.delete_user(user)
            deleted.append(user)
        except exc.UserDoesNotExist:
            not_exist.append(user)
            continue

    return jsonify({"message": "Operation Completed", "deletedUsers": deleted, "notFound": not_exist})


@app.route("/users", methods=["GET"])
@require_admin(db)
def get_all_users(*args, **kwargs):
    try:
        users = db.get_all_users()
        return jsonify({"users": users}), 200

    except Exception as e:
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
    return jsonify({"error": "An unknown error has occured. Please try again. If the error persistst, contact the administrator"})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "The current endpoint cannot be found on the server"})

if __name__ == "__main__":
    if config["debug"]:
        print("RUNNING WITH DEBUG SERVER - DO NOT USE IN PRODUCTION\n")
        app.run(debug=config["debug"], host=config["address"], port=config["port"])
    else:
        print("Auth Server running With Production Server")
        serve(app, host=config["address"], port=config["port"])