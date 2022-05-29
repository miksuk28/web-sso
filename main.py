from flask import Flask, request, jsonify, abort
from waitress import serve
from config import config
from secret_config import secrets
from db import UsersDatabaseWrapper
import db_exceptions as exc
from psycopg2 import Error
from datetime import datetime, timezone
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


@app.route("/authenticate")
@json_validator(schema=JSONSchemas.login)
def authenticate():
    json_data = request.get_json()
    
    try:
        access_token, expiration = db.login(json_data.get("username"), json_data.get("password"))
        return jsonify({"token": access_token, "exp": expiration, "iat": datetime.now(timezone.utc).timestamp()})

    except exc.UserDoesNotExist:
        return jsonify({"error": f"User {json_data.get('username')} does not exist"}), 404
    
    except exc.IncorrectPassword:
        return jsonify({"error": f"Incorrect password for {json_data.get('username')}"}), 403

    except Exception as e:
        print(e)
        return abort(500)


@app.route("/admin/users", methods=["POST"])
def users():
    if request.method == "GET":
        pass



if __name__ == "__main__":
    if config["debug"]:
        print("RUNNING WITH DEBUG SERVER - DO NOT USE IN PRODUCTION\n")
        app.run(debug=config["debug"], host=config["address"], port=config["port"])
    else:
        print("Auth Server running With Production Server")
        serve(app, host=config["address"], port=config["port"])