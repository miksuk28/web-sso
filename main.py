import code
from crypt import methods
from flask import Flask, request, jsonify
from waitress import serve
from secret_config import secrets
from config import config
from db import UsersDatabaseWrapper
import db_exceptions as exc
import verification
from sqlite3 import Error
from flask import make_response

app = Flask(__name__)

db = UsersDatabaseWrapper(
    db_file=config["db_file"],
    token_validity=config["token_validity"],
    secret_key=secrets["SECRET_KEY"],
    global_token_block=config["global_token_block"]
)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    try:
        # raises exc.MissingValue if values are missing or blank
        verification.validate(("username", "password"), data)

        token, expiration = db.login(username=data["username"], password=data["password"])
        return jsonify({"token": token, "exp": expiration})

    except exc.MissingValue as Err:
        return jsonify({"error": f"{Err.args[0]} is missing"}), 400
    
    except exc.UserDoesNotExist:
        return jsonify({"error": "User does exist"}), 404
    
    except exc.IncorrectPassword:
        return jsonify({"error": "Incorrect password"}), 403

    except Error as e:
        print(e)
        return jsonify({"error": "An unknown error has occured. Please try again"}), 500


# Only to be called by backends
@app.route("/validate", methods=["GET"])
def validate_token():
    token = request.headers.get("token", None)

    if request.headers.get("X-Forwarded-For", None) is not None:
        return jsonify({"error": "Access Denied"}), 403

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
        return jsonify({"error": "An unknown error has occured. Please try again"}), 500


@app.route("/user", methods=["POST"])
def create_user():
    token = request.headers.get("token", None)

    if request.headers.get("X-Forwarded-For", None) is not None:
        return jsonify({"error": "Access Denied"}), 403

    elif token is None or token == "":
        return jsonify({"error": "token header is missing"}), 400


    try:
        payload = db._decode_token(token)
        
        if payload["admin"] != True or 1:
            return jsonify({"error": "Access Denied. You are not admin"}), 403
        else:
            pass

    except exc.ExpiredToken:
        return jsonify({"error": "Access token has expired"}), 401

    except exc.InvalidToken:
        return jsonify({"error": "Invalid token"}), 401

    except Error as e:
        print(e)
        return jsonify({"error": "An unknown error has occured. Please try again"}), 500


@app.route("/user/<user>", methods=["GET"])
def get_ser(user=None):
    if request.headers.get("X-Forwarded-For", None) is not None:
        return jsonify({"error": "Access Denied"}), 403
    else:
        pass



@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed for this endpoint"}), 405


if __name__ == "__main__":
    if config["debug"]:
        print("RUNNING WITH DEBUG SERVER - DO NOT USE IN PRODUCTION\n")
        app.run(debug=config["debug"], host=config["address"], port=config["port"])
    else:
        print("Auth Server running With Production Server")
        serve(app, host=config["address"], port=config["port"])