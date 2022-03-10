from flask import Flask, request, jsonify
from waitress import serve
from secret_config import secrets
from config import config
from db import UsersDatabaseWrapper
import db_exceptions as exc

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
        token, expiration = db.login(username=data["username"], password=data["password"])
        return jsonify({"token": token, "exp": expiration})

    except exc.UserDoesNotExist:
        return jsonify({"error": "User does exist"}), 404
    
    except exc.IncorrectPassword:
        return jsonify({"error": "Incorrect password"}), 403

    except:
        return jsonify({"error": "An unknown error has occured. Please try again"}), 500


# Only to be called by backends
@app.route("/validate", methods=["GET"])
def validate_token():
    token = request.headers.get("token", None)

    if token is None:
        return jsonify({"error": "Token header is missing"}), 400
    
    try:
        payload = db._decode_token(token)
        return jsonify({"message": "Token is valid", "payload": payload}), 200

    except exc.ExpiredToken:
        return jsonify({"error": "Access token has expired"}), 401

    except exc.InvalidToken:
        return jsonify({"error": "Invalid token"}), 401