from secret_config import secrets
from config import config
from admin_blueprint import admin
from importlib import reload
from db.db_exceptions import IncorrectPassword, TokenExpired, TokenInvalid, UserAlreadyExists, UserNotFound                                                      # JSON Web Tokens
from db.db import UsersDatabaseWrapper
from flask import Flask, request, jsonify
from login_wrapper import login_required
from logger import Logger

# TEMPORARY, TO BE REMOVED
from flask import render_template


app = Flask(__name__)
app.register_blueprint(admin, url_prefix="/admin")
app.config["SECRET_KEY"] = secrets["SECRET_KEY"]


class ExternalIPsReachedSensitiveEndpoint(Exception):
    pass


# FOR TESTING
@app.route("/get_users", methods=["GET"])
def get_users():
    if not config["debug"]:
        return jsonify({"error": "The path is not valid"}), 404
    else:
        users = db._get_all_users()
        print(f"Users: {users}")
        return render_template("users.html", users=users)


# Reload config.py
@app.route("/reload_config", methods=["GET"])
def reload_config():
    global config
    reload(config)

    from config import config

    print(config)
    return jsonify({"info": "Config reloaded"})


# Public
@app.route("/public")
def public():
    return "For public"


# Authenticated, every request made to backend should be verified here
@app.route("/auth")
@login_required
def auth(*args, **kwargs):
    payload = kwargs["payload"]
    headers = kwargs["headers"]

    return jsonify({"payload": payload})


# Get authserver status. For displaying messages during downtime
@app.route("/authstatus", methods=["GET"])
def get_status():
    # Used by clients to check server status
    logger.log("/authstatus", service_id=1)
    return jsonify(config["auth_status_message"]), 200


# Login
@app.route("/")
@login_required
def home(*args, **kwargs):
    payload = kwargs["payload"]

    return jsonify({"message": f"Welcome {payload['user']}"})


@app.route("/register", methods=["POST"])
def register():
    if not config["allow_register"]:
        return jsonify({"error": "Public Registration is disabled. Please contact the admin to register"}), 403

    data = request.get_json()
    if data == None:
        return jsonify({"error": "No JSON in body"})

    if "password" not in data:
        data["password"] = None

    try:
        user = db.add_user(
            username=data["username"],
            password=data["password"]
        )

        logger.log(text="Created User", user=data["username"], service_id=0)
    except UserAlreadyExists:
        return jsonify({"error": "This username already exists. Please pick another one."}), 409

    return jsonify(user), 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    print("Data", data)

    if data == None:
        return jsonify({"error": "No JSON in body"})

    try:
        token, expiration = db.login(username=data["username"], password=data["password"], restricted_to=None)
        logger.log("Generated token", service_id=1, user=data["username"], ip="localhost")
    except UserNotFound:
        return jsonify({"error": f"User {data['username']} not found"}), 404

    except IncorrectPassword:
        return jsonify({"error": "Password is incorrect"}), 403

    return jsonify({"token": token, "expiration": expiration})


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "The path is not valid"}), 404


@app.errorhandler(405)
def page_not_found(e):
    return jsonify({"error": "Method not allowed for the requested URL"}), 405


if __name__ == "__main__":
    logger = Logger("log.txt")
    db = UsersDatabaseWrapper(config, secrets)
    app.run(debug=config["debug"], host=config["address"], port=config["port"])