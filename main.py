import secret_config                                            # Secret config, containes SECRET_KEY
from config import config                                       # Configs
from db.db_exceptions import IncorrectPassword, TokenExpired, TokenInvalid, UserNotFound                                                      # JSON Web Tokens
from db.db import UsersDatabaseWrapper
from flask import Flask, request, jsonify                       # Everything Flask related                                          # To get Unixtime
from functools import wraps                                     # To create decorators


app = Flask(__name__)
app.config["SECRET_KEY"] = secret_config.secrets["SECRET_KEY"]


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
            return jsonify({"error": "Invalid signature. Please login again"}), 401

        # Catch all
        except Exception as e:
            print(e)
            return jsonify({"error": "An internal server error has occured. Please contact the admin"}), 500

        if config["debug"]:
            print(f"\nPayload: {payload}\n")
            print(f"Expiration: {payload['expiration']} - Current time: {int(unixtime())}")
        
        kwargs["payload"] = payload
        kwargs["headers"] = request.headers

        # Data gets passed back into public original function and run
        return func(*args, **kwargs)
    
    return decorated_function


# Public
@app.route("/public")
def public():
    return "For public"


# Authenticated
@app.route("/auth")
@login_required
def auth(*args, **kwargs):
    payload = kwargs["payload"]
    headers = kwargs["headers"]

    return jsonify(payload, headers)


# Get authserver status. For displaying messages during downtime
@app.route("/authstatus", methods=["GET"])
def get_status():
    # Used by clients to check server status
    return jsonify(config["auth_status_message"]), 200

# Login
@app.route("/")
@login_required
def home(*args, **kwargs):
    payload = kwargs["payload"]

    return jsonify({"message": f"Welcome {payload['user']}"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    try:
        token = db.login(username=data["username"], password=data["password"], service_id=config["service_id"], access_level=data["access_level"], restricted_to=None)
    
    except UserNotFound:
        return jsonify({"error": f"User {data['username']} not found"}), 404

    except IncorrectPassword:
        return jsonify({"error": "Password is incorrect"}), 403

    return jsonify({"token": token})


if __name__ == "__main__":
    db = UsersDatabaseWrapper(db_file="users.db", token_validity=config["token_valid_time"], secret_key=secret_config.secrets["SECRET_KEY"], debug=config["debug"], min_pass_length=config["min_password_length"])
    app.run(debug=config["debug"], host=config["address"], port=config["port"])