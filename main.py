from flask import Flask, request, jsonify                       # Everything Flask related
import jwt                                                      # JSON Web Tokens
from jwt.exceptions import ExpiredSignatureError, \
InvalidTokenError, DecodeError, InvalidSignatureError           # JWT Exceptions
from time import time                                           # To get Unixtime
from functools import wraps                                     # To create decorators
import secret_config                                            # Secret config, containes SECRET_KEY
from config import config                                       # Configs


app = Flask(__name__)
app.config["SECRET_KEY"] = secret_config.secrets["SECRET_KEY"]


def unixtime():
    # Returns Unixtime in int
    return int(time())


# Authentication decorator
def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("token")

        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], "HS256")
            if payload["expiration"] <= unixtime():
                raise ExpiredSignatureError

        except ExpiredSignatureError:
            return jsonify({"error": "Token expired. Please login again"}), 401

        except InvalidSignatureError:
            return jsonify({"error": "Invalid signature. Please login again"}), 401

        except (InvalidTokenError, DecodeError):
            return jsonify({"error": "Invalid token. Please login again"}), 403

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

    if data["username"] == "user" and data["password"] == "1234":
        # session["logged_in"] = True
        token = jwt.encode({
            "user": data["username"],
            "expiration": int(unixtime() + config["token_valid_time"]),
        },
        app.config["SECRET_KEY"], "HS256")
    else:
        return jsonify({"error": "Unable to verify"}), 403

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(debug=config["debug"], host=config["address"], port=config["port"])