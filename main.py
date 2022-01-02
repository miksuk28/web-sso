from flask import Flask, request, jsonify, session              # Everything Flask related
import jwt                                                      # JSON Web Tokens
from jwt.exceptions import ExpiredSignatureError, \
InvalidTokenError, DecodeError, InvalidSignatureError           # JWT Exceptions
from time import time as unixtime                               # To get Unixtime
from functools import wraps                                     # To create decorators
import secret_config                                            # Secret config

DEBUG = True

app = Flask(__name__)
app.config["SECRET_KEY"] = secret_config.secrets["SECRET_KEY"]


def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("token")

        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], "HS256")
            if payload["expiration"] <= int(unixtime()):
                raise ExpiredSignatureError

        except (InvalidTokenError, DecodeError):
            return jsonify({"error": "Invalid token. Please login again"}), 403
        except ExpiredSignatureError:
            return jsonify({"error": "Token expired. Please login again"}), 401
        except InvalidSignatureError:
            return jsonify({"error": "Invalid signature. Please login again"}), 401
        # Catch all
        except Exception as e:
            print(e)
            return jsonify({"error": "An internal server error has occured. Please contact the admin"}), 500

        if DEBUG:
            print(f"\nPayload: {payload}\n")
            print(f"Expiration: {payload['expiration']} - Current time: {int(unixtime())}")
        
        kwargs["payload"] = payload

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

    return jsonify(payload)


@app.route("/authstatus", methods=["GET"])
def get_status():
    return jsonify({"auth_server_status": "OK" }), 200

# Login
@app.route("/")
def home():
    if not session.get("logged_in"):
        return jsonify({"error": "You need to sign in"}), 401
    else:
        return jsonify({"message": "Logged in currently"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if data["username"] == "user" and data["password"] == "1234":
        # session["logged_in"] = True
        token = jwt.encode({
            "user": data["username"],
            "expiration": int(unixtime() + 120),
        },
        app.config["SECRET_KEY"], "HS256")
    else:
        return jsonify({"error": "Unable to verify"}), 403

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(debug=DEBUG, host="127.0.0.1", port=5000)