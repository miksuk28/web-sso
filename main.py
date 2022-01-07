import secret_config                                            # Secret config, containes SECRET_KEY
from config import config                                       # Configs
from db.db_exceptions import IncorrectPassword, TokenExpired, TokenInvalid, UserAlreadyExists, UserNotFound                                                      # JSON Web Tokens
from db.db import UsersDatabaseWrapper
from flask import Flask, json, request, jsonify                       # Everything Flask related                                          # To get Unixtime
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

    return jsonify({"payload": payload})


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


@app.route("/register", methods=["POST"])
def register():
    if not config["allow_register"]:
        return jsonify({"error": "Public Registration is disabled. Please contact the admin to register"}), 403

    data = request.get_json()

    if "password" not in data:
        data["password"] = None

    try:
        user = db.add_user(
            username=data["username"],
            password=data["password"]
        )

    except UserAlreadyExists:
        return jsonify({"error": "This username already exists. Please pick another one."}), 409

    return jsonify(user), 200

    '''
    except Exception as e:
        print(e)
        return jsonify({"error": "Data received is invalid. Please check documentation"}), 400
    '''


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    print("Data", data)

    try:
        token = db.login(username=data["username"], password=data["password"], restricted_to=None)
    
    except UserNotFound:
        return jsonify({"error": f"User {data['username']} not found"}), 404

    except IncorrectPassword:
        return jsonify({"error": "Password is incorrect"}), 403

    return jsonify({"token": token})


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "The path is not valid"}), 404


if __name__ == "__main__":
    db = UsersDatabaseWrapper(config, secret_config.secrets)
    app.run(debug=config["debug"], host=config["address"], port=config["port"])