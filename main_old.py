from flask import Flask, request, jsonify, session
import jwt
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)
# TO BE CHANGED OFC
app.config["SECRET_KEY"] = "1234"

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get("token")
        if not token:
            return jsonify({"error": "Token is missing"}), 400

        payload = jwt.decode(token, app.config["SECRET_KEY"], "HS256")
    
    return decorated

# Public
@app.route("/public")
def public():
    return "For public"


# Authenticated
@app.route("/auth")
@token_required
def auth():
    return jsonify({"message": "Welcome!"}), 200


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
        session["logged_in"] = True
        token = jwt.encode({
            "user": data["username"],
            "expiration": str(datetime.utcnow() + timedelta(seconds=120)),
        },
        app.config["SECRET_KEY"], "HS256")
    else:
        return jsonify({"error": "Unable to verify"}), 403

    return jsonify({"token": token})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)