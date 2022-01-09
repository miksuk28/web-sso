from flask import Blueprint, jsonify, request
from config import config
from login_wrapper import login_required
from secret_config import secrets
from db.db import UsersDatabaseWrapper


admin = Blueprint("admin", __name__)
db = UsersDatabaseWrapper(config=config, secret_config=secrets)


@admin.route("/test", methods=["GET"])
def test():
    return "<h1>Hello, World!</h1>"


@admin.route("/auth", methods=["GET"])
@login_required
def auth(*args, **kwargs):
    payload = kwargs["payload"]
    headers = kwargs["headers"]

    if payload["access_level"] == "Admin":
        return jsonify({"message": "You're logged in as admin. Be careful, and respect the privacy of others!"}), 200
    else:
        return jsonify({"error": "Access denied"}), 403