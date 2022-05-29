from flask import Blueprint

admin_endpoints = Blueprint("admin_endpoints", __name__)

@admin_endpoints.route("/users")
def index():
    return "Hello, World"