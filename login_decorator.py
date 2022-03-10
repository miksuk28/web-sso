from functools import wraps
from flask import request, jsonify
import db_exceptions as exc
from secret_config import secrets
from db import UsersDatabaseWrapper

db = UsersDatabaseWrapper()