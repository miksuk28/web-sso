from lib2to3.pgen2 import token
import sqlite3
import jwt
import hashlib
from bcrypt import gensalt
from time import time


class UsersDatabaseWrapper:
    def __init__(self, db_file, secret_key, token_validity):
        self._db_file = db_file
        self._SECRET_KEY = secret_key
        self._token_valid_for = token_validity
        self._db = self._connect_to_db(self._db_file)


    def _connect_to_db(self, db_file):
        conn = None
        try:
            conn = sqlite3.connect(db_file)
            return conn
        except sqlite3.Error as e:
            raise SystemExit(f"Failed to connect to db. Execute cannot continue...\n\n{e}")


    def _create_user(self, username, password, block_login=False, admin=False):
        