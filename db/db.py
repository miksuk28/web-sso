from collections import defaultdict
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidKeyError, InvalidSignatureError
from sqlitedict import SqliteDict
from bcrypt import gensalt
from time import time
from random import choice
from .db_exceptions import *
import jwt
import hashlib


class UsersDatabaseWrapper:
    def __init__(self, db_file, token_validity, secret_key, debug=False, min_pass_length=8):
        self._db_file = db_file
        self._db = SqliteDict(db_file, autocommit=False, tablename="authserver")
        self._token_validity = token_validity
        self._SECRET_KEY = secret_key
        self._CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"


    def _unixtime(self):
        return int(time())

    
    def _hash_password(self, password, salt):
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed

    
    def _gen_password(self, length=8):
        password = ""
        for _ in range(length):
            password += choice(self._CHARS)

        return password


    def _hash_password(self, password, username=None, salt=None):
        if salt is None:
            salt = self._db["users"][username]["salt"]

        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed

    
    def add_user(self, username, password=None, access_level="user", disallow_tokens_before=0, restrict_access_to=None, block_login=False):
        salt = gensalt()
        
        if password is None:
            password = self._gen_password()
            reset_password = True
        else:
            reset_password = False

        if self._db.get(username, default=None) != None:
            raise UserAlreadyExists(username)
        else:
            user = {"username": username, "hashed_password": self._hash_password(password, salt),
            "salt": salt, "access_level": access_level, "disallow_tokens_before": disallow_tokens_before,
            "restrict_access_to": restrict_access_to, "reset_password": reset_password, "block_login": block_login}
            
            self._db["users"][username] = user
            self._db.commit()

            if reset_password:
                return {"username": username, "access_level": access_level, "password": password}
            else:
                return {"username": username, "access_level": access_level}


    def auth(self, token):
        try:
            try:
                payload = jwt.decode(
                    token,
                    self._SECRET_KEY,
                    "HS256"
                )

            except ExpiredSignatureError:
                raise TokenExpired
            
            except InvalidSignatureError:
                raise TokenInvalid

            except (InvalidKeyError, DecodeError):
                raise TokenInvalid


            if self._db["users"][payload["user"]]["block_login"]:
                raise UserBlocked(payload['username'])

        except KeyError:
            raise UserNotFound(payload['username'])

        return payload


    def _user_exists(self, user):
        try:
            _ = self._db["users"][user]["username"]
        except KeyError:
            raise UserNotFound(user)

        return True


    def _check_password(self, username, password):
        self._user_exists(username)

        correct_hash = self._db["users"][username]["hashed_password"]
        this_hash = self._hash_password(password=password, username=username)

        if this_hash == correct_hash:
            return True
        else:
            return False


    def login(self, username, password, service_id, access_level="User", restricted_to=None):
        self._user_exists(username)
        if self._check_password(username, password):
            token = jwt.encode({
                "user": username,
                "access_level": access_level,
                "expiration": self._unixtime() + self._token_validity,
                "restricted_to": restricted_to 
            },
            self._SECRET_KEY, "HS256")

            return token
        else:
            raise IncorrectPassword




