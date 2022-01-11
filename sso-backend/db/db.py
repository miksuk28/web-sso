from logging import debug
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidKeyError, InvalidSignatureError
from bcrypt import gensalt
from time import time
from random import choice
from .db_exceptions import *
import pymongo
import jwt
import hashlib


class UsersDatabaseWrapper:
    def __init__(self, config, secret_config):
        connection_str = f"mongodb://{config['database']['db_username']}:{secret_config['DB_PASSWORD']}@{config['database']['host']}"
        self._debug = config["debug"]
        self._client = pymongo.MongoClient(connection_str)
        self._db = self._client[config["database"]["db_name"]]
        self._user_col = self._db[config["database"]["db_col_name"]]
        self._token_validity = config["token_valid_time"]
        self._SECRET_KEY = secret_config["SECRET_KEY"]
        self._CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"


    def _unixtime(self):
        return int(time())

    
    def _gen_password(self, length=8):
        password = ""
        for _ in range(length):
            password += choice(self._CHARS)

        return password


    def _get_all_users(self):
        if self._debug:
            users = []
            for user in self._users:
                users.append(user)
            
            return users
        else:
            raise NotAllowedInProduction


    def _hash_password(self, password, username=None, salt=None):
        if salt is None:
            #try:
            salt = self._user_col.find_one({"username": username})["salt"]
            #except KeyError:
            #    raise MissingDocumentKey(f"{username}: salt")

        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed

    
    def add_user(self, username, password=None, access_level="user", disallow_tokens_before=0, restrict_access_to=None, block_login=False):
        if self._user_col.find_one({"username": username}) is not None:
            raise UserAlreadyExists(username)

        salt = gensalt()
        
        if password is None:
            password = self._gen_password()
            reset_password = True
        else:
            reset_password = False

        user = {
            "username": username,
            "hashed_password": self._hash_password(password, salt=salt),
            "salt": salt,
            "access_level": access_level,
            "disallow_tokens_before": disallow_tokens_before,
            "restrict_access_to": restrict_access_to,
            "reset_password": reset_password,
            "block_login": block_login,
            "registered": self._unixtime()
        }
        
        self._user_col.insert_one(user)

        if reset_password:
            return {"username": username, "access_level": access_level, "password": password}
        else:
            return {"username": username, "access_level": access_level}


    def auth(self, token):
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

        user_query = self._user_col.find_one({"username": payload["username"]}, {"block_login": 1})

        if user_query is None:
            # Raise exception if user not in database
            raise UserNotFound(payload["username"])
        elif user_query["block_login"]:
            # Raise exception if login is blocked for that user
            raise UserBlocked(payload['username'])
        else:
            return payload


    def _user_exists(self, user):
        user_query = self._user_col.find_one({"username": user})

        if user_query is None:
            return False
        else:
            return True


    def _check_password(self, username, password):
        self._user_exists(username)

        correct_hash = self._user_col.find_one({"username": username}, {"hashed_password": 1})
        if correct_hash is None:
            raise MissingDocumentKey(f"{username}: hashed_password")

                
        this_hash = self._hash_password(password=password, username=username)

        if this_hash == correct_hash["hashed_password"]:
            return True
        else:
            return False


    def login(self, username, password, service_id=0, access_level="User", restricted_to=None):
        if not self._user_exists(username):
            raise UserNotFound(username)

        if self._debug: print(f"Username: {username} - Password: {password}")

        if self._check_password(username, password):
            expiration = self._unixtime() + self._token_validity
            token = jwt.encode({
                "user": username,
                "access_level": access_level,
                "expiration": expiration,
                "restricted_to": restricted_to 
            },
            self._SECRET_KEY, "HS256")

            print(token)
            return token.decode("UTF-8"), expiration
        else:
            raise IncorrectPassword


