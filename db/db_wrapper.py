from sqlalchemy import create_engine
from sqlalchemy.sql import select
from bcrypt import gensalt
from time import time
import jwt
import hashlib
#from main import unixtime
import models


# Custom exceptions for database wrapper
class UserAlreadyExists(Exception):
    pass

class IncorrectPassword(Exception):
    pass

class UserNotFound(Exception):
    pass




class UsersDatabaseWrapper:
    def __init__(self, db_file, token_validity, secret_key, debug=False):
        self._db_file = db_file
        self._token_validity = token_validity
        self._secret_key = secret_key
        # Database connections
        self._engine = create_engine(f"sqlite:///{self._db_file}", echo=debug)
        self._conn = self._engine.connect()

        self._users = models.users_model


    def _unixtime(self):
        return int(time)


    def _hash_password(self, password, salt):
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed


    def add_user(self, username, password, access_level, disallow_tokens_before=0, restrict_access_to=None):
        salt = gensalt()
        hashed_password = self._hash_password(password, salt)
        
        ins = self._users.insert().values(username=username, hashed_password=hashed_password, access_level=int(access_level), disallow_tokens_before=int(disallow_tokens_before), password_salt=salt, restrict_access_to=restrict_access_to)
        result = self._conn.execute(ins)

        print(f"User {username} has been added")


    def _get_user_salt(self, username):
        user = self._users.query.filter_by(username=username).first()

        if user is None:
            raise UserNotFound(f"User {username} does not exist in database")
        else:
            print(user)

    def _check_password(self, user, password):
        pass


    def get_user(self, username):
        stmt = select([self._users]).where(self._users.c.username == username)
        result = self._conn.execute(stmt)

        for row in result:
            print(row)

        return result

        print(f"\n{result}")


    def auth(self, username, password, service, expiration):
        '''
        salt = self._get_user_salt(username)
        hashed_password = self._hash_password(password, salt)
        '''

        access_level = None

        token = jwt.encode({
            "user": username,
            "access_level": access_level,
            "expiration": int(unixtime() + self._token_validity)
        },
        self._secret_key, "HS256")

        return token