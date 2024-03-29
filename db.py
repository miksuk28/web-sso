import psycopg2
import psycopg2.extras
import jwt
import hashlib
import db_exceptions as exc
import jwt.exceptions as jwtexc
from time import time
from bcrypt import gensalt
from datetime import datetime, timezone, timedelta
from sys import exit
from hmac import compare_digest
from sql_statements import SQLStatements
from secrets import token_hex


class UsersDatabaseWrapper:
    def __init__(self, token_validity, secret_key, database, username, password, address, global_token_block=0, allow_admin_creation=False):
        self._token_valid_for = token_validity
        self._db = self._connect_to_db(address, database, username, password)
        self._allow_admin_creation = allow_admin_creation

        self._global_token_block = global_token_block
        self.__SECRET_KEY = secret_key


    def _exit_cleanly(self, reason, error=True):
        '''Close the database connection before exiting'''
        if self._db is not None:
            self._db.close()

        if error:
            print(f"An error has occured and the execution can not continue\n\nReason:\n{reason}")
            exit(1)
        else:
            print(f"The Auth Server has stopped.\n{reason}")
            exit(0)


    def _connect_to_db(self, address, database, username, password):
        try:
            conn = psycopg2.connect(
                cursor_factory=psycopg2.extras.DictCursor,
                host=address,
                database=database,
                user=username,
                password=password
            )
            
            return conn
        except psycopg2.Error as e:
            self._exit_cleanly(e, error=True)


    def _hash_password(self, password, salt):
        '''Hashed and returns the salted password'''
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        )

        # print(f"HASH FUNC: password: {hashed.hex()}\nSalt: {salt}")
        return hashed.hex()


    def _check_if_user_exists(self, username):
        '''Checks database and returns true if user exists'''
        cur = self._db.cursor()
        cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))

        if cur.fetchone() is not None:
            return True
        else:
            return False


    def login(self, username, password):
        if not self._check_if_user_exists(username):
            raise exc.UserDoesNotExist(username)

        cur = self._db.cursor()
        cur.execute(SQLStatements.get_user_and_password, (username,))
        user = cur.fetchone()
        
        if user.get("block_login"):
            raise exc.BlockedLogin(username, user["block_login_reason"])

        elif compare_digest(user.get("hashed_password"), self._hash_password(password, user.get("salt") )):
            jwt_token, access_token, expiration = self._generate_token(username, admin=self._is_admin(username))
            self._register_token(username, jwt_token, access_token)

            return jwt_token, access_token, expiration

        else:
            raise exc.IncorrectPassword(username)


    def _register_token(self, username, jwt_token, access_token):
        expiration = self.timestamp() + timedelta(self._token_valid_for)
        
        cur = self._db.cursor()
        cur.execute(
            SQLStatements.register_token,
            (username, jwt_token, access_token, expiration)
        )

        self._db.commit()


    def get_jwt(self, access_token):
        cur = self._db.cursor()
        cur.execute(
            SQLStatements.get_token,
            (access_token,)
        )
        token = dict(cur.fetchone())

        token["expirationTimestamp"] = token["expiration"].timestamp()
        return token


    def _is_admin(self, username):
        cur = self._db.cursor()
        cur.execute(SQLStatements.is_admin, (username,))
        admin = cur.fetchone()

        if admin is None:
            return False
        elif admin.get("username") == username:
            return True

        return False
            

    def timestamp(self):
        return datetime.now(timezone.utc)


    def _get_userid(self, username):
        cur = self._db.cursor()
        cur.execute(SQLStatements.get_user_id, (username,))
        user_id = cur.fetchone()

        if user_id is None:
            raise exc.UserDoesNotExist(username)
        else:
            return user_id["user_id"]


    def get_user(self, username):
        cur = self._db.cursor()
        cur.execute(SQLStatements.get_user, (username,))
        user = cur.fetchone()

        if user is None:
            raise exc.UserDoesNotExist(id)

        return user


    def _generate_token(self, username, admin=False):
        user_id = self._get_userid(username)

        access_token = token_hex(32)
        
        expiration = self.timestamp() + timedelta(self._token_valid_for)
        token = jwt.encode({
            "username": username,
            "user_id": user_id,
            "iat": datetime.now(timezone.utc).utctimetuple(),
            "exp": expiration,
            "admin": admin
        },
        self.__SECRET_KEY, "HS256")

        return token, access_token, expiration


    def _decode_token(self, token):
        '''Decode token and return payload. Only to be called by backends'''
        try:
            payload = jwt.decode(
                token,
                self.__SECRET_KEY,
                "HS256"
            )

        except jwtexc.ExpiredSignatureError:
            raise exc.ExpiredToken

        except Exception as e:
            print(e)
            print(token)
            raise exc.InvalidToken

        return payload


    def create_user(self, username, password, fname=None, lname=None, block_login=False, block_login_reason=False, admin=False, admin_granter=None):
        if self._check_if_user_exists(username):
            raise exc.UserAlreadyExists(username)

        if not self._allow_admin_creation:
            admin = False

        salt = gensalt().hex()
        hashed_pass = self._hash_password(password, salt)

        cur = self._db.cursor()
        cur.execute(SQLStatements.create_user, (
            username, fname, lname, self.timestamp(),
            block_login, block_login_reason
        ))
        # Register password
        cur.execute(SQLStatements.add_user_password, (
            username, hashed_pass, salt, self.timestamp(), None
        ))

        self._db.commit()

        if admin:
            self.add_admin(username, granter=admin_granter)


    def add_admin(self, username, granter):
        if not self._check_if_user_exists(username):
            raise exc.UserDoesNotExist(username)

        elif self._is_admin(username):
            # User is already admin - do nothing
            return

        elif self._is_admin(granter):
            cur = self._db.cursor()
            cur.execute(SQLStatements.add_admin, (username, granter, self.timestamp()))
            self._db.commit()

        else:
            raise exc.UserIsNotAdmin(granter)

