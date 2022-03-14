import sqlite3
from unittest import result
import jwt
import hashlib
from bcrypt import gensalt
from time import time
from sys import exit
from hmac import compare_digest
import db_exceptions as exc
import jwt.exceptions as jwtexc


class UsersDatabaseWrapper:
    def __init__(self, db_file, token_validity, secret_key, global_token_block=0):
        self._db_file = db_file
        self._token_valid_for = token_validity
        self._db = self._connect_to_db(self._db_file)
        self._global_token_block = global_token_block
        self.__SECRET_KEY = secret_key
        
        # Setup
        self._enable_primary_keys()


    def _enable_primary_keys(self):
        self._db.execute("PRAGMA foreign_keys = ON;")


    def _exit_cleanly(self, reason, error=True):
        '''Close the database connection before exiting'''
        self._db.close()

        if error:
            print(f"An error has occured and the execution can not continue\n\nReason:\n{reason}")
            exit(1)
        else:
            print(f"The Auth Server has stopped.\n{reason}")
            exit(0)


    def _connect_to_db(self, db_file):
        '''Connect to db and return db object'''
        conn = None
        try:
            conn = sqlite3.connect(db_file, check_same_thread=False)
            return conn
        except sqlite3.Error as e:
            self._exit_cleanly(e, error=True)


    def _hash_password(self, password, salt):
        '''Hashed and returns the salted password'''
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed


    def _check_if_user_exists(self, username):
        '''Checks database and returns true if user exists'''
        cur = self._db.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))

        result = cur.fetchone()

        if result:
            return True
        else:
            return False


    def login(self, username, password):
        '''Check if user exists, and generate jwt if password is right'''
        if not self._check_if_user_exists(username):
            raise exc.UserDoesNotExist(username)

        sql_stmt = '''
            SELECT username, pass_hash, salt, block_login, block_login_reason, block_login_type, admin
            FROM users
            WHERE username=?
        '''

        cur = self._db.cursor()
        cur.execute(sql_stmt, (username,))
        result = cur.fetchone()
        db_pass = result[1]
        db_salt = result[2]
        db_admin = result[6]
        db_block_login = result[3]

        if db_block_login != 0 or False:
            raise exc.BlockedLogin(result[5], result[4])

        elif compare_digest(db_pass, self._hash_password(password, db_salt)):
            token, expiration = self._generate_token(username, admin=db_admin)

            return token, expiration
        else:
            raise exc.IncorrectPassword


    def _get_userid(self, username):
        sql_stmt = '''
            SELECT id FROM users WHERE username=?
        '''

        cur = self._db.cursor()
        cur.execute(sql_stmt, (username,))
        result = cur.fetchone()

        if result is None:
            raise exc.UserDoesNotExist(username)
        else:
            return result[0]


    def get_user(self, id):
        sql_stmt = '''
            SELECT username, fname, lname, block_login,
            block_login_reason, block_login_type,
            registered_time, admin

            FROM users

            WHERE id=?
        '''

        cur = self._db.cursor()
        cur.execute(sql_stmt, (id,))
        result = cur.fetchone()

        if result is None:
            raise exc.UserDoesNotExist(id)

        user_info = {
            "id": id,
            "username": result[0],
            "fname": result[1],
            "lname": result[2],
            "block_login": result[3],
            "block_login_reason": result[4],
            "block_login_type": result[5],
            "registed_time": result[6],
            "admin": result[7]
        }

        return user_info


    def _generate_token(self, username, admin=False):
        user_id = self._get_userid(username)[0]
        
        expiration = int(time()) + self._token_valid_for
        token = jwt.encode({
            "username": username,
            "user_id": user_id,
            "iat": int(time()),
            "exp": expiration,
            "admin": admin
        },
        self.__SECRET_KEY, "HS256")

        return token.decode("utf-8"), expiration


    def _decode_token(self, token):
        '''Decode token and return payload. Only to be called by backends'''
        try:
            payload = jwt.decode(
                token,
                self.__SECRET_KEY,
                "HS256"
            )

        except jwtexc.ExpiredSignature:
            raise exc.ExpiredToken

        except:
            raise exc.InvalidToken

        return payload


    def create_user(
            self,
            username,
            password,
            fname=None,
            lname=None,
            registered_ip=None,
            block_login=False,
            block_login_reason=None,
            block_login_type=None,
            tokens_blocked_after=None,
            admin=False
            ):
        '''Adds user to database. Only to be run by admins'''
        # Raises exception if username taken
        if self._check_if_user_exists(username):
            raise exc.UserAlreadyExists(username)
        
        salt = gensalt()
        hashed_pass = self._hash_password(password, salt)

        sql_stmt = '''
            INSERT INTO users(username,fname,lname,pass_hash,salt,
                block_login,block_login_reason,block_login_type,
                tokens_blocked_after,registered_time,registered_ip,
                last_ip_login,admin)

            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        '''

        values = username, fname, lname, hashed_pass, salt, block_login, block_login_reason, block_login_type, tokens_blocked_after, int(time()), registered_ip, None, admin

        cur = self._db.cursor()
        cur.execute(sql_stmt, values)

        self._db.commit()
