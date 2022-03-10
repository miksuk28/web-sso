from opcode import haslocal
import sqlite3
import jwt
import hashlib
from bcrypt import gensalt
from time import time
from sys import exit
import db_exceptions as exc


class UsersDatabaseWrapper:
    def __init__(self, db_file, secret_key, token_validity):
        self._db_file = db_file
        self._SECRET_KEY = secret_key
        self._token_valid_for = token_validity
        self._db = self._connect_to_db(self._db_file)


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
            conn = sqlite3.connect(db_file)
            return conn
        except sqlite3.Error as e:
            self._exit_cleanly(e, error=True)


    def _db_execute(self, sql_stmt, values):
        '''Generic method for executing SQL statements'''
        try:
            cur = self._db.cursor()
            cur.execute(sql_stmt, values)

            return cur, cur.lastrowid

        except sqlite3.Error as e:
            raise exc.CannotExecuteSQL(e)


    def _hash_password(self, password, salt):
        '''Hashed and returns the salted password'''
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed

    def _create_user(
            self,
            username,
            password,
            fname,
            lname,
            registered_ip=None,
            block_login=False,
            block_login_reason=None,
            block_login_type=None,
            admin=False
            ):
        '''Adds user to database. Only to be run by admins'''
        salt = gensalt()

        hashed_pass = 

