import psycopg2
import psycopg2.extras
import jwt
import hashlib
from bcrypt import gensalt
from datetime import datetime, timezone
from sys import exit
from hmac import compare_digest
from sql_statements import SQLStatements
import db_exceptions as exc
import jwt.exceptions as jwtexc


class UsersDatabaseWrapper:
    def __init__(self, token_validity, secret_key, database, username, password, address, global_token_block=0):
        self._token_valid_for = token_validity
        self._db = self._connect_to_db(address, database, username, password)
        
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
            salt,
            100000
        )

        return hashed


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

        elif compare_digest(user.get("hashed_password").encode("utf-8"), self._hash_password(password, user.get("salt").encode("utf-8") )):
            token, expiration = self._generate_token(username, admin=False)
            return token, expiration

        else:
            raise exc.IncorrectPassword(username)


    def _is_admin(self, username):
        cur = self._db.cursor()
        cur.execute(SQLStatements.is_admin, (username,))
        admin = cur.fetchone()

        if admin.get("username") == username:
            return True
        else:
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


    def create_user_old(
            self,
            username,
            password,
            fname=None,
            lname=None,
            block_login=False,
            block_login_reason=None,
            admin=False,
            admin_granter=None
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


    def create_user(self, username, password, fname=None, lname=None, block_login=False, block_login_reason=False, admin=False, admin_granter=None):
        if self._check_if_user_exists(username):
            raise exc.UserAlreadyExists(username)

        salt = gensalt()
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

