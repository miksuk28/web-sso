from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String
from sqlalchemy.sql import select
from bcrypt import gensalt
import hashlib
meta = MetaData()

engine = create_engine("sqlite:///users.db", echo=True)
conn = engine.connect()

users = Table(
    "users", meta,
    Column("id", Integer, primary_key=True, nullable=False),
    Column("username", String(40), nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("password_salt", String, nullable=False),
    Column("access_level", Integer, nullable=False),
    Column("disallow_tokens_before", Integer, nullable=True),
    Column("restrict_access_to", String, nullable=True)
)

def create_user(username, password, access_level="user"):
    ins = users.insert().values(username = username, hashed_password = password, password_salt="1", access_level = access_level)
    result = conn.execute(ins)
    print("OK")

create_user(username="Mark", password="1234")


class UserAlreadyExists(Exception):
    pass


class UsersDatabaseWrapper:
    def __init__(self, db_file, debug=False):
        self.__db_file = db_file
        # Database connections
        self.__meta = MetaData()
        self.__engine = create_engine(f"sqlite:///{self.__db_file}", echo=debug)
        self.__conn = self.__engine.connect()

        self.__users = Table(
            "users", self.__meta,
            Column("id", Integer, primary_key=True, nullable=False),
            Column("username", String(40), nullable=False),
            Column("hashed_password", String, nullable=False),
            Column("password_salt", String, nullable=False),
            Column("access_level", Integer, nullable=False),
            Column("disallow_tokens_before", Integer, nullable=True),
            Column("restrict_access_to", String, nullable=True)
        )

    def __hash_password(self, password, salt):
        hashed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000
        )

        return hashed


    def add_user(self, username, password, access_level, disallow_tokens_before=0, restrict_access_to=None):
        salt = gensalt()
        hashed_password = self.__hash_password(password, salt)
        
        ins = self.__users.insert().values(username=username, hashed_password=hashed_password, access_level=int(access_level), disallow_tokens_before=int(disallow_tokens_before), password_salt=salt, restrict_access_to=restrict_access_to)
        result = self.__conn.execute(ins)

        print(f"User {username} has been added")

    
    def get_user(self, username):
        stmt = select([self.__users]).where(self.__users.c.username == username)
        result = self.__conn.execute(stmt).keys()

        for row in result:
            print(row)

        print(f"\n{result}")


