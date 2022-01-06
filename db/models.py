from sqlalchemy import MetaData, Table, Column, Integer, String

meta = MetaData()

# Users table in db
users_model = Table(
    "users", meta,
    Column("id", Integer, primary_key=True, nullable=False),
    Column("username", String(40), nullable=False),
    Column("hashed_password", String, nullable=False),
    Column("password_salt", String, nullable=False),
    Column("access_level", Integer, nullable=False),
    Column("disallow_tokens_before", Integer, nullable=True),
    Column("restrict_access_to", String, nullable=True)
)