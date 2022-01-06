from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData

engine = create_engine("sqlite:///users.db", echo=True)
meta = MetaData()

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

meta.create_all(engine)