DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id                      integer     NOT NULL        UNIQUE,
    username                text        NOT NULL        UNIQUE,
    fname                   text,
    lname                   text,
    pass_hash               text        NOT NULL,
    salt                    text        NOT NULL,
    block_login             boolean     NOT NULL,
    block_login_reason      text,
    block_login_type        text,
    tokens_blocked_after    integer,
    registered_time         integer,    NOT NULL,
    registered_ip           text,
    last_ip_login           text,
    admin                   boolean     NOT NULL,

    PRIMARY KEY("id" AUTOINCREMENT)
);


DROP TABLE IF EXISTS banned_tokens;

CREATE TABLE banned_tokens (
    user_id     integer     NOT NULL,
    token       text        NOT NULL,
    banned_time text        NOT NULL,
    reason      text,

    FOREIGN KEY (user_id)   REFERENCES users (id)
);