CREATE TABLE IF NOT EXISTS users (
	user_id SERIAL PRIMARY KEY,
	username VARCHAR(30) UNIQUE NOT NULL,
	fname VARCHAR(40),
	lname VARCHAR(40),
	created_on TIMESTAMP NOT NULL,
	block_login BOOLEAN NOT NULL,
	block_login_reason VARCHAR
);

CREATE TABLE IF NOT EXISTS passwords (
	user_id SERIAL NOT NULL UNIQUE,
	hashed_password VARCHAR NOT NULL,
	salt VARCHAR NOT NULL,
	last_changed TIMESTAMP NOT NULL,
	next_change TIMESTAMP,
	
	FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admins (
	user_id SERIAL NOT NULL UNIQUE,
	granter_user_id SERIAL NOT NULL,
	created_on TIMESTAMP NOT NULL,

	FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
	FOREIGN KEY (granter_user_id) REFERENCES users (user_id) 
);

CREATE TABLE IF NOT EXISTS access_tokens (
	user_id SERIAL NOT NULL UNIQUE,
	jwt_token VARCHAR NOT NULL UNIQUE,
	access_token VARCHAR NOT NULL UNIQUE,
	expiration TIMESTAMP NOT NULL,

	FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);