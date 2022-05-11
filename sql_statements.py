class SQLStatements:
    # Return the user_id based of username
    get_user_id = '''
        SELECT user_id FROM users
        WHERE username=%s
    '''

    # Returns same as get_user + hashed_password and salt based of username
    get_user_and_password = '''
        SELECT username, fname, lname, created_on, block_login, block_login_reason, hashed_password, salt
        FROM users
        LEFT JOIN passwords
        ON passwords.user_id = users.user_id
        WHERE username=%s
    '''

    # Returns user_id, username, fname, lname, created_on, block_login, block_login_reason based of username
    get_user = '''
        SELECT user_id, username, fname, lname, created_on, block_login, block_login_reason
        FROM users
        WHERE username=%s
    '''

    # Check if user is admin
    # Returns users.user_id, username, granter_user_id, admins.created_on based of username
    # Only if user is admin
    is_admin = '''
        SELECT users.user_id, username, granter_user_id, admins.created_on
        FROM users
        RIGHT JOIN admins
        ON users.user_id = admins.user_id
        WHERE users.username=%s
    '''

    create_user = '''
        INSERT INTO users (username, fname, lname, created_on, block_login, block_login_reason)
        VALUES (%s, %s, %s, %s, %s, %s)
    '''

    add_admin = '''
        INSERT INTO admins (user_id, granter_user_id, created_on)
        VALUES ((SELECT user_id FROM users WHERE username=%s), (SELECT user_id FROM users WHERE username=%s), %s)
    '''

    add_user_password = '''
        INSERT INTO passwords (user_id, hashed_password, salt, last_changed, next_change)
        VALUES ((SELECT user_id FROM users WHERE username=%s), %s, %s, %s, %s)
    '''

    register_token = '''
        INSERT INTO access_tokens (user_id, jwt_token, access_token, expiration)
        VALUES ((SELECT user_id FROM users WHERE username=%s), %s, %s, %s)
    '''