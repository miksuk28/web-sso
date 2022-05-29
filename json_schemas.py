class JSONSchemas:
    login = {
        "type" : "object",
        "properties" : {
            "username" : {"type" : "string"},
            "password" : {"type" : "string"}
        },
        "required": ["username", "password"]
    }

    token = {
        "type": "object",
        "properties": {
            "token": {"type": "string"}
        },
        "required": ["token"]
    }

    register = {
        "type": "object",
        "properties": {
            "username":                 {"type": "string"},
            "password":                 {"type": "string"},
            "autoGeneratePassword":     {"type": "boolean"},
            "changePasswordOnFirstLogin": {"type": "boolean"},
            "fname":                    {"type": "string"},
            "lname":                    {"type": "string"},
            "blockLogin":               {"type": "boolean"},
            "blockLoginReason":         {"type": "string"},
            "email":                    {"type": "string"},
        },
        "required": ["username", "autoGeneratePassword", "email"]
    }

    delete_users = {
        "type": "object",
        "properties": {
            "usersToDelete": {"type": "array"}
        },
        "required": ["usersToDelete"]
    }