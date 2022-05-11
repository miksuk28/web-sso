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
            "fname":                    {"type": "string"},
            "lname":                    {"type": "string"},
            "block_login":              {"type": "boolean"},
            "block_login_reason":       {"type": "string"},
            "admin":                    {"type": "boolean"}
        },
        "required": ["username", "password"]
    }