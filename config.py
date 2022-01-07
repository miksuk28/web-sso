# Config dict imported by main.py

_server_status_codes = {
    # OK
    0: {"code": 0, "http_code": 200, "message": "Authserver is operational"},
    1: {"code": 1, "http_code": 503, "message": "Authserver is under maintenence. Please try again later"},
    2: {"code": 2, "http_code": 503, "message": "Authserver is currently disabled. Please try again later or contact the admin"}
}

config = {
    # Enable or disable Flask server debug mode and output debug info
    # SET TO FALSE IN PRODUCTION ENV.
    "debug": False,
    
    # Address to host server on
    "address": "127.0.0.1",
    
    # Port to host server on
    "port": 5000,
    
    # How to detect illegal auth attempt. SUPER IMPORTANT, if this fails, any IP may try to authenticate
    "block_ips_by": {
        # Whitelist of IPs allowed to authenticate. ONLY ADD OTHER, TRUSTED BACKEND SERVICES
        "trused_ips": [],
        
        # Will block any requests with these headers (headers set on requests coming from internet)
        "headers": ["X-Real-IP", "X-Forwarded-For"]
    },
        
    # How many seconds tokens will be valid for
    "token_valid_time": 10,
    
    # Allow anyone to register without admin permission
    "allow_register": True,
    
    # Returned by /authstatus endpoint
    "auth_status_message": _server_status_codes,
    
    # secret_config.py location, currently does nothing
    "secret_config_location": "",
    
    # db path
    "db_file": "users.db",

    # Block date which overrides all user blocks
    "global_dissalow_tokens_before": 0,
    
    # Username rules
    "username_rules": {
        "min_length": 4,
        "max_length": 30,
        
        # Charachters not allowd in username
        "banned_symbols": "",
        
        # Settings this to a string will only allow new username with these charachters, rest will be blocked
        "whitelist_symbols": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghjiklmnopqrstuvwxyz1234567890_!#¤%&£$€"
    },
    
    # Password rules
    "password_rules": {
        "min_length": 8,
        "require_uppercase": False,
        "require_special_char": False,
        "require_num": False
    }
}
