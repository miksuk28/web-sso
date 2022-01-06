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
    "debug": True,
    # Address to host server on
    "address": "127.0.0.1",
    # Port to host server on
    "port": 5000,
    # How many seconds tokens will be valid for
    "token_valid_time": 120,
    # Returned by /authstatus endpoint
    "auth_status_message": _server_status_codes,
    # secret_config.py location, currently does nothing
    "secret_config_location": "",
    # Block date which overrides all user blocks
    "global_dissalow_tokens_before": 0
}
