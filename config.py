# Config dict imported by main.py

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
    "auth_status_message": {"auth_server_status": "OK"},
    # secret_config.py location, currently does nothing
    "secret_config_location": "",
    # Block all tokens before certain date
    "block_tokens_before": 0
}