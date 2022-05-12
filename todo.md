# What to do in rewrite

* Create an API to authenticate Users
* Do not store service permissions here

* Make REST-approved
* Add validation to user input
* Make db respect blocked_login
  
Flask Decorator Boilerplate
´´´
from functools import wraps

def json_validator(requred_arg, *args, **kwargs):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
        
            #### PUT CODE TO RUN HERE ####        
  
        return wrapper
    return decorator
´´´
