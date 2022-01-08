
from os import execlpe


class UserAlreadyExists(Exception):
    pass

class IncorrectPassword(Exception):
    pass

class UserNotFound(Exception):
    pass

class UserBlocked(Exception):
    pass

class PasswordTooShort(Exception):
    pass

class TokenExpired(Exception):
    pass

class TokenInvalid(Exception):
    pass

class NotAllowedInProduction(Exception):
    pass