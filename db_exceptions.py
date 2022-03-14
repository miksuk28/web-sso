class CannotExecuteSQL(Exception):
    pass

class UserAlreadyExists(Exception):
    pass

class IncorrectPassword(Exception):
    pass

class UserDoesNotExist(Exception):
    pass

class IncorrectPassword(Exception):
    pass

class MissingValue(Exception):
    pass

# Token exceptions
class ExpiredToken(Exception):
    pass

class InvalidToken(Exception):
    pass

class BlockedLogin(Exception):
    pass