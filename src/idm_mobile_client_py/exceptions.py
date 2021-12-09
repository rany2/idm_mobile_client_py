# pylint: disable=missing-module-docstring, missing-class-docstring


class LoginFailed(Exception):
    pass


class HTTPStatusCodeError(Exception):
    pass


class BadJSONResponseCode(Exception):
    pass


class NoCredentials(Exception):
    pass


class NotJSONResponse(Exception):
    pass


class UnknownError(Exception):
    pass
