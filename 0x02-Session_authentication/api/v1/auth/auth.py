#!/usr/bin/env python3
""" Class Auth Classes.
"""
from flask import request
from typing import List, TypeVar
from os import getenv


class Auth:
    """Manage the API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Method
        The path is not in the list of strings.
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != "/":
            path += "/"
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Method to validate all requests to protect the API.
        None - request.
        """
        if request is None:
            return None
        if "Authorization" not in request.headers:
            return None
        else:
            return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """ Method
        Args:request.
        """
        return None

    def session_cookie(self, request=None):
        """ Returns a cookie value from a request.
        """
        if request is None:
            return None
        return request.cookies.get(getenv('SESSION_NAME'))
