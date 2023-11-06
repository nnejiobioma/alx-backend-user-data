#!/usr/bin/env python3
""" Auth class.
"""
from typing import List, TypeVar
from flask import request


class Auth:
    """Manage the API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Method that Return true if the path is not in
	the list of strings.
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
        """Validate all requests to protect the API.
        """
        if request is None:
            return None
        if "Authorization" not in request.headers:
            return None
        else:
            return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """ Method that Return:
        None - request.
        """
        return None