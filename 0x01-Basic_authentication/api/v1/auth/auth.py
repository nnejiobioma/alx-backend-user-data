#!/usr/bin/env python3
"""
Module for authentication
"""
from typing import List, TypeVar

from flask import request


class Auth():
    """All authentication system implemented in this app.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Function That takes a path and a list of
        excluded paths as arguments
        and returns a boolean value.
        """
        if not path:
            return True
        if not excluded_paths:
            return True
        path = path.rstrip("/")

        for excluded_path in excluded_paths:
            if excluded_path.endswith("*") and \
                    path.startswith(excluded_path[:-1]):
                return False
            elif path == excluded_path.rstrip("/"):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Value of the Authorization header from the request
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        return None
