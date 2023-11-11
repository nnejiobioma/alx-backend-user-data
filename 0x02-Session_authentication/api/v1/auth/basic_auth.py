#!/usr/bin/env python3
"""module  BasicAuth code.
"""
from typing import TypeVar
import base64
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ This manages the API authentication
    that inherits from Auth.
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ This extracts the Base64 part
        of the authorization header.
        """
        if authorization_header is None:
            return None
        elif type(authorization_header) is not str:
            return None
        elif authorization_header[:6] != "Basic ":
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
                                        self, base64_authorization_header: str
                                            ) -> str:
        """Decode the Base64 part of the
        authorization header.
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is not str:
            return None
        try:
            base64_authorization_header = base64.b64decode(
                                            base64_authorization_header)
        except Exception:
            return None
        return base64_authorization_header.decode("utf-8")

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """ This extract user credentials from
        the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return None, None
        elif type(decoded_base64_authorization_header) is not str:
            return None, None
        elif ":" not in decoded_base64_authorization_header:
            return None, None
        credentials = decoded_base64_authorization_header.split(":")
        return credentials[0], credentials[1]

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar("User"):
        """ This returns the user
        instance based on email and password.
        """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            user = User.search({"email": user_email})
        except Exception:
            return None
        if not user or len(user) == 0:
            return None
        if not user[0].is_valid_password(user_pwd):
            return None
        return user[0]

    def current_user(self, request=None) -> TypeVar("User"):
        """ This overloads Auth and retrieves the
        user instance for a request.
        """
        authHeader = self.authorization_header(request=request)
        extB64 = (self.extract_base64_authorization_header(authHeader))
        decodeB64 = (self.decode_base64_authorization_header(extB64))
        extractUser = self.extract_user_credentials(decodeB64)
        userObject = self.user_object_from_credentials(
            user_email=extractUser[0],
            user_pwd=extractUser[1])
        return userObject
