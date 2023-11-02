#!/usr/bin/env python3
"""
Password functions.
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    hashed password Returns
    """
    pass = password.encode()
    hashed = hashpw(pass, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    password is checked for valid    
    """
    return bcrypt.checkpw(password.encode(), hashed_password)

