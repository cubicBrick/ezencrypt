#   keylib/util/keystuff.py : Key combining functions for Fernet
#   Copyright (C) 2024  cubicBrick (GitHub account)

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.backends import default_backend
from typing import Optional

def derive_key(password: str, salt: bytes, length: int) -> bytes:
    """
    Derive a secure key from the password using PBKDF2.

    Args:
        password (str): The input password.
        salt (bytes): A random salt.
        length (int): The desired length of the derived key.

    Returns:
        bytes: The derived key.
    """
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes.")
    if length <= 0:
        raise ValueError("Key length must be greater than 0.")
    
    kdf = PBKDF2HMAC(
        algorithm=SHA512(),
        length=length,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def mesh(pwd: str, key: bytes, salt: bytes) -> bytes:
    """
    Combines a password and a key using XOR and a derived key.

    Args:
        pwd (str): The password.
        key (bytes): The data to secure (e.g., a cryptographic key).
        salt (bytes): A random salt for deriving the key.

    Returns:
        bytes: The meshed result.

    Raises:
        ValueError: If the key length is invalid.
    """
    if len(key) <= 0:
        raise ValueError("Key must not be empty.")
    derived_key = derive_key(pwd, salt, length=len(key))
    return bytes(a ^ b for a, b in zip(derived_key, key))


def unmesh(meshed: bytes, pwd: str, salt: bytes) -> bytes:
    """
    Retrieves the original data from meshed data and password.

    Args:
        meshed (bytes): The meshed data.
        pwd (str): The password.
        salt (bytes): The salt used for deriving the key.

    Returns:
        bytes: The original data.

    Raises:
        ValueError: If the meshed data length is invalid.
    """
    if len(meshed) <= 0:
        raise ValueError("Meshed data must not be empty.")
    derived_key = derive_key(pwd, salt, length=len(meshed))
    return bytes(a ^ b for a, b in zip(meshed, derived_key))
