#   keylib/Fernet/core.py : Fernet key storage program helpers
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

import hashlib
import os
from cryptography.fernet import Fernet
from keyring import set_password, get_password
from getpass import getpass
from warnings import warn
from typing import Optional
from base64 import b64encode, b64decode
from ..util import mesh, unmesh


def setFernetKey(
    pwd: Optional[str] = None,
    *,
    key: bytes = Fernet.generate_key(),
    service_name: str = "PYTHON_FERNET_KEY",
    user: str = "main",
    userver: str = "verify",
) -> bytes:
    """
    Stores the Fernet key securely in the keyring, protected by a password.

    Args:
        pwd (Optional[str]): Password for securing the key. If None, prompts the user.
        key (bytes): The Fernet key to store. Defaults to a newly generated key.
        service_name (str): Keyring service name.
        user (str): Keyring user for the key.
        userver (str): Keyring user for password verification.

    Returns:
        bytes: The Fernet key.
    """
    if pwd is None:
        pwd = getpass("Enter password: ")

    if len(key) != 44:
        raise ValueError("Fernet key must be 44 bytes.")

    # Generate a random salt
    salt = os.urandom(16)

    # Mesh the key
    meshed = mesh(pwd, key, salt)

    # Store the meshed key and the salt in the keyring
    set_password(service_name, user, b64encode(meshed + salt).decode())

    # Store a hashed verification of the password
    pwd_verify = hashlib.sha3_512(pwd.encode()).hexdigest()
    set_password(service_name, userver, pwd_verify)

    return key


def getFernetKey(
    pwd: str,
    *,
    service_name: str = "PYTHON_FERNET_KEY",
    user: str = "main",
    userver: str = "verify",
) -> Optional[bytes]:
    """
    Retrieves the Fernet key from the keyring if the password is correct.

    Args:
        pwd (str): The password to unlock the key.
        service_name (str): Keyring service name.
        user (str): Keyring user for the key.
        userver (str): Keyring user for password verification.

    Returns:
        Optional[bytes]: The Fernet key if the password is correct; otherwise, None.
    """
    pwd_verify = hashlib.sha3_512(pwd.encode()).hexdigest()
    stored_verify = get_password(service_name, userver)

    if stored_verify is None:
        warn("Password verification data not found in keyring.")
        return None

    if pwd_verify != stored_verify:
        warn("Password verification failed.")
        return None

    try:
        # Retrieve meshed data and salt from the keyring
        meshed_salt = get_password(service_name, user)
        if meshed_salt is None:
            warn("Meshed data not found in keyring.")
            return None

        meshed_salt_bytes = b64decode(meshed_salt)
        meshed, salt = meshed_salt_bytes[:-16], meshed_salt_bytes[-16:]

        # Unmesh to retrieve the original key
        return unmesh(meshed, pwd, salt)
    except Exception as e:
        warn(f"Exception during key retrieval: {e}")
        return None
