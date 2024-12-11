#   core.py : This program manages accounts to the server
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

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization
from hashlib import pbkdf2_hmac
from bcrypt import hashpw, gensalt
from uuid import uuid4
import json
import os
import base64
import re


def get_public_key_fingerprint(public_key):
    formatted = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    parts = formatted.split(b" ")
    key_bytes = base64.b64decode(parts[1])

    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_bytes)
    fingerprint = base64.b64encode(digest.finalize()).rstrip(b"=").decode("utf-8")

    return f"SHA256:{fingerprint}"


ROUNDS = 12


class account:
    def __init__(self, username: str, pwd: str, public: RSAPublicKey):
        if not re.match(r"^[a-zA-Z0-9]*$", username):
            raise ValueError("Username contains invalid chars!")
        self.username = username
        self.salt = str(uuid4())
        self.pwdhash = hashpw(pwd.encode(), gensalt(ROUNDS))
        self.public = public
        self.fingerprint = get_public_key_fingerprint(public)

    def jsonify(self):
        return json.dumps(
            {
                "username": self.username,
                "salt": self.salt,
                "pwdhash": self.pwdhash,
                "public": self.public,
                "fingerprint": self.fingerprint,
            }
        )

class accounts:
    def __init__(self):
        self.accounts : "list[account]" = []
    def toStr(self):
        res = ""
        for i in self.accounts:
            res += i.jsonify()
            res += "^"
        res = res[:len(res)-1]
        return res