#   add.py : This program manages adding a account to the server
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
from hashlib import pbkdf2_hmac
import os

HASH_ITERATIONS = 1_500_000

class account:
    def __init__(self, username : str, pwd : str, public: RSAPublicKey, privateHash: RSAPrivateKey):
        self.username = username
        self.salt = os.urandom(16)
        self.pwdhash = pbkdf2_hmac("SHA3_512", pwd, self.salt, HASH_ITERATIONS)
        self.public = public
        