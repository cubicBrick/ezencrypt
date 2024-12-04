from keyring import set_password, get_password
from cryptography.fernet import Fernet
from util import getpass_char
from meshpwdkey import mesh, getkey
from hashlib import sha3_512
from warnings import warn

def setFernetKey(
    pwd=None,
    *,
    key=Fernet.generate_key(),
    service_name="PYTHON_FERNET_KEY",
    user="main",
    userver="verify"
) -> bytes:
    if pwd == None:
        pwd = getpass_char()
    meshed = mesh(pwd, key)
    set_password(service_name, user, str(meshed))
    set_password(
        service_name, userver, sha3_512(sha3_512(pwd.encode()).hexdigest().encode()).hexdigest()
    )
    return key


def getFernetKey(
    pwd: str, *, service_name="PYTHON_FERNET_KEY", user="main", userver="verify"
) -> bytes:
    doublepwdhash = sha3_512(sha3_512(pwd.encode()).hexdigest().encode()).hexdigest()
    pwdverify = get_password(service_name, userver)
    if not (doublepwdhash == pwdverify):
        return None
    try:
        meshed = get_password(service_name, user)
        return getkey(int(meshed), pwd)
    except Exception:
        warn("Exception!")
        return None

