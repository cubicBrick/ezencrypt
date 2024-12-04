import hashlib

def mesh(pwd : str, key : bytes) -> int:
    pwdhash = hashlib.sha3_512(pwd.encode()).hexdigest()
    return int.from_bytes(pwdhash.encode()) ^ int.from_bytes(key)
def getkey(meshed : int, pwd : str) -> bytes:
    pwdhash = hashlib.sha3_512(pwd.encode()).hexdigest()
    return (meshed ^ int.from_bytes(pwdhash.encode())).to_bytes(64).strip(b'\x00')