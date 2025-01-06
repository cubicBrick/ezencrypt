import os
os.system("pip install cryptography keyring werkzeug pyperclip bcrypt pqcrypto --user")
configdir = os.path.join(os.path.dirname(__file__), "ezencrypt\\config")
requiredFiles = ["enc.txt", "keys.json", "keysenc.txt", "salt.txt"]
for i in requiredFiles:
    if not os.path.exists(os.path.join(configdir, i)):
        open(os.path.join(configdir, i), "x").close()