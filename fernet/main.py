from keywork import *
from util import *
yeskw = ['y', 'yes', 'ok']
nokw = ['n', 'no']
def yesNo(prompt : str)-> (bool | None):
    i = input(prompt).lower()
    if i in yeskw:
        return True
    if i in nokw:
        return False
    return None
print("Welcome to the Fernet system!")

while 1:
    print("============OPTIONS=============")
    print("e - Encrypt new message")
    print("d - Decrypt message")
    print("s - Save key (will overwrite old keys)")
    print("q - Quit this program")
    option = input("Which option? ")
    if option == 'e':
        msg = getpass_char("Enter the message: ")
        pwd = getFernetKey(getpass_char("Enter your password: "))
        if(pwd is None):
            print("Incorrect password!")
        else:
            en = Fernet(pwd)
            print("Encrypted message: " + str(en.encrypt(msg.encode()))[2:-1])
    elif option == 'd':
        msg = input("Enter the encrypted message: ")
        pwd = getFernetKey(getpass_char("Enter your password: "))
        if(pwd is None):
            print("Incorrect password1")
        else:
            en = Fernet(pwd)
            printAndRemove(en.decrypt(msg.encode()).decode())
    elif option == 's':
        pwd = getpass_char("Enter a password to secure this key: ")
        key = getpass_char("Enter the new key, or leave it blank for a random key: ")
        if key == "":
            key = Fernet.generate_key()
            setFernetKey(pwd, key = key)
            printAndRemove("Random key: " + key.decode())
        else:
            setFernetKey(pwd, key=key)
    elif option == 'q':
        print("Quitting...")
        break
    else:
        print("That input was not recognized!")