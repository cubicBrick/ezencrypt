#   main.py : The main program
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

import json
import base64
from pyperclip import copy
import tkinter as tk
from tkinter import messagebox, dialog, ttk, simpledialog
from keyring import set_password, set_keyring
from keylib.RSA import rsa_fernet_encrypt, rsa_fernet_decrypt
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
)
from time import sleep
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os
import sys

def resource_path(relative_path):
    """Get the absolute path to a resource, accounting for PyInstaller."""
    # If the app is running as a PyInstaller bundle
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        # Otherwise, get the base path of the script
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)

CONFIG_PATH = resource_path("config\\keys.json")
ENCRYPTED_PATH = resource_path("config\\enc.txt")
SALT_PATH = resource_path("config\\salt.txt")
CONFIGENC_PATH = resource_path("config\\keysenc.txt")
ICON_PATH = resource_path("assets\\lock.png")
SMALL_ICON_PATH = resource_path("assets\\lock1616.png")
with open(ENCRYPTED_PATH, "r") as f:
    encrypted = f.read() == "1"


class ManageKeysDialog(simpledialog.Dialog):
    def __init__(self, parent, title="Manage Keys"):
        self.listkeys = self.load_keys()
        self.parent = parent
        super().__init__(parent, title)

    def body(self, master):
        tk.Label(master, text="Manage your keys below:").pack(pady=10)

        self.key_list = tk.Listbox(master, width=50, height=10)
        self.key_list.pack(pady=5)
        self.refresh_keys()

        # Buttons for managing keys
        button_frame = tk.Frame(master)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Add Key", command=self.add_key).pack(
            side="left", padx=5
        )
        tk.Button(button_frame, text="Remove Key", command=self.remove_key).pack(
            side="left", padx=5
        )
        tk.Button(button_frame, text="Edit Key", command=self.edit_key).pack(
            side="left", padx=5
        )
        self.share_button = tk.Button(
            button_frame, text="Share", command=self.share_key, state="disabled"
        )
        self.share_button.pack(side="left", padx=5)

        # Bind selection event
        self.key_list.bind("<<ListboxSelect>>", self.on_key_select)

    def load_keys(self):
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "w") as file:
                json.dump([], file)  # Initialize with an empty list
            return []
        try:
            with open(CONFIG_PATH, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            # Handle corrupted or empty file
            with open(CONFIG_PATH, "w") as file:
                json.dump([], file)  # Reinitialize the file
            return []

    def save_keys(self):
        with open(CONFIG_PATH, "w") as file:
            json.dump(self.listkeys, file, indent=2)

    def refresh_keys(self):
        self.key_list.delete(0, tk.END)
        for key in self.listkeys:
            self.key_list.insert(tk.END, f"{key['title']}")

    def on_key_select(self, event):
        # Enable or disable the Share button based on selection
        selected = self.key_list.curselection()
        if not selected:
            self.share_button.config(state="disabled")
            return
        selected_key = self.listkeys[selected[0]]
        if selected_key["type"] == "public":
            self.share_button.config(state="normal")
        else:
            self.share_button.config(state="disabled")

    def share_key(self):
        selected = self.key_list.curselection()
        if not selected:
            return
        selected_key = self.listkeys[selected[0]]

        # Locate the corresponding public key
        public_key_title = f"{selected_key['title']}"
        public_key = next(
            (k for k in self.listkeys if k["title"] == public_key_title), None
        )
        if not public_key:
            messagebox.showerror("Error", "Public key not found!")
            return

        # Display the public key in a dialog
        public_key_pem = public_key["key"]
        dialog = tk.Toplevel(self)
        dialog.title("Share Public Key")
        tk.Label(dialog, text="Public Key (PEM format):").pack(pady=10)
        text = tk.Text(dialog, wrap="word", width=80, height=20)
        text.insert("1.0", public_key_pem)
        text.config(state="disabled")  # Make read-only
        text.pack(pady=10)
        tk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)

    def add_key(self):
        title = simpledialog.askstring(
            "Add Key", "Enter a title for the key:", parent=self
        ).replace("-", "_")
        if not title:
            return
        key_type = simpledialog.askstring(
            "Add Key", "Enter the key type (new/public):", parent=self
        )
        if key_type not in ["new", "public"]:
            messagebox.showerror("Error", "Invalid key type!")
            return
        if key_type == "new":
            password = simpledialog.askstring(
                "Add Key", "Enter a password for the key:", show="*", parent=self
            )
            key = generate_private_key(public_exponent=65537, key_size=2048)
            key_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode()
                ),
            )
            publicKey = key.public_key()
            self.listkeys.append(
                {
                    "title": title + " - private",
                    "type": "private",
                    "key": key_bytes.decode(),
                }
            )
            self.listkeys.append(
                {
                    "title": title + " - public",
                    "type": "public",
                    "key": publicKey.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.PKCS1,
                    ).decode(),
                }
            )
        else:
            key = LargeInputDialog(
                self,
                "Key Input",
                "Enter the public key (should start with -----BEGIN PUBLIC KEY-----)",
            ).get_input()
            try:
                key_bytes = load_pem_public_key(key.encode())
                self.listkeys.append(
                    {
                        "title": title + " - public",
                        "type": "public",
                        "key": key_bytes.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.PKCS1,
                        ).decode(),
                    }
                )
            except ValueError:
                messagebox.showerror(APP_NAME, "You have supplied an invalid key!")
        self.save_keys()
        self.refresh_keys()

    def remove_key(self):
        selected = self.key_list.curselection()
        if not selected:
            messagebox.showerror(APP_NAME, "No key selected!")
            return
        if not messagebox.askyesno(
            APP_NAME,
            "Are you sure you want to remove the following key:\n"
            + str(
                self.listkeys[selected[0]]["title"] + "\nThis action is irriversable!"
            ),
        ):
            return
        del self.listkeys[selected[0]]
        self.save_keys()
        self.refresh_keys()

    def edit_key(self):
        selected = self.key_list.curselection()
        if not selected:
            messagebox.showerror(APP_NAME, "No key selected!")
            return
        key = self.listkeys[selected[0]]
        new_title = simpledialog.askstring(
            APP_NAME, "Enter a new title for the key:", initialvalue=key["title"]
        )
        if new_title:
            key["title"] = new_title
            self.save_keys()
            self.refresh_keys()


class LargeInputDialog(simpledialog.Dialog):
    def __init__(
        self, parent, title=None, prompt="Enter text:", width=50, height=10, show=""
    ):
        """
        Initialize the dialog with an optional 'show' argument.
        :param parent: The parent window
        :param title: The title of the dialog
        :param prompt: The prompt text to display
        :param width: The width of the text widget
        :param height: The height of the text widget
        :param show: A string to control whether the text is shown or masked (e.g., '*' to mask).
        """
        self.prompt = prompt
        self.width = width
        self.height = height
        self.show = show  # Show argument, used for masking text input
        self.input_text = None
        super().__init__(parent, title)

    def body(self, master):
        # Add a label for the prompt
        tk.Label(master, text=self.prompt, wraplength=400, justify="left").pack(pady=10)

        # Add a larger text entry widget
        self.text_entry = tk.Text(
            master, width=self.width, height=self.height, wrap="word"
        )

        if self.show:
            # Use a password-style input if 'show' is provided
            self.text_entry.config(show=self.show)

        self.text_entry.pack(pady=10)
        return self.text_entry  # Focus will be set on this widget

    def apply(self):
        # Retrieve the input text when OK is clicked
        self.input_text = self.text_entry.get("1.0", "end").strip()

    def get_input(self):
        return self.input_text


APP_NAME = "Secure Encryption/Decryption Application"


class mainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.geometry("400x300")
        self.root.resizable = True
        self.root.title(APP_NAME)
        self.encryptButton = tk.Button(
            root, text="Encrypt Message", command=self.encrypt, width=40
        ).pack(pady=10)
        self.decryptButton = tk.Button(
            root, text="Decrypt Message", command=self.decrypt, width=40
        ).pack(pady=10)
        self.managekeys = tk.Button(
            root, text="Manage Keys", command=self.manage_keys, width=40
        ).pack(pady=10)
        self.saveallbutton = tk.Button(
            root, text="Save All Changes/Change Master Key", command=self.saveAll, width=40
        ).pack(pady=10)
        if encrypted:
            tk.Button(
                root, text="Remove Master Key", command=self.removeMasterKey, width=40
            ).pack(pady=10)
        else:
            tk.Button(
                root, text="Add Master Key", command=self.addMasterKey, width=40
            ).pack(pady=10)

    def addMasterKey(self):
        global encrypted
        if not messagebox.askyesno(
            APP_NAME,
            "After adding/changing a master key, this program will restart.\nWARNING: If you forget the master key, you will lose all your information.",
        ):
            return
        pwd = simpledialog.askstring(
            APP_NAME, "Enter the new master key password", show="*"
        )
        if not pwd:
            return
        with open(ENCRYPTED_PATH, "w") as f:
            f.write("1")
        encrypted = True
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            hashes.SHA3_512(),
            32,
            salt,
            480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
        f = Fernet(key)
        with open(CONFIGENC_PATH, "w", encoding="utf-8") as cnfenc:
            with open(CONFIG_PATH, "r") as cnf:
                enc = f.encrypt(cnf.read().encode()).decode()
                cnfenc.write(enc)
                cnfenc.flush()
        with open(ENCRYPTED_PATH, "w") as f:
            f.write("1")
        with open(SALT_PATH, "wb") as f:
            f.write(salt)
        self.root.destroy()
        wipe()
        if not init():
            return
        new_root = tk.Tk()
        new_root.iconphoto(False, tk.PhotoImage(file=ICON_PATH), tk.PhotoImage(file=SMALL_ICON_PATH))
        mainWindow(new_root)
        new_root.mainloop()

    def removeMasterKey(self):
        global encrypted
        checkStr = int.from_bytes(os.urandom(2))
        if not simpledialog.askstring(
            APP_NAME,
            "Are you sure you want to destroy your master key?\nType "
            + str(checkStr)
            + " to verify",
        ) == str(checkStr):
            return
        with open(CONFIGENC_PATH, "w", encoding="utf-8") as cnfenc:
            with open(CONFIG_PATH, "r") as cnf:
                cnfenc.write(cnf.read())
        with open(ENCRYPTED_PATH, "w") as f:
            f.write("0")
        encrypted = False
        self.root.destroy()
        wipe()
        if not init():
            return
        new_root = tk.Tk()
        new_root.iconphoto(False, tk.PhotoImage(file=ICON_PATH), tk.PhotoImage(file=SMALL_ICON_PATH))
        mainWindow(new_root)
        new_root.mainloop()

    def load_keys(self):
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "w") as file:
                json.dump([], file)  # Initialize with an empty list
            return []
        try:
            with open(CONFIG_PATH, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            # Handle corrupted or empty file
            with open(CONFIG_PATH, "w") as file:
                json.dump([], file)  # Reinitialize the file
            return []

    def encrypt(self):
        # Prompt user to enter the message to encrypt
        msg = LargeInputDialog(
            self.root, APP_NAME, "Enter your text to encrypt"
        ).get_input()
        if not msg:
            messagebox.showerror(APP_NAME, "No message provided for encryption!")
            return

        # Fetch available public keys
        public_keys = [key for key in self.load_keys() if key["type"] == "public"]
        if not public_keys:
            messagebox.showerror(APP_NAME, "No public keys available! Please add one.")
            return

        # Fetch available private keys
        private_keys = [key for key in self.load_keys() if key["type"] == "private"]
        if not private_keys:
            messagebox.showerror(APP_NAME, "No private keys available! Please add one.")
            return

        # Create a dialog for selecting a public key (for encryption)
        select_dialog = tk.Toplevel(self.root)
        select_dialog.transient(self.root)
        select_dialog.title("Select Public Key for Encryption")
        tk.Label(select_dialog, text="Select a public key for encryption:").pack(pady=10)

        public_key_titles = [key["title"] for key in public_keys]
        selected_public_key = tk.StringVar()
        public_key_dropdown = ttk.Combobox(
            select_dialog,
            values=public_key_titles,
            state="readonly",
            textvariable=selected_public_key,
        )
        public_key_dropdown.pack(pady=10)
        public_key_dropdown.current(0)  # Default to the first key

        def confirm_public_key_selection():
            select_dialog.destroy()

        tk.Button(select_dialog, text="OK", command=confirm_public_key_selection).pack(pady=5)

        # Wait for the dialog to close
        select_dialog.transient(self.root)
        self.root.wait_window(select_dialog)

        public_key_title = selected_public_key.get()
        if not public_key_title:
            messagebox.showerror(APP_NAME, "No public key selected!")
            return

        # Retrieve the selected public key
        selected_public_key_data = next(
            key for key in public_keys if key["title"] == public_key_title
        )
        public_key_pem = selected_public_key_data["key"]

        # Create a dialog for selecting a private key (for signing)
        select_dialog = tk.Toplevel(self.root)
        select_dialog.transient(self.root)
        select_dialog.title("Select Private Key for Signing")
        tk.Label(select_dialog, text="Select a private key for signing:").pack(pady=10)

        private_key_titles = [key["title"] for key in private_keys]
        selected_private_key = tk.StringVar()
        private_key_dropdown = ttk.Combobox(
            select_dialog,
            values=private_key_titles,
            state="readonly",
            textvariable=selected_private_key,
        )
        private_key_dropdown.pack(pady=10)
        private_key_dropdown.current(0)  # Default to the first key

        def confirm_private_key_selection():
            select_dialog.destroy()

        tk.Button(select_dialog, text="OK", command=confirm_private_key_selection).pack(pady=5)

        # Wait for the dialog to close
        select_dialog.transient(self.root)
        self.root.wait_window(select_dialog)

        private_key_title = selected_private_key.get()
        if not private_key_title:
            messagebox.showerror(APP_NAME, "No private key selected!")
            return

        # Retrieve the selected private key
        selected_private_key_data = next(
            key for key in private_keys if key["title"] == private_key_title
        )
        private_key_pem = selected_private_key_data["key"]

        # Ask for the password to decrypt the private key if encrypted
        password = simpledialog.askstring(
            APP_NAME, f"Enter the password for the private key: {private_key_title}", show="*"
        )
        if not password:
            messagebox.showerror(APP_NAME, "No password provided for the private key!")
            return

        try:
            # Decrypt the private key using the provided password
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=password.encode()
            )
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to load or decrypt the key(s): {e}")
            return

        # Encrypt the message using RSA and Fernet
        try:
            encrypted_message = rsa_fernet_encrypt(public_key, private_key, msg)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Encryption failed: {e}")
            return

        # Display the encrypted message
        dialog = tk.Toplevel(self.root)
        dialog.title("Encrypted Message")
        tk.Label(dialog, text="Your encrypted message:").pack(pady=10)
        text = tk.Text(dialog, wrap="word", width=80, height=10)
        text.insert("1.0", encrypted_message)
        text.config(state="disabled")  # Make it read-only
        text.pack(pady=10)
        tk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
        tk.Button(
            dialog, text="Copy to clipboard", command=copy(encrypted_message)
        ).pack(pady=5)


    def decrypt(self):
        # Prompt user to enter the encrypted message
        encrypted_message = LargeInputDialog(
            self.root, APP_NAME, "Enter the encrypted message:"
        ).get_input()
        if not encrypted_message:
            messagebox.showerror(APP_NAME, "No encrypted message provided!")
            return

        # Fetch available private keys
        keys = [key for key in self.load_keys() if key["type"] == "private"]
        if not keys:
            messagebox.showerror(APP_NAME, "No private keys available! Please add one.")
            return

        # Create a dialog for selecting a private key
        select_dialog = tk.Toplevel(self.root)
        select_dialog.transient(self.root)
        select_dialog.title("Select Private Key")
        tk.Label(select_dialog, text="Select a private key for decryption:").pack(
            pady=10
        )

        key_titles = [key["title"] for key in keys]
        selected_key = tk.StringVar()
        key_dropdown = ttk.Combobox(
            select_dialog,
            values=key_titles,
            state="readonly",
            textvariable=selected_key,
        )
        key_dropdown.pack(pady=10)
        key_dropdown.current(0)

        def confirm_selection():
            select_dialog.destroy()

        tk.Button(select_dialog, text="OK", command=confirm_selection).pack(pady=5)

        # Wait for the dialog to close
        select_dialog.transient(self.root)
        select_dialog.grab_set()
        self.root.wait_window(select_dialog)

        selected_key_title = selected_key.get()
        if not selected_key_title:
            messagebox.showerror(APP_NAME, "No key selected!")
            return

        # Retrieve the selected key
        selected_key_data = next(
            key for key in keys if key["title"] == selected_key_title
        )
        private_key_pem = selected_key_data["key"]

        # Prompt for the private key password
        password = simpledialog.askstring(
            APP_NAME, "Enter the password for the private key:", show="*"
        )
        if not password:
            messagebox.showerror(APP_NAME, "No password provided for the private key!")
            return

        # Load the private key
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=password.encode(),
            )
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to load the private key: {e}")
            return

        # Decrypt the message
        try:
            works = False
            correct = 0
            for public_key_data in self.load_keys():
                try:
                    public_key_pem = public_key_data["key"]
                    public_key = serialization.load_pem_public_key(public_key_pem.encode())

                    decrypted_message = rsa_fernet_decrypt(private_key, public_key, encrypted_message)
                    works = True
                    correct = public_key_data
                except Exception: pass
                if works:
                    break
            if works:
                messagebox.showinfo(APP_NAME, f"This message is verified ✅\nto come from the sender: " + correct["title"])
            else:
                messagebox.showinfo(APP_NAME, "This message is not verified to come from any of your senders")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Decryption failed: {e}")
            return

        # Display the decrypted message
        dialog = tk.Toplevel(self.root)
        dialog.title("Decrypted Message")
        tk.Label(dialog, text="Your decrypted message:").pack(pady=10)
        text = tk.Text(dialog, wrap="word", width=80, height=10)
        text.insert("1.0", decrypted_message)
        text.config(state="disabled")  # Make it read-only
        text.pack(pady=10)
        tk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)


    def saveAll(self):
        if encrypted:
            pwd = simpledialog.askstring(APP_NAME, "Enter the master key to secure your data", show="*")
            if pwd == "":
                return
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                hashes.SHA3_512(),
                32,
                salt,
                480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
            f = Fernet(key)
            with open(CONFIGENC_PATH, "w") as cnfenc:
                with open(CONFIG_PATH, "r") as cnf:
                    cnfenc.write(f.encrypt(cnf.read().encode()).decode())
            with open(SALT_PATH, "wb") as f:
                f.write(salt)
        else:
            with open(CONFIG_PATH, "r") as cnf:
                with open(CONFIGENC_PATH, "w") as cnfenc:
                    cnfenc.write(cnf.read())
        messagebox.showinfo(APP_NAME, "Changes saved!")

    def manage_keys(self):
        ManageKeysDialog(self.root)


def wipe():
    OVERWRITE_LEN = 1000000
    with open(CONFIG_PATH, "wb") as f:
        f.write(b"\x00" * OVERWRITE_LEN)
        f.seek(0)
        for i in range(1000):
            f.write(os.urandom(int(OVERWRITE_LEN)))
            f.flush()
            f.seek(0)
        f.write(b"\x00" * OVERWRITE_LEN)
    with open(CONFIG_PATH, "w"):
        pass

def init():
    try:
        if not os.path.exists(CONFIG_PATH):
            open(CONFIG_PATH, "x").close()
        if encrypted:
            pwd = simpledialog.askstring(
                APP_NAME, "Please enter the master password", show="*"
            )
            salt = b""
            with open(SALT_PATH, "rb") as f:
                salt = f.read()
            kdf = PBKDF2HMAC(
                hashes.SHA3_512(),
                32,
                salt,
                480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
            f = Fernet(key)
            with open(CONFIGENC_PATH, "rb") as cenc:
                with open(CONFIG_PATH, "w") as file:
                    file.write(f.decrypt(cenc.read()).decode())
        else:
            with open(CONFIGENC_PATH, "r") as cenc:
                with open(CONFIG_PATH, "w") as file:
                    file.write(cenc.read())
        return True
    except Exception:
        messagebox.showerror(
            APP_NAME,
            f"There was an error!{"\nYou may have entered the incorrect password." if encrypted else ""}",
        )
        return False

if __name__ == "__main__":
    if init():
        root = tk.Tk()
        large = tk.PhotoImage(file=ICON_PATH)
        small = tk.PhotoImage(file=SMALL_ICON_PATH)
        root.iconphoto(True, large, small)
        app = mainWindow(root)
        root.mainloop()
        wipe()
