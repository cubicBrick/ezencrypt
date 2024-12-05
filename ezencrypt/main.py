import json
import tkinter as tk
from tkinter import messagebox, dialog, ttk, simpledialog
from keyring import set_password, set_keyring
from keylib.RSA import rsa_fernet_encrypt, rsa_fernet_decrypt
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
    RSAPrivateKeyWithSerialization,
    RSAPublicKeyWithSerialization,
    RSAPublicKey,
    RSAPrivateKey,
)
from cryptography.hazmat.primitives import serialization
import os

CONFIG_PATH = "config/keys.json"


class ManageKeysDialog(simpledialog.Dialog):
    def __init__(self, parent, title="Manage Keys"):
        self.allkeys = self.load_keys()
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

        tk.Button(button_frame, text="Add Key", command=self.add_key).pack(side="left", padx=5)
        tk.Button(button_frame, text="Remove Key", command=self.remove_key).pack(side="left", padx=5)
        tk.Button(button_frame, text="Edit Key", command=self.edit_key).pack(side="left", padx=5)
        self.share_button = tk.Button(button_frame, text="Share", command=self.share_key, state="disabled")
        self.share_button.pack(side="left", padx=5)

        # Bind selection event
        self.key_list.bind("<<ListboxSelect>>", self.on_key_select)

    def load_keys(self):
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as file:
                return json.load(file)
        return []

    def save_keys(self):
        with open(CONFIG_PATH, "w") as file:
            json.dump(self.keys, file, indent=2)

    def refresh_keys(self):
        self.key_list.delete(0, tk.END)
        for key in self.keys:
            self.key_list.insert(tk.END, f"{key['title']} ({key['type']})")

    def on_key_select(self, event):
        # Enable or disable the Share button based on selection
        selected = self.key_list.curselection()
        if not selected:
            self.share_button.config(state="disabled")
            return
        selected_key = self.keys[selected[0]]
        if selected_key["type"] == "private":  # "both" has a private key entry
            self.share_button.config(state="normal")
        else:
            self.share_button.config(state="disabled")

    def share_key(self):
        selected = self.key_list.curselection()
        if not selected:
            return
        selected_key = self.keys[selected[0]]

        # Locate the corresponding public key
        public_key_title = f"{selected_key['title']}_public"
        public_key = next((k for k in self.keys if k["title"] == public_key_title), None)
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
        title = simpledialog.askstring("Add Key", "Enter a title for the key:").replace("-", "_")
        if not title:
            return
        key_type = simpledialog.askstring(
            "Add Key", "Enter the key type (both/public):", parent=self.parent
        )
        if key_type not in ["both", "public"]:
            messagebox.showerror("Error", "Invalid key type!")
            return
        if key_type == "both":
            password = simpledialog.askstring(
                "Add Key", "Enter a password for the key:", show="*", parent=self.parent
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
            self.keys.append({"title": title, "type": key_type})
            self.save_keys()
        else:
            private_key = generate_private_key(public_exponent=65537, key_size=2048)
            key = private_key.public_key()
            key_bytes = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        self.keys().append({"title": title, "type": key_type, "key": key_bytes.decode()})
        self.save_keys()
        self.refresh_keys()

    def remove_key(self):
        selected = self.key_list.curselection()
        if not selected:
            messagebox.showerror("Error", "No key selected!")
            return
        del self.keys[selected[0]]
        self.save_keys()
        self.refresh_keys()

    def edit_key(self):
        selected = self.key_list.curselection()
        if not selected:
            messagebox.showerror("Error", "No key selected!")
            return
        key = self.keys[selected[0]]
        new_title = simpledialog.askstring(
            "Edit Key", "Enter a new title for the key:", initialvalue=key["title"]
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


APP_NAME = "Secure Encrypt Application"


class mainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.geometry("600x400")
        self.root.resizable = True
        self.root.title(APP_NAME)
        self.encryptButton = tk.Button(
            root, text="Encrypt Message", command=self.encrypt, width=20, height=2
        ).pack(pady=10)
        self.decyrptButton = tk.Button(
            root, text="Manage Keys", command=self.manage_keys, width=20
        ).pack(pady=10)

    def encrypt(self):
        # Create a dialog to get the text to encrypt
        msg = LargeInputDialog(
            self.root, APP_NAME, "Enter your text to encrypt"
        ).get_input()
        pwd = simpledialog.askstring(
            APP_NAME, "Enter your password:", show="*", parent=root
        )
        keys = None
        with open("/config/keys.txt") as f:
            data = f.read()
        keyid = simpledialog.askstring(
            APP_NAME, "Enter which key to use. You have saved the following keys:\n"
        )
        if pwd:
            encrypted = rsa_fernet_encrypt()
        else:
            simpledialog.SimpleDialog(root, "Password not provided!")

    def manage_keys(self):
        ManageKeysDialog(self.root)


if __name__ == "__main__":
    root = tk.Tk()
    app = mainWindow(root)
    root.mainloop()
