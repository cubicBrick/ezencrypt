import json
from pyperclip import copy
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
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config\\keys.json")


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
            messagebox.showerror("Error", "No key selected!")
            return
        del self.listkeys[selected[0]]
        self.save_keys()
        self.refresh_keys()

    def edit_key(self):
        selected = self.key_list.curselection()
        if not selected:
            messagebox.showerror("Error", "No key selected!")
            return
        key = self.listkeys[selected[0]]
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


APP_NAME = "Secure Encryption/Decryption Application"


class mainWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.geometry("400x300")
        self.root.resizable = True
        self.root.title(APP_NAME)
        self.encryptButton = tk.Button(
            root, text="Encrypt Message", command=self.encrypt, width=20
        ).pack(pady=10)
        self.decryptButton = tk.Button(
            root, text="Decrypt Message", command=self.decrypt, width=20
        ).pack(pady=10)
        self.managekeys = tk.Button(
            root, text="Manage Keys", command=self.manage_keys, width=20
        ).pack(pady=10)

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
        keys = [key for key in self.load_keys() if key["type"] == "public"]
        if not keys:
            messagebox.showerror(APP_NAME, "No public keys available! Please add one.")
            return

        # Create a dialog for selecting a public key
        select_dialog = tk.Toplevel(self.root)
        select_dialog.transient(self.root)
        select_dialog.title("Select Public Key")
        tk.Label(select_dialog, text="Select a public key for encryption:").pack(
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
        key_dropdown.current(0)  # Default to the first key

        def confirm_selection():
            select_dialog.destroy()

        tk.Button(select_dialog, text="OK", command=confirm_selection).pack(pady=5)

        # Wait for the dialog to close
        select_dialog.transient(self.root)
        self.root.wait_window(select_dialog)

        selected_key_title = selected_key.get()
        if not selected_key_title:
            messagebox.showerror(APP_NAME, "No key selected!")
            return

        # Retrieve the selected key
        selected_key_data = next(
            key for key in keys if key["title"] == selected_key_title
        )
        public_key_pem = selected_key_data["key"]
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to load the public key: {e}")
            return

        # Encrypt the message
        try:
            encrypted_message = rsa_fernet_encrypt(public_key, msg)
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
        tk.Button(dialog, text="Copy to clipboard", command=copy(encrypted_message)).pack(pady=5)

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
            decrypted_message = rsa_fernet_decrypt(private_key, encrypted_message)
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

    def manage_keys(self):
        ManageKeysDialog(self.root)


if __name__ == "__main__":
    if not os.path.exists(CONFIG_PATH):
        open(CONFIG_PATH, 'x').close()
    root = tk.Tk()
    app = mainWindow(root)
    root.mainloop()
