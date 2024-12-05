import tkinter as tk
from tkinter import messagebox, simpledialog
from keylib import getFernetKey, setFernetKey
from cryptography.fernet import Fernet
from pyperclip import copy

class LargeInputDialog(simpledialog.Dialog):
    """Custom dialog with larger input area."""

    def __init__(self, parent, title=None, prompt="Enter text:", width=50, height=10):
        self.prompt = prompt
        self.width = width
        self.height = height
        self.input_text = None
        super().__init__(parent, title)

    def body(self, master):
        """Create dialog body."""
        # Add a label for the prompt
        tk.Label(master, text=self.prompt, wraplength=400, justify="left").pack(pady=10)

        # Add a larger text entry widget
        self.text_entry = tk.Text(master, width=self.width, height=self.height)
        self.text_entry.pack(pady=10)
        return self.text_entry  # Focus will be set on this widget

    def apply(self):
        """Retrieve the input text when OK is clicked."""
        self.input_text = self.text_entry.get("1.0", "end").strip()

    def get_input(self):
        """Return the user input."""
        return self.input_text

APP_NAME = "Encryptor!"

class SecureEncryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureEncrypt")
        self.root.geometry("600x400")  # Set initial window size

        # Create buttons for each action
        self.encrypt_button = tk.Button(root, text="Encrypt Message", command=self.encrypt_message, width=20, height=2)
        self.decrypt_button = tk.Button(root, text="Decrypt Message", command=self.decrypt_message, width=20, height=2)
        self.save_key_button = tk.Button(root, text="Save New Key", command=self.save_key, width=20, height=2)
        self.quit_button = tk.Button(root, text="Quit", command=root.quit, width=20, height=2)

        # Layout buttons with padding
        self.encrypt_button.pack(pady=20, padx=20, fill=tk.X)
        self.decrypt_button.pack(pady=20, padx=20, fill=tk.X)
        self.save_key_button.pack(pady=20, padx=20, fill=tk.X)
        self.quit_button.pack(pady=20, padx=20, fill=tk.X)

    def encrypt_message(self):
        """Encrypts a message with the user's Fernet key."""
        msg = simpledialog.askstring("Encrypt Message", "Enter the message to encrypt:", show="")
        if not msg:
            return

        pwd = simpledialog.askstring("Password", "Enter your password:", show="*")
        if not pwd:
            return

        key = getFernetKey(pwd)
        if key is None:
            messagebox.showerror("Error", "Incorrect password! Could not retrieve Fernet key.")
            return

        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(msg.encode()).decode()
        messagebox.showinfo("Encrypted Message", encrypted_message)
        copy(encrypted_message)
        messagebox.askyesno("")
        messagebox.showinfo("Copied to Clipboard", "Encrypted message copied to clipboard!")

    def decrypt_message(self):
        """Decrypts a message with the user's Fernet key."""
        msg = simpledialog.askstring("Decrypt Message", "Enter the encrypted message:")
        if not msg:
            return

        pwd = simpledialog.askstring("Password", "Enter your password:", show="*")
        if not pwd:
            return

        key = getFernetKey(pwd)
        if key is None:
            messagebox.showerror("Error", "Incorrect password! Could not retrieve Fernet key.")
            return

        try:
            fernet = Fernet(key)
            decrypted_message = fernet.decrypt(msg.encode()).decode()
            copy(decrypted_message)
            messagebox.showinfo("Decrypted Message", decrypted_message)
            messagebox.showinfo("Copied to Clipboard", "Decrypted message copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def save_key(self):
        """Saves a new Fernet key, secured with a password."""
        pwd = simpledialog.askstring("Save Key", "Enter a password to secure the new key:", show="*")
        if not pwd:
            return

        key = simpledialog.askstring(
            "New Key",
            "Enter the new key (leave blank to generate a random key):",
            show="*"
        )

        if not key:
            key = Fernet.generate_key()
            setFernetKey(pwd, key=key)
            messagebox.showinfo("Random Key", f"Generated random key:\n{key.decode()}")
        else:
            try:
                setFernetKey(pwd, key=key.encode())
                messagebox.showinfo("Success", "Key saved successfully!")
            except ValueError as e:
                messagebox.showerror("Error", f"Failed to save key: {e}")


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureEncryptApp(root)
    root.mainloop()
