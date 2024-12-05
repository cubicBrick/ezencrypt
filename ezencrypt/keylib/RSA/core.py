import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def rsa_encrypt_fernet_key(public_key, fernet_key: bytes) -> bytes:
    """
    Encrypt a Fernet key using an RSA public key.
    
    Args:
        public_key: The RSA public key.
        fernet_key (bytes): The Fernet key to encrypt.
        
    Returns:
        bytes: The RSA-encrypted Fernet key.
    """
    return public_key.encrypt(
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_fernet_key(private_key, encrypted_fernet_key: bytes) -> bytes:
    """
    Decrypt an RSA-encrypted Fernet key using an RSA private key.
    
    Args:
        private_key: The RSA private key.
        encrypted_fernet_key (bytes): The RSA-encrypted Fernet key.
        
    Returns:
        bytes: The decrypted Fernet key.
    """
    return private_key.decrypt(
        encrypted_fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_fernet_encrypt(public_key, message: str) -> str:
    """
    Encrypt a string message using an RSA-encrypted Fernet key and return a string.

    Args:
        public_key: The RSA public key.
        message (str): The message to encrypt.
        
    Returns:
        str: A base64-encoded string containing both the RSA-encrypted Fernet key
             and the Fernet-encrypted message, concatenated with a delimiter.
    """
    # Generate a Fernet key
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)

    # Encrypt the Fernet key with the RSA public key
    rsa_fernet_key = rsa_encrypt_fernet_key(public_key, fernet_key)

    # Encrypt the message with the Fernet key
    fernet_encrypted_message = fernet.encrypt(message.encode())

    # Encode both components as base64 strings and concatenate them
    return (
        base64.b64encode(rsa_fernet_key).decode() + ":" +
        base64.b64encode(fernet_encrypted_message).decode()
    )


def rsa_fernet_decrypt(private_key, encrypted_data: str) -> str:
    """
    Decrypt a string message encrypted with an RSA-protected Fernet key.
    
    Args:
        private_key: The RSA private key.
        encrypted_data (str): A base64-encoded string containing the RSA-encrypted
                              Fernet key and the Fernet-encrypted message, concatenated with a delimiter.
        
    Returns:
        str: The decrypted original message.
    """
    # Split the encrypted data into the RSA-encrypted Fernet key and the Fernet-encrypted message
    rsa_fernet_key_b64, fernet_encrypted_message_b64 = encrypted_data.split(":")
    rsa_fernet_key = base64.b64decode(rsa_fernet_key_b64)
    fernet_encrypted_message = base64.b64decode(fernet_encrypted_message_b64)

    # Decrypt the Fernet key using the RSA private key
    fernet_key = rsa_decrypt_fernet_key(private_key, rsa_fernet_key)

    # Decrypt the message using the Fernet key
    fernet = Fernet(fernet_key)
    return fernet.decrypt(fernet_encrypted_message).decode()
