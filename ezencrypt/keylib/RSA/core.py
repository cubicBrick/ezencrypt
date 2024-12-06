#   keylib/RSA/core.py : RSA key signing and encryption helpers
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

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils

def sign_message(private_key, message: bytes) -> bytes:
    """
    Sign a message with an RSA private key.
    
    Args:
        private_key: The RSA private key.
        message (bytes): The message to sign.
        
    Returns:
        bytes: The signature.
    """
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

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


def rsa_fernet_encrypt(public_key, private_key, message: str) -> str:
    """
    Encrypt and sign a string message using RSA and Fernet keys.
    
    Args:
        public_key: The RSA public key for encryption.
        private_key: The RSA private key for signing.
        message (str): The message to encrypt and sign.
        
    Returns:
        str: A base64-encoded string containing the RSA-encrypted Fernet key,
             the Fernet-encrypted message, and the signature, concatenated with a delimiter.
    """
    # Generate a Fernet key
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)

    # Encrypt the Fernet key with the RSA public key
    rsa_fernet_key = rsa_encrypt_fernet_key(public_key, fernet_key)

    # Encrypt the message with the Fernet key
    fernet_encrypted_message = fernet.encrypt(message.encode())

    # Compute the hash of the encrypted message and sign it
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(fernet_encrypted_message)
    digest = message_hash.finalize()
    signature = sign_message(private_key, digest)

    # Encode all components as base64 strings and concatenate them
    return (
        base64.b64encode(rsa_fernet_key).decode() + ":" +
        base64.b64encode(fernet_encrypted_message).decode() + ":" +
        base64.b64encode(signature).decode()
    )

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify the signature of a message with an RSA public key.
    
    Args:
        public_key: The RSA public key.
        message (bytes): The message whose signature needs verification.
        signature (bytes): The signature to verify.
        
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def rsa_fernet_decrypt(private_key, public_key, encrypted_data: str) -> str:
    """
    Decrypt a string message and verify its integrity and authenticity.
    
    Args:
        private_key: The RSA private key for decryption.
        public_key: The RSA public key for verifying the signature.
        encrypted_data (str): A base64-encoded string containing the RSA-encrypted
                              Fernet key, the Fernet-encrypted message, and the signature.
        
    Returns:
        str: The decrypted original message if verification succeeds.
        
    Raises:
        ValueError: If verification fails.
    """
    # Split the encrypted data into components
    rsa_fernet_key_b64, fernet_encrypted_message_b64, signature_b64 = encrypted_data.split(":")
    rsa_fernet_key = base64.b64decode(rsa_fernet_key_b64)
    fernet_encrypted_message = base64.b64decode(fernet_encrypted_message_b64)
    signature = base64.b64decode(signature_b64)

    # Decrypt the Fernet key using the RSA private key
    fernet_key = rsa_decrypt_fernet_key(private_key, rsa_fernet_key)
    fernet = Fernet(fernet_key)

    # Verify the signature
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(fernet_encrypted_message)
    digest = message_hash.finalize()

    if not verify_signature(public_key, digest, signature):
        raise ValueError("Signature verification failed!")

    # Decrypt the message using the Fernet key
    return fernet.decrypt(fernet_encrypted_message).decode()

