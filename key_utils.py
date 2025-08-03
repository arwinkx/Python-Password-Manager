#key_utils.py
from cryptography.fernet import Fernet
import base64
import os 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SALT_SIZE = 16 # 16 bytes is a good size for salt
ITERATIONS = 480000 # Recommended iterations for PBKDF2 (NIST recommendation as of 2023)

def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derives a 32-byte key from a string password using PBKDF2 with SHA256.
    Includes a salt to protect against rainbow table attacks and iterations
    to slow down brute-force attacks.
    Returns the derived key and the salt used.
    If no salt is provided, a new one is generated.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE) # Generate a new random salt

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet requires a 32-byte key
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    return derived_key, salt

def encrypt_key(fernet_key: bytes, master_password: str):
    """
    Encrypts the main Fernet key using a key derived from the master password
    via PBKDF2 and saves it to 'key.key.enc'.
    The salt used for PBKDF2 is prepended to the encrypted key in the file.
    """
    derived_key, salt = derive_key_from_password(master_password)
    # Fernet requires a URL-safe base64 encoded key
    fernet_cipher = Fernet(base64.urlsafe_b64encode(derived_key))
    encrypted_fernet_key = fernet_cipher.encrypt(fernet_key)

    # Store salt and encrypted key together
    with open("key.key.enc", "wb") as f:
        f.write(salt + encrypted_fernet_key) # Prepend salt to the encrypted key

def decrypt_key(master_password: str) -> bytes:
    """
    Decrypts the main Fernet key from 'key.key.enc' using a key derived
    from the master password.
    It first reads the salt from the file, then uses it with PBKDF2 to derive the key.
    Raises an exception if decryption fails (e.g., wrong password or corrupted file).
    """
    if not os.path.exists("key.key.enc"):
        raise FileNotFoundError("Encrypted key file 'key.key.enc' not found.")

    with open("key.key.enc", "rb") as f:
        file_content = f.read()

    if len(file_content) < SALT_SIZE:
        raise ValueError("Encrypted key file is too short or corrupted (missing salt).")

    salt = file_content[:SALT_SIZE] # Extract the salt from the beginning
    encrypted_fernet_key = file_content[SALT_SIZE:] # The rest is the encrypted key

    derived_key, _ = derive_key_from_password(master_password, salt=salt) # Use the extracted salt
    fernet_cipher = Fernet(base64.urlsafe_b64encode(derived_key))

    return fernet_cipher.decrypt(encrypted_fernet_key)
