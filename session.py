# session.py
from key_utils import decrypt_key # Import decrypt_key here as it's used by Session

class Session:
    """
    Manages the user's authentication state and holds the decrypted Fernet key
    for the duration of the session.
    """
    def __init__(self):
        self._authenticated = False
        self._password = None # Stores the master password (optional, could be removed if not needed after auth)
        self._fernet_key = None # Stores the decrypted Fernet key

    def login(self, master_password: str, fernet_key: bytes):
        """
        Authenticates the session and stores the master password and decrypted Fernet key.
        """
        self._authenticated = True
        self._password = master_password
        self._fernet_key = fernet_key

    def logout(self):
        """Logs out the session, clearing sensitive information."""
        self._authenticated = False
        self._password = None
        self._fernet_key = None

    def is_authenticated(self) -> bool:
        """Returns True if the user is currently authenticated, False otherwise."""
        return self._authenticated

    def get_password(self) -> str | None:
        """Returns the master password if authenticated, otherwise None."""
        return self._password if self._authenticated else None

    def get_fernet_key(self) -> bytes | None:
        """Returns the decrypted Fernet key if authenticated, otherwise None."""
        return self._fernet_key if self._authenticated else None
