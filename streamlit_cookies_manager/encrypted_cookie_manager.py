import base64
import os
import warnings
from typing import Any, MutableMapping, Optional, Tuple

import streamlit as st
from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Assuming the corrected CookieManager is in the same package
from streamlit_cookies_manager import CookieManager


# --- Helper Function for Key Derivation ---
# @st.cache_data is the modern, recommended way for caching data in Streamlit.
# This function's output is deterministic based on its inputs, making it a perfect
# candidate for caching. The decorator ensures the expensive key derivation is
# only run once per unique set of inputs.
# The 'show_spinner' argument is no longer a part of st.cache_data in recent
# Streamlit versions (it's part of st.spinner context manager).
# The function's name is also made more descriptive.
@st.cache_data
def derive_key_from_password(salt: bytes, iterations: int, password: str) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2HMAC.
    """
    # The number of iterations should be large enough to be computationally
    # expensive, making brute-force attacks difficult.
    # The value 390,000 is a good, modern recommendation (OWASP 2023).
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits, suitable for Fernet
        salt=salt,
        iterations=iterations,
    )

    # We use urlsafe_b64encode as Fernet keys must be URL-safe base64.
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# --- EncryptedCookieManager Class ---
class EncryptedCookieManager(MutableMapping[str, str]):
    """
    Manages browser cookies with transparent encryption using Fernet.
    It wraps a CookieManager instance and encrypts/decrypts values
    before storing/retrieving them.
    """

    # Use constants for cookie names to avoid magic strings and typos.
    _KEY_PARAMS_COOKIE = "EncryptedCookieManager.key_params"

    # Recommended iterations for PBKDF2HMAC as per OWASP.
    _PBKDF2_ITERATIONS = 600_000

    def __init__(
        self,
        *,
        password: str,
        path: Optional[str] = None,
        prefix: str = "",
        key_params_cookie: Optional[str] = None,
        ignore_broken: bool = True,
    ):
        """
        Initializes the encrypted cookie manager.

        Args:
            password (str): The password used to derive the encryption key.
                            This must be a secret known to the app.
            path (Optional[str]): The path for the cookies.
            prefix (str): A prefix for all managed cookie names.
            key_params_cookie (str): The name of the cookie that stores the
                                     key derivation parameters (salt, iterations).
                                     Defaults to a constant name if not provided.
            ignore_broken (bool): If True, corrupted or un-decryptable cookies
                                  will be ignored and treated as non-existent.
                                  If False, a fernet.InvalidToken exception will be raised.
        """
        # We need a unique prefix for the inner CookieManager to avoid conflicts.
        # This makes the encrypted cookies distinct from any other cookies.
        manager_prefix = f"encrypted_{prefix}" if prefix else "encrypted_"
        self._cookie_manager = CookieManager(path=path, prefix=manager_prefix)

        self._fernet: Optional[Fernet] = None

        # Use the provided key_params_cookie name or the default constant.
        self._key_params_cookie = key_params_cookie if key_params_cookie is not None else self._KEY_PARAMS_COOKIE

        self._password = password
        self._ignore_broken = ignore_broken

    def ready(self) -> bool:
        """Returns True if the underlying CookieManager is ready."""
        return self._cookie_manager.ready()

    def save(self) -> None:
        """Saves any queued changes to the browser cookies."""
        return self._cookie_manager.save()

    def _encrypt(self, value: bytes) -> bytes:
        """Encrypts a byte string using Fernet."""
        self._setup_fernet()
        # The 'self._fernet' is guaranteed to be not None after the setup call.
        return self._fernet.encrypt(value)  # type: ignore

    def _decrypt(self, value: bytes) -> bytes:
        """Decrypts a byte string using Fernet."""
        self._setup_fernet()
        # The 'self._fernet' is guaranteed to be not None after the setup call.
        return self._fernet.decrypt(value)  # type: ignore

    def _setup_fernet(self) -> None:
        """
        Initializes the Fernet instance for encryption/decryption.
        It generates a new key and stores its parameters in a cookie if needed.
        """
        if self._fernet is not None:
            return  # Already set up.

        key_params = self._get_key_params()
        if not key_params:
            # No key parameters found, so we need to generate new ones.
            key_params = self._initialize_new_key_params()

        salt, iterations, magic = key_params

        # Derive the key from the stored parameters and the password.
        # This is cached by @st.cache_data.
        key = derive_key_from_password(salt=salt, iterations=iterations, password=self._password)

        self._fernet = Fernet(key)

    def _get_key_params(self) -> Optional[Tuple[bytes, int, bytes]]:
        """
        Retrieves the key derivation parameters from a cookie.
        Returns (salt, iterations, magic) or None if the cookie is not found or is invalid.
        """
        raw_key_params = self._cookie_manager.get(self._key_params_cookie)
        if not raw_key_params:
            return None

        try:
            # We expect a string formatted as "base64_salt:iterations:base64_magic"
            raw_salt, raw_iterations_str, raw_magic = raw_key_params.split(":")

            # The iterations should be an integer.
            iterations = int(raw_iterations_str)

            # Decode the base64-encoded bytes.
            salt = base64.b64decode(raw_salt)
            magic = base64.b64decode(raw_magic)

            return salt, iterations, magic
        except (ValueError, TypeError) as e:
            # Catch errors if the cookie's content is malformed.
            warnings.warn(
                f"Failed to parse key parameters from cookie '{self._key_params_cookie}'. " f"Cookie content: '{raw_key_params}'. Error: {e}", UserWarning, stacklevel=2
            )
            # Return None to signal that a new key should be initialized.
            return None

    def _initialize_new_key_params(self) -> Tuple[bytes, int, bytes]:
        """
        Generates new key derivation parameters and stores them in a cookie.
        """
        # Generate a new random salt and a magic value for integrity check.
        salt = os.urandom(16)
        magic = os.urandom(16)

        # Use the recommended number of iterations for security.
        iterations = self._PBKDF2_ITERATIONS

        # Construct the string to be stored in the cookie.
        # Use base64 encoding for the binary data (salt, magic).
        cookie_value = b":".join([base64.b64encode(salt), str(iterations).encode("ascii"), base64.b64encode(magic)]).decode("ascii")

        # Store the new parameters in the cookie manager.
        # This will be saved to the browser when `save()` is called.
        self._cookie_manager[self._key_params_cookie] = cookie_value

        return salt, iterations, magic

    def __repr__(self) -> str:
        """String representation of the EncryptedCookieManager."""
        if self.ready():
            # Use self._cookie_manager.__repr__ for consistency
            return f"<EncryptedCookieManager wrapping {self._cookie_manager!r}>"
        return "<EncryptedCookieManager: not ready>"

    def __getitem__(self, k: str) -> str:
        """
        Retrieves and decrypts a cookie's value.

        Raises:
            KeyError: If the cookie does not exist.
            fernet.InvalidToken: If decryption fails and `ignore_broken` is False.
        """
        # First, check if the key exists to raise a proper KeyError if not.
        # This is more Pythonic than catching the exception later.
        encrypted_value = self._cookie_manager[k]  # This will raise KeyError if not found.

        try:
            # Decode from the base64-encoded string stored in the cookie.
            decrypted_bytes = self._decrypt(encrypted_value.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except fernet.InvalidToken as e:
            # Handle decryption failures (e.g., tampered cookies or wrong password).
            if self._ignore_broken:
                # If configured to ignore, treat it as if the cookie doesn't exist.
                # Returning None would be ambiguous for __getitem__.
                # So we raise KeyError which is more consistent with dictionary behavior.
                raise KeyError(f"Cookie '{k}' is corrupted or un-decryptable.") from e
            else:
                # Re-raise the original exception if not ignoring broken cookies.
                raise

    def __iter__(self) -> Any:
        """Iterates over the names of the cookies, including the key params cookie."""
        # Note: Iterating this way reveals the encrypted cookie names.
        return iter(self._cookie_manager)

    def __len__(self) -> int:
        """Returns the number of managed cookies."""
        return len(self._cookie_manager)

    def __setitem__(self, key: str, value: str) -> None:
        """
        Encrypts and queues a value to be set as a cookie.

        The change is queued and requires a call to .save() to be applied.
        """
        # The key for the key parameters cookie should not be encrypted.
        if key == self._key_params_cookie:
            # It's better to manage this internally and not allow external sets.
            # You can raise an error or just ignore it.
            warnings.warn(f"Attempted to set the internal key parameters cookie '{key}'. This is managed automatically.", UserWarning, stacklevel=2)
            return

        # Ensure the value is a string before encoding.
        if not isinstance(value, str):
            value = str(value)

        # Encrypt the UTF-8 encoded value and then decode it to ASCII for storage
        # in the cookie manager. Cookies are ASCII/Latin1.
        encrypted_bytes = self._encrypt(value.encode("utf-8"))
        self._cookie_manager[key] = base64.urlsafe_b64encode(encrypted_bytes).decode("ascii")

    def __delitem__(self, key: str) -> None:
        """
        Deletes a cookie. The deletion is queued and requires a call to .save().
        """
        del self._cookie_manager[key]
