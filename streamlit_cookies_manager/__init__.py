"""
Streamlit component to manage cookies from Python.

This package exposes two main classes:
- `CookieManager`: read/write/delete cookies.
- `EncryptedCookieManager`: same API with transparent encryption.
"""

from .cookie_manager import CookieManager
from .encrypted_cookie_manager import EncryptedCookieManager

__all__ = ["CookieManager", "EncryptedCookieManager"]
