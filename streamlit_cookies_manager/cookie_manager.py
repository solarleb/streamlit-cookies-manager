"""
Cookie manager Streamlit component backend.

Provides CookieManager, a dictionary-like interface to browser cookies.
"""

from collections.abc import Iterator, Mapping, MutableMapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from urllib.parse import unquote

import streamlit as st
from streamlit.components.v1 import declare_component

build_path = Path(__file__).parent / "build"
try:
    _component_func = declare_component("CookieManager.sync_cookies", path=str(build_path))
except FileNotFoundError as err:
    message = (
        "Could not find the component's 'build' directory at "
        f"'{build_path}'. Make sure to run 'npm run build' in your frontend "
        "directory and ensure that the 'build' folder is included in your package data."
    )
    raise RuntimeError(message) from err


# --- Custom Exception ---
class CookiesNotReady(Exception):
    """Raise when the CookieManager is not yet ready to read cookies."""


# --- Helper Function ---
def parse_cookies(raw_cookie: str) -> Mapping[str, str]:
    """
    Parse a raw cookie header into a dictionary.

    Returns a mapping from cookie names to values. Malformed parts are ignored.

    Returns:
        Mapping[str, str]: The parsed cookie dictionary.

    """
    cookies: dict[str, str] = {}
    if not raw_cookie:
        return cookies

    for part_raw in raw_cookie.split(";"):
        part = part_raw.strip()
        if not part:
            continue
        try:
            name, value = part.split("=", 1)
            # Use unquote to handle URL-encoded characters
            cookies[unquote(name)] = unquote(value)
        except ValueError:
            # Handle cases like malformed cookies (e.g., "name" or "=value")
            continue
    return cookies


# --- Main CookieManager Class ---
class CookieManager(MutableMapping[str, str]):
    """
    Manage browser cookies in a Streamlit application.

    Acts as a dictionary-like interface for reading and writing cookies.
    """

    # Define session state keys to avoid magic strings and potential typos.
    _QUEUE_KEY_PREFIX = "CookieManager.queue."
    _SYNC_KEY_PREFIX = "CookieManager.sync_cookies."
    _SAVE_KEY_PREFIX = "CookieManager.sync_cookies.save."

    def __init__(self, *, path: str | None = None, prefix: str = "") -> None:
        """
        Initialize the CookieManager.

        Args:
            path: The path for the cookies. Defaults to '/'.
            prefix: A prefix for all cookie names to avoid conflicts. Useful if you have
                multiple components setting cookies.

        """
        # Ensure a unique key for the session state queue for each instance
        self._queue_key = self._QUEUE_KEY_PREFIX + prefix
        self._prefix = prefix

        # Use session_state to store the queue of pending cookie changes.
        self._queue = st.session_state.setdefault(self._queue_key, {})

        # Run the component to get the initial cookie values from the browser.
        # We use a unique key for each component instance to prevent conflicts.
        component_key = self._SYNC_KEY_PREFIX + prefix
        raw_cookie = self._run_component(save_only=False, key=component_key)

        if raw_cookie is None:
            # The component is not yet ready or has not returned data.
            self._cookies = None
        else:
            # Component is ready, parse the cookies.
            self._cookies = parse_cookies(raw_cookie)
            # Clean the queue of any changes that have already been applied by the browser.
            self._clean_queue()

        # Set default expiry for new cookies to one year.
        self._default_expiry = datetime.now(tz=UTC) + timedelta(days=365)
        self._path = path if path is not None else "/"

    def ready(self) -> bool:
        """
        Return whether the component has synced cookies from the browser.

        Returns:
            bool: True if cookies from the browser are available.

        """
        return self._cookies is not None

    def save(self) -> None:
        """
        Save any queued cookie changes to the browser.

        This must be called for changes to take effect.
        """
        if self._queue:
            # Use a unique key for the save operation to prevent conflicts.
            save_key = self._SAVE_KEY_PREFIX + self._prefix
            self._run_component(save_only=True, key=save_key)

    def _run_component(self, *, save_only: bool, key: str) -> str | None:
        """
        Call the Streamlit component function.

        Args:
            save_only: If True, only saves cookies from the queue.
            key: The unique key for the component call.

        Returns:
            str | None: The raw cookie header from the browser, if available.

        """
        # Prefix the cookie names in the queue before sending them to the component.
        # This ensures that your instance only manages its own cookies.
        queue_with_prefix = {self._prefix + k: v for k, v in self._queue.items()}
        # The component function returns the raw cookie string from the browser.
        return cast("str | None", _component_func(queue=queue_with_prefix, saveOnly=save_only, key=key))

    def _clean_queue(self) -> None:
        """Remove items from the internal queue already applied by the browser."""
        if self._cookies is None:
            return  # No cookies to check against yet.

        # Use a list to iterate over a copy of the keys to avoid issues with
        # dictionary size changes during iteration.
        for name in list(self._queue.keys()):
            spec = self._queue[name]
            prefixed_name = self._prefix + name

            # Check if the browser's cookie value matches the queued value.
            # If so, the change has been applied.
            if spec["value"] is None:
                # If the queued action was a deletion, check if the cookie is gone.
                if prefixed_name not in self._cookies:
                    del self._queue[name]
            elif self._cookies.get(prefixed_name) == spec["value"]:
                # If the queued action was a set, check if the value is correct.
                del self._queue[name]

    def __repr__(self) -> str:
        """
        Return a string representation of the CookieManager.

        Returns:
            str: Human-readable state of the manager.

        """
        if self.ready():
            return f"<CookieManager: {dict(self)!r}>"
        return "<CookieManager: not ready>"

    def __getitem__(self, k: str) -> str:
        """
        Get the value of a cookie by name.

        Returns:
            str: The cookie value.

        Raises:
            KeyError: If the cookie is not present.

        """
        try:
            return self._get_cookies()[k]
        except KeyError as err:
            msg = f"Cookie '{k}' not found."
            raise KeyError(msg) from err

    def __iter__(self) -> Iterator[str]:
        """
        Iterate over the names of the available cookies.

        Returns:
            Iterator[str]: An iterator over cookie names.

        """
        return iter(self._get_cookies())

    def __len__(self) -> int:
        """
        Return the number of available cookies.

        Returns:
            int: The number of cookies.

        """
        return len(self._get_cookies())

    def __setitem__(self, key: str, value: str) -> None:
        """
        Set a cookie's value.

        The change is queued and requires a call to ``save()`` to be applied in the browser.
        """
        # Ensure the value is a string or can be converted to one.
        if not isinstance(value, str):
            value = str(value)

        # Only queue the change if the value is different from the current value
        # to avoid unnecessary component reruns.
        current_value = self._get_cookies().get(key) if self.ready() else None
        if current_value != value:
            self._queue[key] = {
                "value": value,
                "expires_at": self._default_expiry.isoformat(),
                "path": self._path,
            }

    def __delitem__(self, key: str) -> None:
        """
        Delete a cookie.

        The deletion is queued and requires a call to ``save()`` to be applied in the browser.
        """
        # Only queue the deletion if the cookie is currently present.
        if key in self._get_cookies():
            self._queue[key] = {"value": None, "path": self._path}

    def _get_cookies(self) -> Mapping[str, str]:
        """
        Return all managed cookies, including queued changes.

        Returns:
            Mapping[str, str]: Cookies visible to this manager.

        Raises:
            CookiesNotReady: If the component hasn't synced with the browser yet.

        """
        if self._cookies is None:
            msg = (
                "CookieManager is not ready. The component has not synced with the browser yet. "
                "You need to wait for a rerun after initialization or check `ready()` first."
            )
            raise CookiesNotReady(msg)

        # Start with the cookies from the browser
        cookies = {k[len(self._prefix) :]: v for k, v in self._cookies.items() if k.startswith(self._prefix)}

        # Overlay the queued changes
        for name, spec in self._queue.items():
            if spec["value"] is not None:
                cookies[name] = spec["value"]
            else:
                # If value is None, it's a deletion
                cookies.pop(name, None)

        return cookies
