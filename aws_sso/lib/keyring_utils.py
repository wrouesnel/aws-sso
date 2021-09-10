"""Helper utilities for handling values in the keyring"""
import json
from typing import Optional, Any

import ilock
import keyring
import retrying

from . import click_utils

from .constants import KEYRING_LOCK_NAME

"""
The temptation is to use keyring from multiple processes. The SecretService on Linux
tends to have DBus race issues with this, which then makes everything else kind of
slow. To fix this - we add our own concept of a global lock when interfacing with keyring.
This is implemented by monkey-patching the set/get routines. We also add retry logic
to handle random DBus exceptions. If DBus isn't running this will fail badly, but the
keyring contract is no exceptions - yet Dbus will fail on this for no reason.
"""
_get_password = keyring.get_password
_set_password = keyring.set_password

@retrying.retry(wait_fixed=100)
def get_password(service: str, username: str):
    with ilock.ILock(KEYRING_LOCK_NAME):
        result = _get_password(service, username)
    return result

@retrying.retry(wait_fixed=100)
def set_password(service: str, username: str, password: str):
    with ilock.ILock(KEYRING_LOCK_NAME):
        result = _set_password(service, username, password)
    return result

def get_or_prompt(value: Optional[str], service: str, user: str):
    # If got a value, then pass that back
    if value is not None:
        return value

    # Otherwise try and use the keyring
    v = keyring.get_password(service, user)
    if v is None or v == "":
        # No keyring value, prompt to enter one.
        nv = click_utils.prompt(f"Enter {service} for {user}: ")
        keyring.set_password(service, user, nv)
        v = keyring.get_password(service, user)
    return v

def get_json_or_none(service: str, username: str) -> Optional[Any]:
    raw = keyring.get_password(service, username)
    if raw is not None:
        return json.loads(raw)
    return None
