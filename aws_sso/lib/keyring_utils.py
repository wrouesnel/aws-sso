"""Helper utilities for handling values in the keyring"""
import json
from typing import Optional, Any

import keyring
from . import click_utils

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
