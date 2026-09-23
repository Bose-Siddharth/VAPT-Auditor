"""Minimal, dependency-free user store + HTTP Basic Auth gate.

This tool is not meant to be public. Every route is protected by HTTP Basic
Auth against a small local user list (data/users.json). On first run, if no
users exist, a single admin account is seeded with a randomly generated
password, printed once and saved to data/INITIAL_CREDENTIALS.txt (chmod 600)
so whoever deploys it can hand credentials out to a limited set of people.
Manage additional users with scripts/manage_users.py.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

DATA_DIR = Path(os.environ.get("VAPT_DATA_DIR", "data"))
USERS_FILE = DATA_DIR / "users.json"
INITIAL_CREDS_FILE = DATA_DIR / "INITIAL_CREDENTIALS.txt"

_security = HTTPBasic()


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()


def _load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text())


def _save_users(users: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))
    os.chmod(USERS_FILE, 0o600)


def add_user(username: str, password: str) -> None:
    users = _load_users()
    salt = secrets.token_hex(16)
    users[username] = {"salt": salt, "hash": _hash_password(password, bytes.fromhex(salt))}
    _save_users(users)


def remove_user(username: str) -> bool:
    users = _load_users()
    if username in users:
        del users[username]
        _save_users(users)
        return True
    return False


def list_users() -> list[str]:
    return sorted(_load_users().keys())


def seed_default_admin_if_needed() -> None:
    """Create a single admin account with a random password on first boot only."""
    if USERS_FILE.exists() and _load_users():
        return

    username = os.environ.get("VAPT_ADMIN_USER", "admin")
    password = os.environ.get("VAPT_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
    add_user(username, password)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    INITIAL_CREDS_FILE.write_text(
        "VAPT Auditor - initial admin credentials (generated once)\n"
        f"username: {username}\n"
        f"password: {password}\n\n"
        "Hand these out to authorized users only, then delete this file.\n"
        "Add more accounts with: python -m scripts.manage_users add <user> <password>\n"
    )
    os.chmod(INITIAL_CREDS_FILE, 0o600)
    print("=" * 60)
    print("VAPT Auditor: seeded initial admin account")
    print(f"  username: {username}")
    print(f"  password: {password}")
    print(f"  (also saved to {INITIAL_CREDS_FILE})")
    print("=" * 60)


def verify_credentials(credentials: HTTPBasicCredentials = Depends(_security)) -> str:
    users = _load_users()
    record = users.get(credentials.username)

    # Always hash something to keep timing consistent whether or not the
    # username exists, then compare with a constant-time comparison.
    salt = bytes.fromhex(record["salt"]) if record else secrets.token_bytes(16)
    expected_hash = record["hash"] if record else _hash_password("", salt)
    supplied_hash = _hash_password(credentials.password, salt)

    if not record or not hmac.compare_digest(supplied_hash, expected_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
