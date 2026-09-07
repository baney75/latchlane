"""Authenticated encrypted state. Never store the passphrase or log payloads."""
import base64
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

AAD = b"latchlane-v1"
MAX_VAULT = 8 * 1024 * 1024

class VaultError(Exception):
    pass


def private_directory(path: Path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode):
        raise VaultError("Storage directory cannot be a symlink.")
    if os.name != "nt":
        if s.st_uid != os.getuid():
            raise VaultError("Storage directory belongs to another user.")
        path.chmod(0o700)


def private_read(path: Path):
    if path.is_symlink():
        raise VaultError("Refusing a symlink.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as f:
        s = os.fstat(f.fileno())
        if not stat.S_ISREG(s.st_mode):
            raise VaultError("Storage must be a regular file.")
        if os.name != "nt" and (s.st_uid != os.getuid() or s.st_mode & 0o077):
            raise VaultError("Storage permissions must be private (600).")
        data = f.read(MAX_VAULT + 1)
    if len(data) > MAX_VAULT:
        raise VaultError("Vault exceeds the size limit.")
    return data


def atomic_write(path: Path, data: bytes):
    if path.is_symlink():
        raise VaultError("Refusing a symlink.")
    fd, tmp = tempfile.mkstemp(prefix=".latchlane-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            d = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(d)
            finally: os.close(d)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


class Vault:
    def __init__(self, directory: Path):
        private_directory(directory)
        self.path = directory / "store.vault"
        self.key = None
        self.salt = None
        self.data = None

    def initialize(self, password):
        if self.path.exists(): raise VaultError("A vault already exists.")
        if len(password) < 14: raise VaultError("Use a passphrase of at least 14 characters.")
        self.salt = secrets.token_bytes(16)
        self.key = self.derive(password, self.salt)
        self.data = {"mode": "ask", "keys": {}, "clients": {}, "audit": [], "revision": 0}
        self.save()

    @staticmethod
    def derive(password, salt):
        return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode())

    def unlock(self, password):
        try:
            raw = json.loads(private_read(self.path))
            if raw["version"] != 1: raise ValueError()
            salt = base64.b64decode(raw["salt"], validate=True)
            blob = base64.b64decode(raw["sealed"], validate=True)
            if len(salt) != 16: raise ValueError()
            key = self.derive(password, salt)
            data = json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], AAD))
            if data["mode"] not in ("ask", "auto", "yolo"): raise ValueError()
        except Exception:
            raise VaultError("Could not unlock. Check your passphrase and vault file.") from None
        self.salt, self.key, self.data = salt, key, data

    def save(self):
        if self.key is None: raise VaultError("Vault is locked.")
        revision = self.data["revision"]
        self.data["revision"] = revision + 1
        nonce = secrets.token_bytes(12)
        blob = nonce + AESGCM(self.key).encrypt(nonce, json.dumps(self.data, separators=(",", ":")).encode(), AAD)
        out = json.dumps({"version": 1, "salt": base64.b64encode(self.salt).decode(), "sealed": base64.b64encode(blob).decode()}).encode()
        if len(out) > MAX_VAULT:
            self.data["revision"] = revision
            raise VaultError("Vault exceeds the size limit.")
        atomic_write(self.path, out)

    def lock(self):
        self.key = self.data = self.salt = None
