"""
    https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet

    simple_key:
    https://stackoverflow.com/questions/73532164/proper-data-encryption-with-a-user-set-password-in-python3/73535983#73535983
"""
import secrets
from base64 import urlsafe_b64decode, urlsafe_b64encode
from pathlib import Path
from typing import TypeVar

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .utils import encode64urlsafe

PathLike = TypeVar("PathLike", str, Path)


backend = default_backend()
ITERATIONS = 1_200_000


def _derive_key(password: bytes, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend,
    )
    return urlsafe_b64encode(kdf.derive(password))


def password_encrypt(plaintext: bytes, password: str, iterations: int = ITERATIONS) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return urlsafe_b64encode(
        b"%b%b%b"
        % (
            salt,
            iterations.to_bytes(4, "big"),
            urlsafe_b64decode(Fernet(key).encrypt(plaintext)),
        )
    )


def password_decrypt(ciphertext: bytes, password: str) -> bytes:
    decoded = urlsafe_b64decode(ciphertext)
    salt, iter, token = decoded[:16], decoded[16:20], urlsafe_b64encode(decoded[20:])
    iterations = int.from_bytes(iter, "big")
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def simple_key(pwd: str):
    return encode64urlsafe(f"{pwd:<32}".encode())


def fernet_key(pwd: str | None = None, iterations: int = ITERATIONS) -> bytes:
    """Генерирует urlsafe ключ для симметричного шифрования

    :param pwd: пароль, по-умолчанию None
    :return: строка bytes с ключом
    """
    if pwd is None:
        key = Fernet.generate_key()
        return key

    pwd_bytes = pwd.encode()
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(pwd_bytes)


def fernet_encrypt(plaintext: str, key: bytes) -> bytes:
    """Шифрует строку plaintext ключем key

    :param plaintext: текстовое сообщение
    :param key: ключ
    :return: зашифрованный текст, bytes
    """
    f = Fernet(key)
    encrypted = f.encrypt(plaintext.encode())
    return encrypted


def fernet_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    decrypted = f.decrypt(ciphertext)
    return decrypted


def store_fernet_key(path: PathLike, key: bytes | None = None):
    """Сохраняет ключ на диск"""
    if key is None:
        key = fernet_key()
    with open(path, "wb") as key_file:
        key_file.write(key)


def load_fernet_key(path: PathLike) -> str:
    """Загружает ключ с диска"""
    with open(path, "rb") as key_file:
        return key_file.read().decode()
