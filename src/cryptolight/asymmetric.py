"""
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization

https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
"""

from pathlib import Path
from typing import NamedTuple, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

PathLike = TypeVar("PathLike", str, Path)


__all__ = (
    "deserialize_public_pem",
    "load_public_key",
    "load_private_key",
    "store_private_key",
    "store_public_key",
    "get_private_pem",
    "get_public_pem",
    "sign_message",
    "verify_message_sign",
    "encrypt_message",
    "decrypt_message",
    "generate_keys",
)

PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048


class RSAKeysPair(NamedTuple):
    public_key: RSAPublicKey
    private_key: RSAPrivateKey


def deserialize_public_pem(data: bytes):
    return serialization.load_pem_public_key(data, backend=default_backend())


def load_public_key(path: PathLike) -> PublicKeyTypes:
    """Загружает из файла публичный ключ
    :param path: путь к файлу
    :return: экземпляр публичного ключа
    """
    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        return public_key


def load_private_key(path: PathLike, password: bytes | None = None) -> PrivateKeyTypes:
    """Загружает из файла приватный ключ. Если необходимо можно указать пароль
    :param path: путь к файлу
    :param password: пароль, если необходим
    :return: экземпляр приватного ключа
    """
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None if password is None else password
        )
        return private_key


def _store_key(
    path: PathLike,
    private_key: RSAPrivateKey,
    *,
    public_key: bool = False,
    password: str | None = None,
) -> None:
    """Сохраняет ключ на диск в формате PEM
    :param path: путь к файлу
    :param private_key: экземпляр приватного ключа
    :param store_public_key: если True, сохраняет публичный ключ
    :param password: пароль для приватного ключа, если необходим
    """
    pem = get_public_pem(private_key) if public_key else get_private_pem(private_key, password)

    with open(path, "wb") as key_file:
        key_file.write(pem)


def store_private_key(path: PathLike, private_key: RSAPrivateKey, *, password: str | None = None):
    """Сохраняет ключ на диск в формате PEM
    :param path: путь к файлу
    :param private_key: экземпляр приватного ключа
    :param password: пароль для приватного ключа, по-умолчанию None
    """
    _store_key(path, private_key, password=password)


def store_public_key(path: PathLike, private_key: RSAPrivateKey):
    """Сохраняет ключ на диск в формате PEM
    :param path: путь к файлу
    :param private_key: экземпляр приватного ключа
    """
    _store_key(path, private_key, public_key=True)


def get_private_pem(private_key: PrivateKeyTypes, password: str | None = None) -> bytes:
    """Cериализует приватный ключ в формате PEM. С шифрованием, если указан пароль
    :param private_key: экземпляр приватного ключа
    :param password: пароль, если надо
    :return: bytes
    """
    encryption_algorithm = (
        serialization.NoEncryption()
        if password is None
        else serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=encryption_algorithm,
    )

    return pem


def get_public_pem(private_key: PrivateKeyTypes) -> bytes:
    """Сериализует публичный ключ в формате PEM
    :param private_key: экземпляр приватного ключа
    :return: bytes
    """
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem


def sign_message(message: bytes, private_key: RSAPrivateKey) -> bytes:
    """Подпись для сообщения приватным ключом
    https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
    :param message: .encode сообщение
    :param private_key: экземпляр приватного ключа
    :return: bytes
    """
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature


def verify_message_sign(message: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """Проверяет сообщение с подписью с использованием публичного ключа.
    :param message: Сообщение
    :param signature: Подпись
    :param public_key: экземпляр публичного ключа
    :return: False если подпись не совпадает возвращает, True если Ок
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def encrypt_message(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Шифрует сообщение
    :param message: Сообщение
    :param public_key: Экземпляр публичного ключа
    :return: bytes
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def decrypt_message(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Расшифровывает сообщение
    :param message: Сообщение
    :param public_key: Экземпляр приватного ключа
    :return: bytes
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def generate_keys(exponent: int = PUBLIC_EXPONENT, key_size: int = KEY_SIZE) -> RSAKeysPair:
    """Генерирует приватный и публичный ключи
    :return: кортеж из приватного и публичного ключа
    """
    private_key = rsa.generate_private_key(
        public_exponent=exponent, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()

    return RSAKeysPair(private_key=private_key, public_key=public_key)
