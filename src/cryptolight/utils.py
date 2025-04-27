import base64
import secrets
import string


def generate_random_code(digits: int = 6) -> str:
    """Generate random code with number of digits"""
    return "".join(secrets.choice(string.digits) for i in range(digits))


def encode64(data: bytes) -> str:
    """Декодирует data из bytes в строку ASCII"""
    return base64.b64encode(data).decode("ascii")


def decode64(data: bytes | str):
    """Декодирует data из bytes или str в оригинальную bytes строку"""
    return base64.b64decode(data)


def encode64urlsafe(data: bytes) -> str:
    """Декодирует data из bytes в строку ASCII"""
    return base64.urlsafe_b64encode(data).decode("ascii")


def decode64urlsafe(data: bytes | str):
    """Декодирует data из bytes или str в оригинальную bytes строку"""
    return base64.urlsafe_b64decode(data)

