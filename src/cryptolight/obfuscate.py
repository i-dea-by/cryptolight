"""
    https://stackoverflow.com/questions/2490334/simple-way-to-encode-a-string-according-to-a-password/55147077#55147077
"""
import zlib
from base64 import urlsafe_b64decode, urlsafe_b64encode


def obscure(data: bytes) -> bytes:
    """Сжимает data в zlib и возвращает urlsafe base64

    :param data: данные
    :return: urlsafe base64 сжатые данные
    """
    return urlsafe_b64encode(zlib.compress(data, 9))


def unobscure(obscured: bytes | str) -> bytes:
    """ Распаковывет data

    :param obscured: urlsafe base64 сжатые данные
    :return: распакованные данные
    """
    return zlib.decompress(urlsafe_b64decode(obscured))
