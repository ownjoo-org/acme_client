from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key, RSAPrivateKey

from jose import constants
from jose.jwk import RSAKey


def create_key() -> Tuple[RSAKey, RSAKey]:
    key: RSAPrivateKey = generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key: bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key: bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pub_key: RSAKey = RSAKey(algorithm=constants.Algorithms.RS256, key=public_key.decode('utf-8'))
    priv_key: RSAKey = RSAKey(algorithm=constants.Algorithms.RS256, key=private_key.decode('utf-8'))

    return priv_key, pub_key
