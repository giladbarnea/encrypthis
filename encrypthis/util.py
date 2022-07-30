import hashlib
import hmac
import os

import click
from cryptography.fernet import Fernet


@click.command
def genkey_cli() -> bytes:
    key = generate_key()
    decoded_key = key.decode()
    click.echo("\n", err=True)
    click.echo(decoded_key)
    click.echo(
        f"\n\n\x1b[1mNote: This key cannot be recovered\x1b[0m, and so are any files encrypted with it; Please save it now. \n\n"
        f"You can store the key in ENCRYPTHIS_KEY environment variable, and it will be used automatically when encrypting/decrypting files.\n"
        f"Run the following:\n\n"
        f"export ENCRYPTHIS_KEY={decoded_key!r}\n",
        err=True,
    )
    return key


def generate_key() -> bytes:
    return Fernet.generate_key()


# Check out encrypt-file: https://github.com/brunocampos01/encrypt-file/blob/b0d96c036b0d51c83374519eaa16f3a505c4c6c8/encryptfile/encryptfile.py#L27
# Example usage:
# pw_hash = hash_password('correct horse battery staple')
# salt = os.urandom(16)
# assert password_ok('correct horse battery staple', salt, pw_hash)
# assert not password_ok('Tr0ub4dor&3', salt, pw_hash)
# assert not password_ok('rosebud', salt, pw_hash)
def hash_password(password: str, salt: bytes = None) -> bytes:
    if salt is None:
        salt = os.urandom(16)
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations=100000
    )


def password_ok(password: str, salt: bytes, pw_hash: bytes) -> bool:
    compare_to = hash_password(password, salt)
    return hmac.compare_digest(pw_hash, compare_to)
