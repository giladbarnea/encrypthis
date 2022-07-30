#!.venv/bin/python3
# see for salt+hash:
# https://stackoverflow.com/a/23768422

import textwrap
from pathlib import Path

# pip install cryptography
import click
from cryptography.fernet import Fernet

from .validators import validate_in_path, validate_out_path

ENCRYPT_EXTENSION_WHITELIST = {".py", ".txt", ".md", ".rst", ""}


IN_PATH_HELP = (
    "Path to file or directory, or glob pattern, to encrypt. "
    f"If directory, all text files with extensions {ENCRYPT_EXTENSION_WHITELIST} in directory will be encrypted."
)

OUT_PATH_HELP = (
    "Path to output the encrypted file(s). "
    "If IN_PATH is a directory or glob, OUT_PATH must be a directory as well."
)

ENCRYPT_HELP = textwrap.dedent(
    f"""\b\bArguments: 
IN_PATH:
{IN_PATH_HELP}
OUT_PATH:
{OUT_PATH_HELP}"""
).replace("\n", "\n\n")


@click.command(
    no_args_is_help=True,
    help=ENCRYPT_HELP,
)
@click.argument(
    "in_path",
    type=click.Path(exists=True, readable=True, resolve_path=True, path_type=Path),
    callback=validate_in_path,
)
@click.argument(
    "out_path",
    type=click.Path(resolve_path=True, path_type=Path),
    required=False,
    callback=validate_out_path,
)
@click.option(
    "--key",
    "-k",
    "encryption_key",
    prompt="Encryption key",
    envvar="ENCRYPTHIS_KEY",
    show_envvar=True,
    callback=lambda ctx, param, value: value.encode(),
)
@click.option("-w", "--overwrite", is_flag=True, help="Overwrite existing files", is_eager=True)
def encrypt(in_path: Path, out_path: Path, encryption_key: bytes, overwrite: bool = False):
    fernet: Fernet = Fernet(encryption_key)

    if not click.confirm(
        f"Encrypting:  {str(in_path)!r}\n" f"Output path: {str(out_path)!r}\n" f"Continue?"
    ):
        raise click.Abort()

    encrypted_data = get_encrypted_file_data(in_path, fernet)

    write_encrypted_data(encrypted_data, out_path, in_path)
    click.echo(f"Encrypted {in_path} to {out_path}")


def get_encrypted_file_data(path, fernet: Fernet) -> bytes:
    bytes_content = Path(path).read_bytes()
    encrypted_data = fernet.encrypt(bytes_content)
    return encrypted_data


def write_encrypted_data(encrypted: bytes, out_path, in_path):
    out_path = Path(out_path)
    if out_path.is_dir():
        return Path(out_path / in_path.name).write_bytes(encrypted)
    return Path(out_path).write_bytes(encrypted)


def iter_encrypted_dir_files(in_path: Path, fernet: Fernet):
    for path in in_path.rglob("*"):
        if (
            path.is_file()
            and path.suffix in ENCRYPT_EXTENSION_WHITELIST
            and not any(part.startswith(".") for part in path.parts)
        ):
            encrypted = get_encrypted_file_data(path, fernet)
            yield path, encrypted
