import os
import stat
from pathlib import Path

from django.core.management.base import CommandError


def read_protected_file(value: str, *, maximum_bytes: int = 65_536) -> bytes:
    path = Path(value)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise CommandError("A protected PKI input must be a regular file, not a link.")
    if metadata.st_size > maximum_bytes:
        raise CommandError("A protected PKI input exceeds the maximum size.")
    if os.name == "posix" and metadata.st_mode & 0o077:
        raise CommandError("A protected PKI input must not be accessible by group or others.")
    return path.read_bytes()
