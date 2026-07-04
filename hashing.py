"""
IRONYX Process Guard — Executable Hashing
==========================================

Computes SHA-256 hashes of executable files, caches results, and detects
changes when a binary on disk is modified.

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from logger import get_app_logger

log = get_app_logger()

# In-memory cache: {exe_path: (sha256, mtime)}
_cache: dict[str, tuple[str, float]] = {}


def compute_sha256(file_path: str | Path, chunk_size: int = 65_536) -> str | None:
    """Return the SHA-256 hex digest of *file_path*, or *None* on error.

    Parameters
    ----------
    file_path:
        Path to the file to hash.
    chunk_size:
        Read chunk size in bytes (default 64 KiB).

    Returns
    -------
    str | None
        Hex digest or *None* if the file cannot be read.
    """
    p = Path(file_path)
    try:
        if not p.is_file():
            return None
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError, FileNotFoundError) as exc:
        log.debug("Cannot hash %s: %s", file_path, exc)
        return None


def get_cached_hash(file_path: str) -> str | None:
    """Return a cached hash if the file's mtime hasn't changed; otherwise recompute."""
    try:
        mtime = os.path.getmtime(file_path)
    except OSError:
        return None

    cached = _cache.get(file_path)
    if cached and cached[1] == mtime:
        return cached[0]

    digest = compute_sha256(file_path)
    if digest:
        _cache[file_path] = (digest, mtime)
    return digest


def has_executable_changed(file_path: str, known_hash: str) -> bool:
    """Return *True* if the current hash differs from *known_hash*."""
    current = get_cached_hash(file_path)
    if current is None:
        return False
    return current.lower() != known_hash.lower()


def clear_cache() -> None:
    """Clear the in-memory hash cache."""
    _cache.clear()
