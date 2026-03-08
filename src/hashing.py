"""
Artifact hashing utilities for chain-of-custody documentation.

Computes SHA-256 hashes of source artifact files before extraction begins
so the collection record shows the state of each file at acquisition time.
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_CHUNK = 8192


def hash_file(path: str) -> Optional[str]:
    """Return the SHA-256 hex digest of a file, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(_CHUNK):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        logger.warning(f"Permission denied hashing {path}")
        return None
    except OSError as e:
        logger.warning(f"Cannot hash {path}: {e}")
        return None


def collect_artifact_hashes(paths: List[str]) -> Dict[str, str]:
    """
    Hash every readable path in the list.

    Returns a dict mapping absolute path → SHA-256. Paths that don't exist
    or can't be read are silently skipped and not included.
    """
    hashes: Dict[str, str] = {}
    for path in paths:
        if not path:
            continue
        p = Path(path)
        if not p.exists() or not p.is_file():
            continue
        digest = hash_file(path)
        if digest:
            hashes[str(p.resolve())] = digest
            logger.debug(f"Hashed {path}: {digest[:16]}…")
    if hashes:
        logger.info(f"Pre-collection hashes computed for {len(hashes)} artifact(s)")
    return hashes
