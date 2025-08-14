import os
from typing import Optional, Dict
from dotenv import load_dotenv, find_dotenv

def _load_env() -> None:
    """Load `.env` from the current working directory upward to root.
    If no `.env` is found, do nothing and rely on system environment variables."""
    path = find_dotenv(usecwd=True)
    if path:
        load_dotenv(path)

# Load .env at import time
_load_env()

def get_credential(key: str, default: Optional[str] = None) -> Optional[str]:
    """Return the value of env var `key` if set, else `default`."""
    return os.getenv(key, default)

def require_credential(key: str) -> str:
    """Return env var `key` or raise RuntimeError if missing."""
    v = os.getenv(key)
    if v is None:
        raise RuntimeError(f"Missing credential `{key}`. Set it in .env or your environment.")
    return v

def get_namespace(prefix: str) -> Dict[str, str]:
    """Return dict of env vars starting with `prefix_`, keys stripped after the underscore."""
    p = f"{prefix}_"
    return {k[len(p):]: v for k, v in os.environ.items() if k.startswith(p)}
