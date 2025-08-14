from pathlib import Path
import os

def _load_env():
    try:
        from dotenv import load_dotenv, find_dotenv
        p=find_dotenv(usecwd=True); load_dotenv(p) if p else None
    except Exception: pass

_load_env()

def get_credential(key, default=None): return os.getenv(key, default)

def require_credential(key):
    v=os.getenv(key)
    if v is None: raise RuntimeError(f"Missing credential: {key}")
    return v

def get_namespace(prefix):
    pref=f"{prefix}_"
    return {k[len(pref):]:v for k,v in os.environ.items() if k.startswith(pref)}
