from typing import Optional, Dict, Any, Tuple
from pathlib import Path
import io
import requests
import csv 
import pandas as pd
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
from .._config.settings import USER_AGENT, DEFAULT_TIMEOUT


def _session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    """Create a configured requests.Session with retry logic and default headers."""
    s = requests.Session()
    r = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=False
    )
    s.headers.update({"User-Agent": USER_AGENT})
    s.mount("http://", HTTPAdapter(max_retries=r))
    s.mount("https://", HTTPAdapter(max_retries=r))
    return s


def fetch_bytes_from_url(url: str, *, headers: Optional[Dict[str, str]] = None,
                params: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None,
                raw_transport: bool = False) -> bytes:
    """Fetch bytes from URL with retries/timeouts.
    By default returns the **decoded** body (let requests handle gzip/deflate).
    Set raw_transport=True to request identity encoding (no auto-decompression)."""
    s = _session()
    hdrs = dict(headers or {})
    if raw_transport:
        # Ask server for identity so we get raw transport bytes (no gzip/deflate)
        hdrs.setdefault("Accept-Encoding", "identity")
    resp = s.get(url, headers=hdrs, params=params,
                 timeout=timeout or DEFAULT_TIMEOUT, stream=True)
    resp.raise_for_status()
    return resp.content  # trust requests to decode when appropriate



def detect_filetype_from_url(url: str, *, headers: Optional[Dict[str, str]] = None,
                    timeout: Optional[float] = None, peek_bytes: int = 65536) -> Tuple[str, Optional[str]]:
    """Detect whether a URL points to an Excel ('excel') or delimited text ('csv') file.
    Robust order: HEAD Content-Type → streamed byte 'magic' → extension heuristic.
    Returns (kind, content_type_or_reason) where kind ∈ {'excel','csv','unknown'}."""
    s = _session()
    # 1) HEAD: trust the server if it tells us
    ctype = ""
    try:
        h = s.head(url, headers=headers, timeout=timeout or DEFAULT_TIMEOUT, allow_redirects=True)
        ctype = (h.headers.get("Content-Type") or "").lower()
    except requests.RequestException:
        ctype = ""

    if "spreadsheet" in ctype or "excel" in ctype:
        return "excel", ctype
    if "text/csv" in ctype or "application/csv" in ctype or "text/plain" in ctype:
        return "csv", ctype

    # 2) GET (stream) a small chunk and inspect magic numbers (no full download)
    try:
        g = s.get(url, headers=headers, timeout=timeout or DEFAULT_TIMEOUT, stream=True)
        g.raise_for_status()
        # Read just enough to fingerprint (don’t exhaust the generator for downstream)
        chunk = next(g.iter_content(chunk_size=peek_bytes))
    except Exception:
        chunk = b""

    # Excel signatures
    if chunk.startswith(b"PK\x03\x04"):                 # ZIP header (xlsx/xlsm/xlsb)
        return "excel", "zip_magic"
    if chunk.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):  # OLE (legacy .xls)
        return "excel", "ole_magic"

    # If it's likely text, we’ll treat as CSV; delimiter will be auto-sniffed later if requested
    if chunk and all(32 <= b <= 126 or b in (9, 10, 13) for b in chunk[:4096]):
        return "csv", "text_heuristic"

    # 3) Last resort: extension heuristic
    lower = url.lower()
    if any(lower.endswith(ext) for ext in (".xlsx", ".xlsm", ".xlsb", ".xls")):
        return "excel", "ext_heuristic"
    if any(lower.endswith(ext) for ext in (".csv", ".tsv", ".txt")):
        return "csv", "ext_heuristic"

    return "unknown", ctype or "undetermined"


def _sample_bytes_from_url(url: str, *, headers: Optional[Dict[str, str]] = None,
                           timeout: Optional[float] = None, chunk_size: int = 65536) -> Tuple[bytes, Optional[str]]:
    """Fetch a small chunk (≤chunk_size) and return (bytes, best_guess_encoding)."""
    s = _session()
    r = s.get(url, headers=headers, timeout=timeout or DEFAULT_TIMEOUT, stream=True)
    r.raise_for_status()
    try:
        chunk = next(r.iter_content(chunk_size=chunk_size))
    except StopIteration:
        chunk = b""
    enc = r.encoding or getattr(r, "apparent_encoding", None) or "utf-8"
    return chunk, enc

def _heuristic_delimiter(sample_text: str, candidates: Tuple[str, ...] = (",", "\t", ";", "|")) -> Optional[str]:
    """Pick the delimiter whose count is positive on most lines and has low variance across lines."""
    lines = [ln for ln in sample_text.splitlines() if ln.strip()]
    lines = lines[:20] if len(lines) > 20 else lines
    if len(lines) < 2:
        return None
    import statistics as stats
    best = None; best_score = float("inf")
    for d in candidates:
        counts = [ln.count(d) for ln in lines]
        if max(counts) == 0:  # delimiter not present
            continue
        # score: prefer many lines with the delimiter and low dispersion of counts
        try:
            var = stats.pvariance(counts)
        except stats.StatisticsError:
            var = 0.0
        nonzero = sum(c > 0 for c in counts)
        score = var - 0.01 * nonzero  # reward consistency & presence
        if score < best_score:
            best_score, best = score, d
    return best

def detect_delimiter_from_url(url: str,
                            headers: Optional[Dict[str, str]] = None,
                            timeout: Optional[float] = None,
                            nbytes: int = 65536) -> Optional[str]:
    """Guess delimiter by sampling the response and trying csv.Sniffer with a heuristic fallback."""
    sample, enc = _sample_bytes_from_url(url, headers=headers, timeout=timeout, chunk_size=nbytes)
    if not sample:
        return None
    text = sample.decode(enc, errors="ignore")

    # Try Sniffer first
    try:
        dialect = csv.Sniffer().sniff(text, delimiters=[",", "\t", ";", "|"])
        return dialect.delimiter
    except Exception:
        pass

    # Fallback: variance-based heuristic across lines
    return _heuristic_delimiter(text)
  

def read_csv_from_url(url: str, *,
                 nrows: Optional[int] = None,
                 skiprows: Optional[int] = None,
                 delimiter: str = "auto",
                 compression: str = "infer",
                 headers: Optional[Dict[str, str]] = None,
                 encoding: Optional[str] = None,
                 robust: bool = True,
                 pandas_kwargs: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
    """Read a CSV (or other delimited text file) from a URL into a DataFrame.

    Parameters
    ----------
    nrows : int, optional
        Number of rows to read.
    skiprows : int, optional
        Number of rows to skip at the start.
    delimiter : str, optional
        Field delimiter (e.g., ',' for CSV, '\t' for TSV). Use "auto" to autodetect.
    compression : str, optional
        Compression type ('gzip', 'zip', 'bz2', 'xz', 'zstd', or 'infer').
    headers : dict, optional
        HTTP headers to pass to the request.
    encoding : str, optional
        Text encoding (defaults to HTTP response encoding or UTF-8).
    robust : bool, default True
        If True, fetch entire file before parsing (safer, handles quoting/compression).
        If False, stream for faster prefix reads (may break on quoted newlines).
    pandas_kwargs : dict, optional
        Additional keyword arguments passed to pandas.read_csv.
    """
    kw = pandas_kwargs or {}
    if compression is not None: 
        kw["compression"] = compression

    # Auto-detect delimiter once (using a small sample) so we don't parse twice
    if delimiter == "auto" or delimiter is None:
        guessed = detect_delimiter_at_url(url, headers=headers)
        if guessed:
            delimiter = guessed
    if delimiter not in (None, "auto"):
        kw["delimiter"] = delimiter

    if robust or (nrows is None and skiprows is None):
        raw = fetch_bytes_from_url(url, headers=headers)
        bio = io.BytesIO(raw)
        return pd.read_csv(bio, nrows=nrows, skiprows=skiprows, encoding=encoding, **kw)

    s = _session()
    resp = s.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, stream=True)
    resp.raise_for_status()
    if encoding is None:
        encoding = resp.encoding or "utf-8"
    if skiprows:
        kw["skiprows"] = skiprows
    it = (line.decode(encoding) for line in resp.iter_lines())
    return pd.read_csv(it, nrows=nrows, engine="python", **kw)


def read_excel_from_url(url: str, *, sheet_name=0, headers=None, params=None,
                   timeout=None, pandas_kwargs=None):
    """Read an Excel file from a URL into a DataFrame."""
    kw = pandas_kwargs or {}
    raw = fetch_bytes_from_url(url, headers=headers, params=params, timeout=timeout)
    return pd.read_excel(io.BytesIO(raw), sheet_name=sheet_name, **kw)


def read_table_from_url(url: str, *,  # unified dispatcher
                   delimiter: Optional[str] = "auto",    # for delimited text; use "auto" to sniff
                   compression: Optional[str] = "infer",
                   sheet_name: Any = 0,                # for Excel
                   nrows: Optional[int] = None,
                   skiprows: Optional[int] = None,
                   headers: Optional[Dict[str, str]] = None,
                   encoding: Optional[str] = None,
                   timeout: Optional[float] = None,
                   robust: bool = True,                # passed to CSV path
                   pandas_kwargs: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
    """Read a tabular file (Excel or delimited text) from a URL into a DataFrame.
    Prefers robust detection: HEAD Content-Type → streamed magic bytes → extension.
    For CSV: optionally auto-detects delimiter when delimiter='auto' or delimiter is None."""

    kind, reason = detect_filetype_from_url(url, headers=headers, timeout=timeout)
    kw = pandas_kwargs or {}

    if kind == "excel":
        return read_excel_from_url(url, sheet_name=sheet_name,
            headers=headers, params=None, timeout=timeout, pandas_kwargs=kw
        )

    return read_csv_from_url(
        url, nrows=nrows, skiprows=skiprows, delimiter=delimiter,
        compression=compression, headers=headers, encoding=encoding,
        robust=robust, pandas_kwargs=kw
    )

def fetch_to_file_from_url(url: str, dest: Path, *,
                           headers: Optional[Dict[str, str]] = None,
                           params: Optional[Dict[str, Any]] = None,
                           timeout: Optional[float] = None,
                           chunk: int = 1024 * 1024,
                           infer_extension: bool = True,
                           ext_map: Optional[Dict[str, str]] = None,
                           overwrite: bool = False) -> Path:
    """Stream a URL directly to disk at `dest`. If `dest` has no suffix and `infer_extension` is True,
    detect file type via HEAD/peek and append an extension (default: '.xlsx' for Excel, '.csv' for delimited).
    Returns the final saved Path."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Optionally infer extension if none supplied
    if infer_extension and dest.suffix == "":
        kind, _reason = detect_filetype_from_url(url, headers=headers, timeout=timeout)
        mapping = ext_map or {"excel": ".xlsx", "csv": ".csv"}
        inferred = mapping.get(kind, "")

        if not inferred:
            # Fallback to URL path suffix if detector is 'unknown'
            path_suffix = Path(urlparse(url).path).suffix
            inferred = path_suffix if path_suffix else ""

        if inferred:
            dest = dest.with_suffix(inferred)

    if dest.exists() and not overwrite:
        return dest

    s = _session()
    resp = s.get(url, headers=headers, params=params,
                 timeout=timeout or DEFAULT_TIMEOUT, stream=True)
    resp.raise_for_status()

    with open(dest, "wb") as f:
        for c in resp.iter_content(chunk_size=chunk):
            if c:
                f.write(c)

    return dest