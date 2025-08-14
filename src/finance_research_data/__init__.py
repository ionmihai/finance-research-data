from importlib.metadata import version, PackageNotFoundError
try:
    __version__ = version("finance-research-data")
except PackageNotFoundError:
    __version__ = "0.0.0"

from ._infrastructure.auth import (
    get_credential, 
    require_credential, 
    get_namespace
)

from ._infrastructure.http_tools import (
    fetch_bytes_from_url, 
    detect_filetype_from_url, 
    detect_delimiter_at_url,
    read_csv_from_url,
    read_excel_from_url,
    read_table_from_url,
    fetch_to_file_from_url,

)

