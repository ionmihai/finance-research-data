import os

# Safe defaults
_DEFAULT_USER_AGENT = "finance_research_data/0.1 (+https://github.com/ionmihai/finance_research_data)"
_DEFAULT_TIMEOUT = 60  # seconds

# Allow overrides from environment variables
USER_AGENT = os.getenv("FRD_USER_AGENT", _DEFAULT_USER_AGENT)
DEFAULT_TIMEOUT = float(os.getenv("FRD_DEFAULT_TIMEOUT", _DEFAULT_TIMEOUT))

FRED_BASE="https://api.stlouisfed.org/fred"
