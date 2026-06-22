# cryptoanalyzer/utils/logger.py

"""
Centralized logger configuration for CryptoAnalyzer.

Provides a `get_logger(name: str)` function. On first request, it:
  - Configures a StreamHandler to stderr
  - Sets a default formatter: "YYYY-MM-DD HH:MM:SS LEVEL [logger_name] message"
  - Defaults to INFO level (can be overridden via environment variable or config)
"""

import logging
import os

_DEFAULT_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Environment variable to override default level (e.g. CRYPTOANALYZER_LOG=DEBUG)
_ENV_LEVEL = os.getenv("CRYPTOANALYZER_LOG", "").upper()


def get_logger(name: str = None) -> logging.Logger:
    """
    Return a logger named `cryptoanalyzer.<name>`. On first use, configures
    a StreamHandler with a default format. Honors the CRYPTOANALYZER_LOG
    environment variable if set to a valid level (DEBUG/INFO/WARNING/ERROR).
    """
    base_name = "cryptoanalyzer"
    logger_name = f"{base_name}.{name}" if name else base_name
    logger = logging.getLogger(logger_name)

    # If this logger is not yet configured, add a handler and set level
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter(_DEFAULT_FORMAT, datefmt=_DATEFMT)
        handler.setFormatter(fmt)
        logger.addHandler(handler)

        # Determine default level: use env var if valid, else INFO
        level = logging.INFO
        if _ENV_LEVEL in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            level = getattr(logging, _ENV_LEVEL)
        logger.setLevel(level)

        # Prevent double-logging: do not propagate to root
        logger.propagate = False

    return logger
