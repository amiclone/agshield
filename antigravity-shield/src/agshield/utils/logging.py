"""
AntiGravity Shield — Logging Utilities
=======================================
Provides structured logging with both file and console output.
"""

import os
import sys
import logging
from typing import Optional


def setup_logging(log_level: str = "INFO",
                  log_file: Optional[str] = None,
                  use_syslog: bool = False) -> None:
    """
    Set up logging for AntiGravity Shield.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        use_syslog: Whether to also log to syslog
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    ))
    handlers.append(console_handler)

    # File handler
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
        ))
        handlers.append(file_handler)

    # Syslog handler (if available)
    if use_syslog:
        try:
            from logging.handlers import SysLogHandler
            syslog_handler = SysLogHandler(address="/dev/log")
            syslog_handler.setFormatter(logging.Formatter(
                "antigravity: %(name)s %(levelname)s: %(message)s"
            ))
            handlers.append(syslog_handler)
        except (OSError, ImportError):
            pass

    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        handlers=handlers,
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the antigravity prefix.

    Args:
        name: Logger name (e.g., "monitor.realtime")

    Returns:
        logging.Logger: Configured logger
    """
    return logging.getLogger(f"antigravity.{name}")
