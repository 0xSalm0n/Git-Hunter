"""
Structured JSON logging with severity levels.
"""

import json
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Any, Optional


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data

        return json.dumps(log_entry, default=str)


class ContextAdapter(logging.LoggerAdapter):
    """Logger adapter that supports extra structured data."""

    def process(self, msg: str, kwargs: dict) -> tuple:
        extra = kwargs.get("extra", {})
        if "extra_data" in extra:
            pass
        elif self.extra:
            extra["extra_data"] = self.extra
            kwargs["extra"] = extra
        return msg, kwargs

    def with_data(self, msg: str, data: dict[str, Any], **kwargs) -> None:
        """Log a message with structured extra data."""
        kwargs.setdefault("extra", {})["extra_data"] = data
        self.info(msg, **kwargs)

    def error_with_data(self, msg: str, data: dict[str, Any], **kwargs) -> None:
        """Log an error with structured extra data."""
        kwargs.setdefault("extra", {})["extra_data"] = data
        self.error(msg, **kwargs)


def setup_logger(
    name: str = "ghrecon",
    log_file: Optional[str] = None,
    level: int = logging.INFO,
    json_console: bool = False,
) -> ContextAdapter:
    """
    Set up a structured logger.

    Args:
        name: Logger name
        log_file: Path to log file (JSON formatted)
        level: Logging level
        json_console: If True, use JSON formatting on console too

    Returns:
        ContextAdapter wrapping the configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    # File handler - always JSON
    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(JSONFormatter())
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

    # Console handler - minimal by default
    if json_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(JSONFormatter())
        console_handler.setLevel(logging.WARNING)
        logger.addHandler(console_handler)

    return ContextAdapter(logger, {})


def get_logger(name: str = "ghrecon") -> ContextAdapter:
    """Get an existing logger by name."""
    logger = logging.getLogger(name)
    return ContextAdapter(logger, {})
