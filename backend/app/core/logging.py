"""
QuShield-PnB Structured Logging Framework

Provides JSON-structured logging to both console (colored) and file (JSONL).
Every log entry includes: timestamp, level, service, function, message.
"""
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pythonjsonlogger.json import JsonFormatter
from rich.console import Console
from rich.logging import RichHandler

from app.config import settings


_loggers: dict[str, logging.Logger] = {}
_console = Console(stderr=True)


class StructuredJsonFormatter(JsonFormatter):
    """Custom JSON formatter that adds service name and standardized fields."""

    def __init__(self, service_name: str, **kwargs):
        super().__init__(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            rename_fields={"levelname": "level", "name": "service"},
            **kwargs,
        )
        self.service_name = service_name

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record["timestamp"] = datetime.now(timezone.utc).isoformat()
        log_record["service"] = self.service_name
        log_record["function"] = record.funcName
        if record.funcName == "<module>":
            log_record["function"] = record.filename


def get_logger(service_name: str, log_level: Optional[str] = None) -> logging.Logger:
    """
    Get or create a structured logger for the given service.

    Outputs to:
      - Console: colored, human-readable (via Rich)
      - File: JSON lines at logs/{service_name}/{date}.jsonl

    Args:
        service_name: Name of the service/module (e.g., "crypto_inspector")
        log_level: Override log level (default: from settings.LOG_LEVEL)

    Returns:
        Configured logging.Logger instance
    """
    if service_name in _loggers:
        return _loggers[service_name]

    level = getattr(logging, (log_level or settings.LOG_LEVEL).upper(), logging.DEBUG)

    logger = logging.getLogger(f"qushield.{service_name}")
    logger.setLevel(level)
    logger.propagate = False

    # --- Console handler (Rich) ---
    console_handler = RichHandler(
        console=_console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        tracebacks_show_locals=False,
        markup=True,
    )
    console_handler.setLevel(level)
    console_fmt = logging.Formatter(f"[bold]{service_name}[/bold] %(message)s")
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # --- File handler (JSONL) ---
    log_dir = settings.log_dir_abs / service_name
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"

    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setLevel(level)
    json_formatter = StructuredJsonFormatter(service_name=service_name)
    file_handler.setFormatter(json_formatter)
    logger.addHandler(file_handler)

    _loggers[service_name] = logger
    return logger
