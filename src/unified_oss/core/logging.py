"""
Logging configuration for Unified OSS Framework.

Provides structured logging with multiple handlers and formatters.
"""

import logging
import sys
from datetime import datetime
from typing import Optional
import json


class StructuredFormatter(logging.Formatter):
    """
    Structured JSON log formatter.
    
    Outputs log records as JSON objects for easier parsing
    and integration with log aggregation systems.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: Log record to format.
            
        Returns:
            JSON-formatted log string.
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, "extra_data"):
            log_data["extra"] = record.extra_data
        
        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """
    Colored console formatter for development.
    
    Adds ANSI color codes to log output for better readability
    in terminal environments.
    """
    
    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors.
        
        Args:
            record: Log record to format.
            
        Returns:
            Colored log string.
        """
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    structured: bool = False,
) -> None:
    """
    Configure logging for the Unified OSS Framework.
    
    Sets up console and optional file logging with appropriate
    formatters based on the environment.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional path to log file.
        structured: Use JSON structured logging format.
    
    Example:
        >>> setup_logging(level="DEBUG", structured=True)
        >>> logger = get_logger(__name__)
        >>> logger.info("Application started")
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    
    if structured:
        console_handler.setFormatter(StructuredFormatter())
    else:
        console_handler.setFormatter(
            ColoredFormatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
    
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the specified module.
    
    Args:
        name: Logger name, typically __name__ of the calling module.
        
    Returns:
        Configured logger instance.
    
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing alarm", extra={"extra_data": {"alarm_id": "123"}})
    """
    return logging.getLogger(name)


class LogContext:
    """
    Context manager for adding temporary log context.
    
    Allows adding extra context to all log messages within
    a code block.
    
    Example:
        >>> with LogContext(request_id="abc123"):
        ...     logger.info("Processing request")
    """
    
    def __init__(self, **kwargs):
        """
        Initialize log context with extra fields.
        
        Args:
            **kwargs: Key-value pairs to add to log context.
        """
        self.context = kwargs
        self.old_factory = None
    
    def __enter__(self):
        """Enter context and set up log factory."""
        self.old_factory = logging.getLogRecordFactory()
        
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context and restore original log factory."""
        logging.setLogRecordFactory(self.old_factory)
        return False
