"""
QuShield-PnB Timing Decorator

Logs function execution time, arguments, and return value summary.
Works with both sync and async functions.
"""
import asyncio
import functools
import time
import json
from typing import Any

from app.core.logging import get_logger


def _truncate(value: Any, max_len: int = 200) -> str:
    """Truncate a value's string representation for logging."""
    s = str(value)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _summarize_return(value: Any) -> Any:
    """Create a compact summary of a return value for logging."""
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return _truncate(value, 100)
    if isinstance(value, dict):
        return {k: _truncate(v, 50) for k, v in list(value.items())[:5]}
    if isinstance(value, (list, tuple)):
        return f"[{type(value).__name__} len={len(value)}]"
    return _truncate(value, 100)


def timed(func=None, *, service: str = None):
    """
    Decorator that logs function execution time and arguments.

    Usage:
        @timed
        def my_function(x, y): ...

        @timed(service="my_service")
        async def my_async_function(x): ...
    """
    def decorator(fn):
        logger_service = service or fn.__module__.split(".")[-1]
        logger = get_logger(logger_service)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            start = time.perf_counter()
            func_name = fn.__qualname__
            logger.debug(
                f"→ {func_name} called",
                extra={
                    "event": "function_start",
                    "function": func_name,
                    "args_summary": _truncate(args[1:] if args else args),  # skip self
                    "kwargs_summary": _truncate(kwargs),
                },
            )
            try:
                result = await fn(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - start) * 1000
                logger.debug(
                    f"← {func_name} completed in {elapsed_ms:.1f}ms",
                    extra={
                        "event": "function_end",
                        "function": func_name,
                        "duration_ms": round(elapsed_ms, 1),
                        "return_summary": _summarize_return(result),
                    },
                )
                return result
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                logger.error(
                    f"✗ {func_name} failed after {elapsed_ms:.1f}ms: {e}",
                    extra={
                        "event": "function_error",
                        "function": func_name,
                        "duration_ms": round(elapsed_ms, 1),
                        "error": str(e),
                        "error_type": type(e).__name__,
                    },
                )
                raise

        @functools.wraps(fn)
        def sync_wrapper(*args, **kwargs):
            start = time.perf_counter()
            func_name = fn.__qualname__
            logger.debug(
                f"→ {func_name} called",
                extra={
                    "event": "function_start",
                    "function": func_name,
                    "args_summary": _truncate(args[1:] if args else args),
                    "kwargs_summary": _truncate(kwargs),
                },
            )
            try:
                result = fn(*args, **kwargs)
                elapsed_ms = (time.perf_counter() - start) * 1000
                logger.debug(
                    f"← {func_name} completed in {elapsed_ms:.1f}ms",
                    extra={
                        "event": "function_end",
                        "function": func_name,
                        "duration_ms": round(elapsed_ms, 1),
                        "return_summary": _summarize_return(result),
                    },
                )
                return result
            except Exception as e:
                elapsed_ms = (time.perf_counter() - start) * 1000
                logger.error(
                    f"✗ {func_name} failed after {elapsed_ms:.1f}ms: {e}",
                    extra={
                        "event": "function_error",
                        "function": func_name,
                        "duration_ms": round(elapsed_ms, 1),
                        "error": str(e),
                        "error_type": type(e).__name__,
                    },
                )
                raise

        if asyncio.iscoroutinefunction(fn):
            return async_wrapper
        return sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator
