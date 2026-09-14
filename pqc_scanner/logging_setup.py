

import json
import logging
import os
import sys
import time
from pathlib import Path

TRACE = 5
LOGGER_NAME = "pqc_scanner"

_CONSOLE_LEVELS = {0: logging.INFO, 1: logging.DEBUG, 2: TRACE}

_LEVEL_COLORS = {
    TRACE: "\033[38;5;245m",
    logging.DEBUG: "\033[36m",
    logging.INFO: "\033[32m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
    logging.CRITICAL: "\033[1;37;41m",
}
_RESET = "\033[0m"
_DIM = "\033[38;5;245m"

logging.addLevelName(TRACE, "TRACE")


def _trace(self, message, *args, **kwargs) -> None:
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


logging.Logger.trace = _trace
logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())


def get_logger(name: str) -> logging.Logger:

    if name == LOGGER_NAME or name.startswith(LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


class _ConsoleFormatter(logging.Formatter):


    def __init__(self, color: bool) -> None:
        super().__init__(datefmt="%H:%M:%S")
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        short = record.name
        if short.startswith(LOGGER_NAME + "."):
            short = short[len(LOGGER_NAME) + 1:]
        elif short == LOGGER_NAME:
            short = "main"
        short = short.rsplit(".", 1)[-1]

        stamp = self.formatTime(record, self.datefmt)
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"

        if self.color:
            tint = _LEVEL_COLORS.get(record.levelno, "")
            return (f"{_DIM}{stamp}{_RESET} {tint}{record.levelname:<7}{_RESET} "
                    f"{_DIM}{short:<16}{_RESET} {message}")
        return f"{stamp} {record.levelname:<7} {short:<16} {message}"


class _JsonFormatter(logging.Formatter):


    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                         + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(getattr(record, "context", {}))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if sys.platform == "win32":
        return _enable_windows_vt()
    return os.environ.get("TERM", "") != "dumb"


def _enable_windows_vt() -> bool:

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-12)  # STD_ERROR_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def configure_logging(
    verbosity: int = 0,
    quiet: bool = False,
    log_file: str | None = None,
    json_logs: bool = False,
    color: bool | None = None,
) -> logging.Logger:

    console_level = logging.WARNING if quiet else _CONSOLE_LEVELS.get(
        min(verbosity, 2), TRACE
    )

    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        if not isinstance(handler, logging.NullHandler):
            handler.close()
    logger.propagate = False

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(console_level)
    if json_logs:
        console.setFormatter(_JsonFormatter())
    else:
        use_color = _supports_color(sys.stderr) if color is None else color
        console.setFormatter(_ConsoleFormatter(use_color))
    logger.addHandler(console)

    file_level = console_level
    if log_file:
        file_level = min(console_level, logging.DEBUG)
        path = Path(log_file)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, mode="w", encoding="utf-8")
        file_handler.setLevel(file_level)
        file_handler.setFormatter(
            _JsonFormatter() if json_logs else logging.Formatter(
                "%(asctime)s %(levelname)-7s %(name)-28s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)

    logger.setLevel(min(console_level, file_level))
    return logger


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    return f"{int(seconds // 60)}m{seconds % 60:04.1f}s"


def format_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KiB", "MiB"):
        if size < 1024:
            return f"{size:.0f}B" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GiB"
