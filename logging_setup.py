import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from .paths import LOGS_DIR, ensure_directories


def setup_logging(command: str, args: List[str]) -> logging.Logger:
    ensure_directories()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"findmissingbytes_{command}_{timestamp}.log"
    log_path = LOGS_DIR / log_filename

    logger = logging.getLogger("findmissingbytes")
    logger.setLevel(logging.DEBUG)

    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_format)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info(f"Command: findmissingbytes {command} {' '.join(args)}")
    logger.debug(f"Log file: {log_path}")

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger("findmissingbytes")
