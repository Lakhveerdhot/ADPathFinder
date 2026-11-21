import logging
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_DIRECTORY = PROJECT_ROOT / "logs"

LOG_DIRECTORY.mkdir(exist_ok=True)

LOG_FILE = LOG_DIRECTORY / "adpathfinder.log"


def setup_logger():
    """
    Configure ADPathFinder logging.
    """

    logger = logging.getLogger("ADPathFinder")

    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    # Console handler
    console_handler = logging.StreamHandler()

    console_handler.setFormatter(formatter)

    # File handler
    file_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    logger.addHandler(file_handler)

    return logger