import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DATA_DIRECTORY = PROJECT_ROOT / "data" / "raw"


def load_json_file(filename):
    """
    Load JSON data from the raw data directory.
    """

    file_path = RAW_DATA_DIRECTORY / filename

    if not file_path.exists():

        raise FileNotFoundError(
            f"Data file not found: {file_path}"
        )

    with open(file_path, "r", encoding="utf-8") as file:

        return json.load(file)