import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DIRECTORY = PROJECT_ROOT / "data" / "processed"


def export_json(data, filename):

    PROCESSED_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    file_path = PROCESSED_DIRECTORY / filename

    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )

    return file_path