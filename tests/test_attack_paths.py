import json
from pathlib import Path

from adpathfinder.analyzers.attack_path_analyzer import (
    AttackPathAnalyzer
)

from adpathfinder.reporting.attack_path_reporter import (
    AttackPathReporter
)


BASE_DIR = Path(__file__).resolve().parent.parent

PROCESSED_DIR = BASE_DIR / "data" / "processed"


def load_json(filename):

    file_path = PROCESSED_DIR / filename

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def main():

    print("\n" + "=" * 60)
    print("ADPathFinder - Attack Path Discovery")
    print("=" * 60)

    normalized_data = load_json(
        "normalized_data.json"
    )

    users = normalized_data.get(
        "users",
        []
    )

    groups = normalized_data.get(
        "groups",
        []
    )

    analyzer = AttackPathAnalyzer(
        max_depth=10
    )

    attack_paths = analyzer.find_privileged_paths(
        users,
        groups
    )

    summary = analyzer.get_summary()

    print("\n[+] Attack Path Analysis Completed")

    print("\nSummary:")
    print("-" * 40)

    for key, value in summary.items():

        print(f"{key}: {value}")

    print("\nDiscovered Attack Paths:")
    print("-" * 40)

    if not attack_paths:

        print(
            "No potential paths to privileged groups found."
        )

    for index, attack_path in enumerate(
        attack_paths,
        start=1
    ):

        print(f"\nAttack Path #{index}")

        print(
            f"Source User: "
            f"{attack_path['source_user']}"
        )

        print(
            f"Target Group: "
            f"{attack_path['target_group']}"
        )

        print(
            f"Risk: "
            f"{attack_path['risk']}"
        )

        print(
            f"Path Length: "
            f"{attack_path['path_length']}"
        )

        print("Path:")

        for node in attack_path["path"]:

            print(f"  -> {node}")

    reporter = AttackPathReporter()

    reporter.export_json(
        attack_paths
    )

    print("\n[+] Day 12 analysis completed")


if __name__ == "__main__":
    main()