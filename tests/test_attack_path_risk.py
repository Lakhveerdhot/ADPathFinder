import json
from pathlib import Path

from adpathfinder.risk.attack_path_risk_engine import (
    AttackPathRiskEngine
)

from adpathfinder.reporting.attack_path_risk_reporter import (
    AttackPathRiskReporter
)


BASE_DIR = Path(__file__).resolve().parent.parent

PROCESSED_DIR = (
    BASE_DIR
    / "data"
    / "processed"
)


def load_json(filename):

    file_path = (
        PROCESSED_DIR
        / filename
    )

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def main():

    print("\n" + "=" * 60)

    print(
        "ADPathFinder - Day 13 "
        "Attack Path Risk Prioritization"
    )

    print("=" * 60)

    attack_path_data = load_json(
        "attack_paths.json"
    )

    attack_paths = attack_path_data.get(
        "attack_paths",
        []
    )

    risk_engine = AttackPathRiskEngine()

    prioritized_paths = (
        risk_engine.prioritize_paths(
            attack_paths
        )
    )

    summary = risk_engine.get_summary(
        prioritized_paths
    )

    print("\n[+] Risk Prioritization Completed")

    print("\nSummary:")
    print("-" * 40)

    for key, value in summary.items():

        print(
            f"{key}: {value}"
        )

    print("\nPrioritized Attack Paths:")
    print("-" * 40)

    for index, path in enumerate(
        prioritized_paths,
        start=1
    ):

        print(
            f"\nPath #{index}"
        )

        print(
            f"Source User: "
            f"{path.get('source_user')}"
        )

        print(
            f"Target Group: "
            f"{path.get('target_group')}"
        )

        print(
            f"Risk Score: "
            f"{path.get('risk_score')}/100"
        )

        print(
            f"Risk Level: "
            f"{path.get('risk_level')}"
        )

        print(
            f"Priority: "
            f"{path.get('priority')}"
        )

        print(
            f"Path Length: "
            f"{path.get('path_length')}"
        )

        print("Path:")

        for node in path.get(
            "path",
            []
        ):

            print(
                f"  -> {node}"
            )

    reporter = AttackPathRiskReporter()

    reporter.export_json(
        prioritized_paths,
        summary
    )

    print(
        "\n[+] Day 13 completed successfully"
    )


if __name__ == "__main__":

    main()