import json

from adpathfinder.risk.attack_path_risk_engine import (
    AttackPathRiskEngine
)

from adpathfinder.reporting.attack_path_risk_reporter import (
    AttackPathRiskReporter
)


def main():

    print("=" * 60)

    print(
        "ADPathFinder - Attack Path Risk Prioritization"
    )

    print("=" * 60)


    # Load discovered attack paths

    input_file = (
        "data/processed/attack_paths.json"
    )


    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as file:

        attack_path_data = json.load(file)


    attack_paths = attack_path_data.get(
        "attack_paths",
        []
    )


    print(
        f"\n[+] Loaded attack paths: "
        f"{len(attack_paths)}"
    )


    # Initialize risk engine

    risk_engine = AttackPathRiskEngine()


    # Calculate and prioritize risk

    prioritized_paths = (
        risk_engine.prioritize_attack_paths(
            attack_paths
        )
    )


    # Generate summary

    summary = risk_engine.get_summary(
        prioritized_paths
    )


    # Initialize reporter

    reporter = AttackPathRiskReporter()


    # Print report

    reporter.print_report(
        prioritized_paths,
        summary
    )


    # Export JSON report

    reporter.export_json(
        prioritized_paths,
        summary
    )


    print(
        "\n[+] Day 13 analysis completed"
    )


if __name__ == "__main__":

    main()