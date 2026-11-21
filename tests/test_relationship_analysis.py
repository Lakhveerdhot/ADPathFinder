import json
from pathlib import Path

from adpathfinder.analyzers.relationship_analyzer import (
    RelationshipAnalyzer
)


BASE_DIR = Path(__file__).resolve().parent.parent

PROCESSED_DIR = BASE_DIR / "data" / "processed"


def load_json(filename):

    file_path = PROCESSED_DIR / filename

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def main():

    print("\n" + "=" * 60)
    print("ADPathFinder - Day 11 Relationship Analysis")
    print("=" * 60)

    normalized_data = load_json("normalized_data.json")

    relationships = load_json("relationships.json")

    analyzer = RelationshipAnalyzer()

    findings = analyzer.analyze(
        normalized_data,
        relationships
    )

    summary = analyzer.get_summary()

    print("\n[+] Relationship Analysis Completed")

    print("\nSummary:")
    print("-" * 40)

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\nFindings:")
    print("-" * 40)

    for finding in findings:

        print(
            f"\n[{finding['severity']}] "
            f"{finding['title']}"
        )

        print(f"Object: {finding['affected_object']}")

        print(f"Description: {finding['description']}")

        print(f"Recommendation: {finding['recommendation']}")

    output_file = (
        PROCESSED_DIR
        / "relationship_findings.json"
    )

    with open(output_file, "w", encoding="utf-8") as file:

        json.dump(
            findings,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"\n[+] Findings exported to: {output_file}")


if __name__ == "__main__":
    main()