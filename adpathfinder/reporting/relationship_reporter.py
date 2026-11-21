import json
from pathlib import Path


class RelationshipReporter:

    def __init__(self, output_directory="reports"):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def export_json(self, findings):

        output_file = (
            self.output_directory
            / "relationship_analysis.json"
        )

        report = {
            "report_type": "Relationship Analysis",
            "total_findings": len(findings),
            "findings": findings
        }

        with open(output_file, "w", encoding="utf-8") as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(f"[+] Relationship report saved: {output_file}")

        return output_file