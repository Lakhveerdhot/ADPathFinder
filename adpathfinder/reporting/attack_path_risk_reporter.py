import json
from pathlib import Path


class AttackPathRiskReporter:

    def __init__(self, output_directory="data/processed"):

        self.output_directory = Path(
            output_directory
        )

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def export_json(
        self,
        prioritized_paths,
        summary
    ):

        output_file = (
            self.output_directory
            / "prioritized_attack_paths.json"
        )

        report = {
            "report_type": (
                "Prioritized Attack Path Risk Assessment"
            ),

            "summary": summary,

            "attack_paths": prioritized_paths
        }

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(
            f"[+] Prioritized attack path report saved: "
            f"{output_file}"
        )

        return output_file