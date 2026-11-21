import json
from pathlib import Path


class AttackPathReporter:

    def __init__(self, output_directory="data/processed"):
        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True
        )

    def export_json(self, attack_paths):

        output_file = (
            self.output_directory
            / "attack_paths.json"
        )

        report = {
            "report_type": "Attack Path Analysis",
            "total_attack_paths": len(attack_paths),
            "attack_paths": attack_paths
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
            f"[+] Attack path report saved: {output_file}"
        )

        return output_file