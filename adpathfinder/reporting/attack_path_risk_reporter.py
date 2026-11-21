import json
import os


class AttackPathRiskReporter:

    def __init__(self, output_directory="data/processed"):

        self.output_directory = output_directory

        os.makedirs(
            self.output_directory,
            exist_ok=True
        )


    def export_json(
        self,
        prioritized_paths,
        summary
    ):

        report = {

            "summary": summary,

            "prioritized_attack_paths":
                prioritized_paths,

        }


        output_file = os.path.join(
            self.output_directory,
            "attack_path_risk_report.json"
        )


        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4
            )


        print(
            f"[+] Attack path risk report saved: "
            f"{output_file}"
        )


        return output_file


    def print_report(
        self,
        prioritized_paths,
        summary
    ):

        print("\n")
        print("=" * 60)
        print("ADPathFinder - Attack Path Risk Prioritization")
        print("=" * 60)


        print("\nSummary:")
        print("-" * 40)


        for key, value in summary.items():

            print(
                f"{key}: {value}"
            )


        print("\nPrioritized Attack Paths:")
        print("-" * 40)


        if not prioritized_paths:

            print(
                "No attack paths available for prioritization."
            )

            return


        for index, path in enumerate(
            prioritized_paths,
            start=1
        ):

            print(
                f"\nAttack Path #{index}"
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
                f"{path.get('risk_score')}"
            )


            print(
                f"Risk Level: "
                f"{path.get('risk_level')}"
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


            print("\nRisk Breakdown:")


            breakdown = path.get(
                "risk_breakdown",
                {}
            )


            print(
                f"  Privileged Group Score: "
                f"{breakdown.get('privileged_group_score')}"
            )


            print(
                f"  Path Length Score: "
                f"{breakdown.get('path_length_score')}"
            )


            print(
                f"  Direct Membership Score: "
                f"{breakdown.get('direct_membership_score')}"
            )