class AttackPathRiskEngine:

    PRIVILEGED_GROUP_WEIGHTS = {
        "domain admins": 40,
        "enterprise admins": 50,
        "schema admins": 50,
        "administrators": 35,
        "account operators": 25,
        "backup operators": 25,
        "server operators": 25,
        "print operators": 15,
        "group policy creator owners": 30,
        "gg-it-admins": 30,
        "gg-server-admins": 25,
    }

    PATH_LENGTH_WEIGHTS = {
        1: 30,
        2: 25,
        3: 20,
        4: 15,
        5: 10,
    }

    def calculate_score(self, attack_path):

        target_group = (
            attack_path.get("target_group", "")
            .strip()
            .lower()
        )

        path_length = attack_path.get(
            "path_length",
            0
        )

        score = 0

        # Target privilege score
        privilege_score = (
            self.PRIVILEGED_GROUP_WEIGHTS.get(
                target_group,
                15
            )
        )

        score += privilege_score

        # Path complexity score
        path_score = (
            self.PATH_LENGTH_WEIGHTS.get(
                path_length,
                5
            )
        )

        score += path_score

        # Direct membership receives additional priority
        if path_length == 1:

            score += 20

        return min(score, 100)

    def determine_risk_level(self, score):

        if score >= 80:
            return "Critical"

        elif score >= 60:
            return "High"

        elif score >= 40:
            return "Medium"

        else:
            return "Low"

    def prioritize_paths(self, attack_paths):

        prioritized_paths = []

        for attack_path in attack_paths:

            score = self.calculate_score(
                attack_path
            )

            risk_level = self.determine_risk_level(
                score
            )

            prioritized_path = attack_path.copy()

            prioritized_path["risk_score"] = score

            prioritized_path["risk_level"] = (
                risk_level
            )

            prioritized_path["priority"] = (
                self.get_priority(risk_level)
            )

            prioritized_paths.append(
                prioritized_path
            )

        prioritized_paths.sort(
            key=lambda path: path["risk_score"],
            reverse=True
        )

        return prioritized_paths

    @staticmethod
    def get_priority(risk_level):

        priority_mapping = {
            "Critical": "Immediate Investigation",
            "High": "High Priority",
            "Medium": "Moderate Priority",
            "Low": "Low Priority",
        }

        return priority_mapping.get(
            risk_level,
            "Review Required"
        )

    def get_summary(self, prioritized_paths):

        return {
            "total_paths": len(prioritized_paths),

            "critical": sum(
                1 for path in prioritized_paths
                if path["risk_level"] == "Critical"
            ),

            "high": sum(
                1 for path in prioritized_paths
                if path["risk_level"] == "High"
            ),

            "medium": sum(
                1 for path in prioritized_paths
                if path["risk_level"] == "Medium"
            ),

            "low": sum(
                1 for path in prioritized_paths
                if path["risk_level"] == "Low"
            ),
        }