class AttackPathRiskEngine:

    PRIVILEGED_GROUP_WEIGHTS = {

        "enterprise admins": 50,

        "schema admins": 50,

        "domain admins": 40,

        "administrators": 35,

        "gg-server-admins": 30,

        "gg-it-admins": 25,

        "account operators": 20,

        "backup operators": 20,

        "server operators": 20,

        "print operators": 15,

        "group policy creator owners": 20,

    }


    PATH_LENGTH_WEIGHTS = {

        1: 30,

        2: 25,

        3: 20,

        4: 15,

        5: 10,

    }


    def normalize_name(self, name):

        return str(name).strip().lower()


    def calculate_privileged_group_score(
        self,
        target_group
    ):

        group_name = self.normalize_name(
            target_group
        )

        return self.PRIVILEGED_GROUP_WEIGHTS.get(
            group_name,
            10
        )


    def calculate_path_length_score(
        self,
        path_length
    ):

        if path_length in self.PATH_LENGTH_WEIGHTS:

            return self.PATH_LENGTH_WEIGHTS[
                path_length
            ]

        return 5


    def calculate_direct_membership_score(
        self,
        path_length
    ):

        if path_length == 1:

            return 20

        return 0


    def calculate_risk_score(
        self,
        attack_path
    ):

        target_group = attack_path.get(
            "target_group",
            ""
        )

        path_length = attack_path.get(
            "path_length",
            0
        )


        privileged_group_score = (
            self.calculate_privileged_group_score(
                target_group
            )
        )


        path_length_score = (
            self.calculate_path_length_score(
                path_length
            )
        )


        direct_membership_score = (
            self.calculate_direct_membership_score(
                path_length
            )
        )


        total_score = (
            privileged_group_score
            + path_length_score
            + direct_membership_score
        )


        return {

            "privileged_group_score":
                privileged_group_score,

            "path_length_score":
                path_length_score,

            "direct_membership_score":
                direct_membership_score,

            "total_score":
                total_score,

            "risk_level":
                self.classify_risk(total_score),

        }


    @staticmethod
    def classify_risk(score):

        if score >= 80:

            return "Critical"

        elif score >= 60:

            return "High"

        elif score >= 40:

            return "Medium"

        else:

            return "Low"


    def prioritize_attack_paths(
        self,
        attack_paths
    ):

        prioritized_paths = []


        for attack_path in attack_paths:

            risk_data = self.calculate_risk_score(
                attack_path
            )


            prioritized_path = {
                **attack_path,

                "risk_score":
                    risk_data["total_score"],

                "risk_level":
                    risk_data["risk_level"],

                "risk_breakdown": {

                    "privileged_group_score":
                        risk_data[
                            "privileged_group_score"
                        ],

                    "path_length_score":
                        risk_data[
                            "path_length_score"
                        ],

                    "direct_membership_score":
                        risk_data[
                            "direct_membership_score"
                        ],

                }

            }


            prioritized_paths.append(
                prioritized_path
            )


        prioritized_paths.sort(
            key=lambda path: path.get(
                "risk_score",
                0
            ),
            reverse=True
        )


        return prioritized_paths


    def get_summary(
        self,
        prioritized_paths
    ):

        return {

            "total_attack_paths":
                len(prioritized_paths),

            "critical_paths":
                sum(
                    1
                    for path in prioritized_paths
                    if path.get("risk_level")
                    == "Critical"
                ),

            "high_risk_paths":
                sum(
                    1
                    for path in prioritized_paths
                    if path.get("risk_level")
                    == "High"
                ),

            "medium_risk_paths":
                sum(
                    1
                    for path in prioritized_paths
                    if path.get("risk_level")
                    == "Medium"
                ),

            "low_risk_paths":
                sum(
                    1
                    for path in prioritized_paths
                    if path.get("risk_level")
                    == "Low"
                ),

        }