from adpathfinder.models.finding import Finding


class PrivilegeAnalyzer:
    """
    Analyzes privilege-related configurations.
    """

    PRIVILEGED_GROUPS = [
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "gg-it-admins",
        "gg-server-admins"
    ]

    def analyze(self, users, groups):

        findings = []

        privileged_accounts = set()

        for user in users:

            username = user.get("username", "Unknown")

            user_groups = [
                group.lower()
                for group in user.get("groups", [])
            ]

            for group in self.PRIVILEGED_GROUPS:

                if group in user_groups:

                    privileged_accounts.add(username)

                    findings.append(
                        Finding(
                            title="Privileged User Account",
                            description=(
                                f"{username} has membership "
                                f"in privileged group {group}."
                            ),
                            severity="High",
                            affected_object=username,
                            recommendation=(
                                "Verify that this account "
                                "requires administrative access. "
                                "Use separate administrative "
                                "accounts where appropriate."
                            ),
                            category="Privilege Management"
                        ).to_dict()
                    )

        # Privileged account summary
        if privileged_accounts:

            findings.append(
                Finding(
                    title="Privileged Accounts Detected",
                    description=(
                        f"ADPathFinder identified "
                        f"{len(privileged_accounts)} "
                        "accounts with privileged group membership."
                    ),
                    severity="Medium",
                    affected_object="Active Directory Domain",
                    recommendation=(
                        "Review all privileged accounts, "
                        "validate business justification, "
                        "and enforce least privilege."
                    ),
                    category="Privilege Management"
                ).to_dict()
            )

        return findings