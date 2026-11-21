from adpathfinder.models.finding import Finding


class GroupAnalyzer:
    """
    Analyzes Active Directory groups.
    """

    PRIVILEGED_GROUPS = [
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "gg-it-admins",
        "gg-server-admins",
        "gg-helpdesk"
    ]

    def analyze(self, groups):

        findings = []

        for group in groups:

            group_name = group.get("name", "Unknown")

            members = group.get("members", [])

            # Empty security groups
            if (
                group.get("category", "").lower() == "security"
                and len(members) == 0
            ):

                findings.append(
                    Finding(
                        title="Empty Security Group",
                        description=(
                            f"Security group {group_name} "
                            "has no members."
                        ),
                        severity="Informational",
                        affected_object=group_name,
                        recommendation=(
                            "Review whether the group is still "
                            "required. Remove unused groups "
                            "according to administrative policy."
                        ),
                        category="Group Management"
                    ).to_dict()
                )

            # Privileged groups
            if group_name.lower() in self.PRIVILEGED_GROUPS:

                findings.append(
                    Finding(
                        title="Privileged Group Identified",
                        description=(
                            f"{group_name} is a privileged "
                            "or administrative group."
                        ),
                        severity="High",
                        affected_object=group_name,
                        recommendation=(
                            "Review group membership regularly "
                            "and apply least privilege."
                        ),
                        category="Privilege Management"
                    ).to_dict()
                )

            # Large group membership
            if len(members) > 20:

                findings.append(
                    Finding(
                        title="Large Group Membership",
                        description=(
                            f"Group {group_name} contains "
                            f"{len(members)} members."
                        ),
                        severity="Low",
                        affected_object=group_name,
                        recommendation=(
                            "Review group membership and "
                            "consider whether access should "
                            "be divided into smaller groups."
                        ),
                        category="Group Management"
                    ).to_dict()
                )

        return findings