from collections import defaultdict

from adpathfinder.models.finding import Finding


PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "domain controllers",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "group policy creator owners",
    "gg-it-admins",
    "gg-server-admins",
}


class RelationshipAnalyzer:

    def __init__(self):
        self.findings = []
        self.relationships = []

    @staticmethod
    def normalize_name(name):
        return str(name).strip().lower()

    def analyze(self, normalized_data, relationships=None):

        self.findings = []
        self.relationships = relationships or []

        users = normalized_data.get("users", [])
        groups = normalized_data.get("groups", [])

        self._analyze_privileged_memberships(users, groups)
        self._analyze_nested_groups(groups)
        self._analyze_large_groups(groups)
        self._analyze_empty_groups(groups)

        return self.findings

    def _analyze_privileged_memberships(self, users, groups):

        privileged_group_names = {
            self.normalize_name(group.get("name", ""))
            for group in groups
            if self.normalize_name(group.get("name", "")) in PRIVILEGED_GROUPS
        }

        for group in groups:

            group_name = group.get("name", "")
            normalized_group_name = self.normalize_name(group_name)

            if normalized_group_name not in PRIVILEGED_GROUPS:
                continue

            members = group.get("members", [])

            for member in members:

                member_name = (
                    member.get("name")
                    if isinstance(member, dict)
                    else str(member)
                )

                self.findings.append(
                    Finding(
                        title="Privileged Group Membership",
                        description=(
                            f"Object '{member_name}' is a member of "
                            f"the privileged group '{group_name}'. "
                            "This relationship may provide elevated "
                            "administrative privileges."
                        ),
                        severity="High",
                        affected_object=member_name,
                        recommendation=(
                            "Review whether this object requires "
                            "membership in the privileged group. "
                            "Remove unnecessary privileges and "
                            "implement least privilege."
                        ),
                        category="Relationship Analysis",
                    ).to_dict()
                )

    def _analyze_nested_groups(self, groups):

        group_map = {
            self.normalize_name(group.get("name", "")): group
            for group in groups
        }

        for group in groups:

            parent_group = group.get("name", "")
            members = group.get("members", [])

            for member in members:

                member_name = (
                    member.get("name")
                    if isinstance(member, dict)
                    else str(member)
                )

                normalized_member = self.normalize_name(member_name)

                if normalized_member not in group_map:
                    continue

                child_group = group_map[normalized_member]

                if (
                    self.normalize_name(parent_group)
                    in PRIVILEGED_GROUPS
                ):

                    self.findings.append(
                        Finding(
                            title="Nested Group in Privileged Group",
                            description=(
                                f"Group '{member_name}' is nested "
                                f"inside privileged group '{parent_group}'. "
                                "Members of the nested group may inherit "
                                "privileged access."
                            ),
                            severity="High",
                            affected_object=member_name,
                            recommendation=(
                                "Review nested group membership. "
                                "Avoid unnecessary nesting inside "
                                "privileged groups and verify all "
                                "members have legitimate access."
                            ),
                            category="Relationship Analysis",
                        ).to_dict()
                    )

    def _analyze_large_groups(self, groups):

        for group in groups:

            members = group.get("members", [])

            if len(members) > 20:

                self.findings.append(
                    Finding(
                        title="Large Group Membership",
                        description=(
                            f"Group '{group.get('name')}' contains "
                            f"{len(members)} members. Large groups can "
                            "make access reviews and privilege management "
                            "more difficult."
                        ),
                        severity="Low",
                        affected_object=group.get("name"),
                        recommendation=(
                            "Review group membership regularly. "
                            "Split groups according to responsibilities "
                            "and remove unnecessary members."
                        ),
                        category="Relationship Analysis",
                    ).to_dict()
                )

    def _analyze_empty_groups(self, groups):

        for group in groups:

            members = group.get("members", [])

            if len(members) == 0:

                self.findings.append(
                    Finding(
                        title="Empty Group",
                        description=(
                            f"Group '{group.get('name')}' has no members. "
                            "This group may be unnecessary or may indicate "
                            "incomplete access configuration."
                        ),
                        severity="Informational",
                        affected_object=group.get("name"),
                        recommendation=(
                            "Verify whether the group is required. "
                            "Delete unused groups after confirming "
                            "they are not referenced by applications "
                            "or access-control configurations."
                        ),
                        category="Relationship Analysis",
                    ).to_dict()
                )

    def get_summary(self):

        return {
            "total_relationship_findings": len(self.findings),
            "high": sum(
                1 for finding in self.findings
                if finding.get("severity") == "High"
            ),
            "medium": sum(
                1 for finding in self.findings
                if finding.get("severity") == "Medium"
            ),
            "low": sum(
                1 for finding in self.findings
                if finding.get("severity") == "Low"
            ),
            "informational": sum(
                1 for finding in self.findings
                if finding.get("severity") == "Informational"
            ),
        }