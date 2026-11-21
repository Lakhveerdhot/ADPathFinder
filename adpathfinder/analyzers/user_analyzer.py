from adpathfinder.models.finding import Finding


class UserAnalyzer:
    """
    Analyzes Active Directory users for security risks.
    """

    def analyze(self, users):

        findings = []

        for user in users:

            username = user.get("username", "Unknown")

            # Password never expires
            if user.get("password_never_expires"):

                findings.append(
                    Finding(
                        title="Password Never Expires",
                        description=(
                            f"User {username} has a password "
                            "configured to never expire."
                        ),
                        severity="Medium",
                        affected_object=username,
                        recommendation=(
                            "Review the account and configure "
                            "an appropriate password expiration "
                            "policy where applicable."
                        ),
                        category="Account Security"
                    ).to_dict()
                )

            # Password not required
            if user.get("password_not_required"):

                findings.append(
                    Finding(
                        title="Password Not Required",
                        description=(
                            f"User {username} has the "
                            "Password Not Required attribute enabled."
                        ),
                        severity="Critical",
                        affected_object=username,
                        recommendation=(
                            "Disable the Password Not Required "
                            "attribute and enforce a strong "
                            "authentication policy."
                        ),
                        category="Authentication"
                    ).to_dict()
                )

            # Disabled account
            if not user.get("enabled", True):

                findings.append(
                    Finding(
                        title="Disabled User Account",
                        description=(
                            f"User {username} is disabled."
                        ),
                        severity="Informational",
                        affected_object=username,
                        recommendation=(
                            "Confirm that the account is no "
                            "longer required and remove it "
                            "according to account lifecycle policy."
                        ),
                        category="Account Management"
                    ).to_dict()
                )

            # Privileged group membership
            privileged_groups = [
                "domain admins",
                "enterprise admins",
                "schema admins",
                "administrators",
                "gg-it-admins",
                "gg-server-admins"
            ]

            user_groups = [
                group.lower()
                for group in user.get("groups", [])
            ]

            for group in privileged_groups:

                if group in user_groups:

                    findings.append(
                        Finding(
                            title="Privileged Group Membership",
                            description=(
                                f"User {username} belongs to "
                                f"privileged group {group}."
                            ),
                            severity="High",
                            affected_object=username,
                            recommendation=(
                                "Review the user's privileges "
                                "and ensure administrative "
                                "access is necessary."
                            ),
                            category="Privilege Management"
                        ).to_dict()
                    )

        return findings