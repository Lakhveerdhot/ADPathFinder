from adpathfinder.models.finding import Finding


class DomainAnalyzer:
    """
    Analyzes domain-level security configurations.
    """

    def analyze(self, domain):

        findings = []

        password_policy = domain.get(
            "password_policy",
            {}
        )

        # Minimum password length
        minimum_length = password_policy.get(
            "minimum_password_length"
        )

        if minimum_length is not None:

            if minimum_length < 8:

                findings.append(
                    Finding(
                        title="Weak Minimum Password Length",
                        description=(
                            f"The domain minimum password "
                            f"length is {minimum_length} characters."
                        ),
                        severity="High",
                        affected_object=domain.get(
                            "name",
                            "Domain"
                        ),
                        recommendation=(
                            "Review the password policy and "
                            "consider increasing the minimum "
                            "password length."
                        ),
                        category="Password Policy"
                    ).to_dict()
                )

            elif minimum_length < 12:

                findings.append(
                    Finding(
                        title="Minimum Password Length Review",
                        description=(
                            f"The domain minimum password "
                            f"length is {minimum_length} characters."
                        ),
                        severity="Low",
                        affected_object=domain.get(
                            "name",
                            "Domain"
                        ),
                        recommendation=(
                            "Consider a longer password "
                            "length based on your organization's "
                            "security requirements."
                        ),
                        category="Password Policy"
                    ).to_dict()
                )

        # Password complexity
        complexity = password_policy.get(
            "password_complexity",
            None
        )

        if complexity is False:

            findings.append(
                Finding(
                    title="Password Complexity Disabled",
                    description=(
                        "The domain password complexity "
                        "requirement is disabled."
                    ),
                    severity="High",
                    affected_object=domain.get(
                        "name",
                        "Domain"
                    ),
                    recommendation=(
                        "Review and enable an appropriate "
                        "password complexity policy."
                    ),
                    category="Password Policy"
                ).to_dict()
            )

        # Lockout threshold
        lockout_threshold = password_policy.get(
            "lockout_threshold"
        )

        if lockout_threshold == 0:

            findings.append(
                Finding(
                    title="Account Lockout Threshold Disabled",
                    description=(
                        "The domain account lockout threshold "
                        "is configured as zero."
                    ),
                    severity="Medium",
                    affected_object=domain.get(
                        "name",
                        "Domain"
                    ),
                    recommendation=(
                        "Review the account lockout policy "
                        "and configure an appropriate threshold "
                        "based on operational requirements."
                    ),
                    category="Authentication"
                ).to_dict()
            )

        return findings