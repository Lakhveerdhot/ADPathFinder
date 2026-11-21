class RiskEngine:
    """
    Calculates risk scores from security findings.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 2,
        "Informational": 1
    }

    def calculate_finding_score(self, finding):

        severity = finding.get(
            "severity",
            "Informational"
        )

        return self.SEVERITY_WEIGHTS.get(
            severity,
            1
        )

    def calculate_total_score(self, findings):

        total_score = sum(
            self.calculate_finding_score(finding)
            for finding in findings
        )

        return total_score

    def calculate_risk_level(self, total_score):

        if total_score >= 50:

            return "Critical"

        elif total_score >= 30:

            return "High"

        elif total_score >= 15:

            return "Medium"

        elif total_score >= 5:

            return "Low"

        return "Minimal"

    def get_severity_summary(self, findings):

        summary = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }

        for finding in findings:

            severity = finding.get(
                "severity",
                "Informational"
            )

            if severity in summary:

                summary[severity] += 1

        return summary

    def generate_risk_report(self, findings):

        total_score = self.calculate_total_score(
            findings
        )

        severity_summary = (
            self.get_severity_summary(findings)
        )

        risk_level = self.calculate_risk_level(
            total_score
        )

        return {
            "total_findings": len(findings),
            "risk_score": total_score,
            "risk_level": risk_level,
            "severity_summary": severity_summary
        }