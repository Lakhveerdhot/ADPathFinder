from adpathfinder.collectors.domain_collector import DomainCollector
from adpathfinder.collectors.user_collector import UserCollector
from adpathfinder.collectors.group_collector import GroupCollector
from adpathfinder.collectors.computer_collector import ComputerCollector
from adpathfinder.collectors.ou_collector import OUCollector

from adpathfinder.normalizer.normalizer import DataNormalizer

from adpathfinder.analyzers.user_analyzer import UserAnalyzer
from adpathfinder.analyzers.group_analyzer import GroupAnalyzer
from adpathfinder.analyzers.domain_analyzer import DomainAnalyzer
from adpathfinder.analyzers.privilege_analyzer import (
    PrivilegeAnalyzer
)

from adpathfinder.risk.risk_engine import RiskEngine


def main():

    print("\nADPathFinder Security Analysis Test")
    print("=" * 45)

    # Collect
    collected_data = {
        "domain": DomainCollector().collect(),
        "users": UserCollector().collect(),
        "groups": GroupCollector().collect(),
        "computers": ComputerCollector().collect(),
        "organizational_units": OUCollector().collect()
    }

    # Normalize
    normalized_data = DataNormalizer().normalize_all(
        collected_data
    )

    # Security analysis
    findings = []

    findings.extend(
        UserAnalyzer().analyze(
            normalized_data["users"]
        )
    )

    findings.extend(
        GroupAnalyzer().analyze(
            normalized_data["groups"]
        )
    )

    findings.extend(
        DomainAnalyzer().analyze(
            normalized_data["domain"]
        )
    )

    findings.extend(
        PrivilegeAnalyzer().analyze(
            normalized_data["users"],
            normalized_data["groups"]
        )
    )

    # Risk
    risk_engine = RiskEngine()

    risk_report = risk_engine.generate_risk_report(
        findings
    )

    # Display findings
    print("\n[+] Security Findings")

    for finding in findings:

        print(
            f"\n[{finding['severity']}] "
            f"{finding['title']}"
        )

        print(
            f"Object: {finding['affected_object']}"
        )

        print(
            f"Description: {finding['description']}"
        )

        print(
            f"Recommendation: {finding['recommendation']}"
        )

    # Risk summary
    print("\n[+] Risk Summary")

    print(
        f"Total Findings: {risk_report['total_findings']}"
    )

    print(
        f"Risk Score: {risk_report['risk_score']}"
    )

    print(
        f"Risk Level: {risk_report['risk_level']}"
    )

    print("\n[+] Severity Breakdown")

    for severity, count in (
        risk_report["severity_summary"].items()
    ):

        print(
            f"{severity}: {count}"
        )

    print(
        "\nSecurity analysis test completed."
    )


if __name__ == "__main__":

    main()