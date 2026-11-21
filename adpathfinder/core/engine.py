from adpathfinder.collectors.domain_collector import DomainCollector
from adpathfinder.collectors.user_collector import UserCollector
from adpathfinder.collectors.group_collector import GroupCollector
from adpathfinder.collectors.computer_collector import ComputerCollector
from adpathfinder.collectors.ou_collector import OUCollector

from adpathfinder.normalizer.normalizer import DataNormalizer

from adpathfinder.relationships.relationship_engine import (
    RelationshipEngine
)

from adpathfinder.analyzers.user_analyzer import UserAnalyzer
from adpathfinder.analyzers.group_analyzer import GroupAnalyzer
from adpathfinder.analyzers.domain_analyzer import DomainAnalyzer
from adpathfinder.analyzers.privilege_analyzer import (
    PrivilegeAnalyzer
)

from adpathfinder.risk.risk_engine import RiskEngine

from adpathfinder.utils.data_exporter import export_json
from adpathfinder.analyzers.relationship_analyzer import RelationshipAnalyzer

class ADPathFinderEngine:
    """
    Main engine of ADPathFinder.
    """

    def __init__(self, config, logger):

        self.config = config

        self.logger = logger

        self.normalizer = DataNormalizer()

        self.user_analyzer = UserAnalyzer()

        self.group_analyzer = GroupAnalyzer()

        self.domain_analyzer = DomainAnalyzer()

        self.privilege_analyzer = PrivilegeAnalyzer()

        self.risk_engine = RiskEngine()

        self.logger.info(
            "ADPathFinder engine initialized"
        )

    def collect_data(self):

        self.logger.info(
            "Starting data collection"
        )

        collected_data = {
            "domain": DomainCollector().collect(),
            "users": UserCollector().collect(),
            "groups": GroupCollector().collect(),
            "computers": ComputerCollector().collect(),
            "organizational_units": OUCollector().collect()
        }

        self.logger.info(
            "Data collection completed"
        )

        return collected_data

    def normalize_data(self, collected_data):

        self.logger.info(
            "Starting data normalization"
        )

        normalized_data = self.normalizer.normalize_all(
            collected_data
        )

        self.logger.info(
            "Data normalization completed"
        )

        return normalized_data

    def analyze_relationships(self, normalized_data):

        relationship_engine = RelationshipEngine(
            normalized_data
        )

        relationships = (
            relationship_engine.build_relationships()
        )

        relationship_summary = (
            relationship_engine.get_relationship_summary()
        )

        return relationships, relationship_summary

    def analyze_security(self, normalized_data):

        self.logger.info(
            "Starting security analysis"
        )

        findings = []

        findings.extend(
            self.user_analyzer.analyze(
                normalized_data["users"]
            )
        )

        findings.extend(
            self.group_analyzer.analyze(
                normalized_data["groups"]
            )
        )

        findings.extend(
            self.domain_analyzer.analyze(
                normalized_data["domain"]
            )
        )

        findings.extend(
            self.privilege_analyzer.analyze(
                normalized_data["users"],
                normalized_data["groups"]
            )
        )

        self.logger.info(
            f"Security findings generated: {len(findings)}"
        )

        return findings

    def analyze_risk(self, findings):

        risk_report = (
            self.risk_engine.generate_risk_report(
                findings
            )
        )

        return risk_report

    def save_processed_data(
        self,
        normalized_data,
        relationships,
        findings,
        risk_report
    ):

        export_json(
            normalized_data,
            "normalized_data.json"
        )

        export_json(
            relationships,
            "relationships.json"
        )

        export_json(
            findings,
            "security_findings.json"
        )

        export_json(
            risk_report,
            "risk_report.json"
        )

        self.logger.info(
            "Processed data and security reports exported"
        )

    def start(self):

        self.logger.info(
            "ADPathFinder engine started"
        )

        print("\nADPathFinder Engine")
        print("-------------------")

        print(
            f"Project: {self.config['project_name']}"
        )

        print(
            f"Version: {self.config['version']}"
        )

        print(
            f"Environment: {self.config['environment']}"
        )

        # 1. Collection
        print("\n[1] Collecting data...")

        collected_data = self.collect_data()

        # 2. Normalization
        print("[2] Normalizing data...")

        normalized_data = self.normalize_data(
            collected_data
        )

        # 3. Relationships
        print("[3] Mapping relationships...")

        relationships, relationship_summary = (
            self.analyze_relationships(
                normalized_data
            )
        )

        # 4. Security Analysis
        print("[4] Analyzing security...")

        findings = self.analyze_security(
            normalized_data
        )

        # 5. Relationship analysis
        relationship_analyzer = RelationshipAnalyzer()

        relationship_findings = relationship_analyzer.analyze(
            normalized_data,
            relationships
        )

        findings.extend(relationship_findings)

        # 5. Risk Calculation
        print("[5] Calculating risk...")

        risk_report = self.analyze_risk(
            findings
        )

        # 6. Export
        print("[6] Exporting results...")

        self.save_processed_data(
            normalized_data,
            relationships,
            findings,
            risk_report
        )

        # Final summary
        print("\nADPathFinder Analysis Summary")
        print("=" * 40)

        print(
            f"Domain: {normalized_data['domain']['name']}"
        )

        print(
            f"Users: {len(normalized_data['users'])}"
        )

        print(
            f"Groups: {len(normalized_data['groups'])}"
        )

        print(
            f"Computers: {len(normalized_data['computers'])}"
        )

        print(
            f"OUs: {len(normalized_data['organizational_units'])}"
        )

        print(
            f"Relationships: {len(relationships)}"
        )

        print(
            f"Security Findings: {risk_report['total_findings']}"
        )

        print(
            f"Risk Score: {risk_report['risk_score']}"
        )

        print(
            f"Risk Level: {risk_report['risk_level']}"
        )

        print("\nSeverity Breakdown")

        for severity, count in (
            risk_report["severity_summary"].items()
        ):

            print(
                f"{severity}: {count}"
            )

        print(
            "\nAnalysis completed successfully."
        )

    def shutdown(self):

        self.logger.info(
            "ADPathFinder engine stopped"
        )

        print(
            "\nADPathFinder shutdown complete."
        )