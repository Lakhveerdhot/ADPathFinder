from adpathfinder.collectors.domain_collector import DomainCollector
from adpathfinder.collectors.user_collector import UserCollector
from adpathfinder.collectors.group_collector import GroupCollector
from adpathfinder.collectors.computer_collector import ComputerCollector
from adpathfinder.collectors.ou_collector import OUCollector

from adpathfinder.normalizer.normalizer import DataNormalizer

from adpathfinder.relationships.relationship_engine import (
    RelationshipEngine
)


def main():

    print("\nADPathFinder Day 09 Test")
    print("=" * 40)

    # Collect data
    collected_data = {
        "domain": DomainCollector().collect(),
        "users": UserCollector().collect(),
        "groups": GroupCollector().collect(),
        "computers": ComputerCollector().collect(),
        "organizational_units": OUCollector().collect()
    }

    # Normalize
    normalizer = DataNormalizer()

    normalized_data = normalizer.normalize_all(
        collected_data
    )

    print("\n[+] Normalization")

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

    # Relationships
    relationship_engine = RelationshipEngine(
        normalized_data
    )

    relationships = (
        relationship_engine.build_relationships()
    )

    print("\n[+] Relationship Mapping")

    print(
        f"Total Relationships: {len(relationships)}"
    )

    # Summary
    summary = (
        relationship_engine.get_relationship_summary()
    )

    for relationship_type, count in summary.items():

        print(
            f"{relationship_type}: {count}"
        )

    # Specific object
    print("\n[+] Alice Relationships")

    alice_relationships = (
        relationship_engine.get_relationships_for_object(
            "alice.it"
        )
    )

    for relationship in alice_relationships:

        print(
            f"{relationship['source']} "
            f"--{relationship['relationship']}--> "
            f"{relationship['target']}"
        )

    print(
        "\nDay 09 testing completed successfully."
    )


if __name__ == "__main__":

    main()