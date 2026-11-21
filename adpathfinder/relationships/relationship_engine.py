class RelationshipEngine:
    """
    Maps relationships between Active Directory objects.
    """

    def __init__(self, normalized_data):

        self.data = normalized_data

        self.relationships = []

    def add_relationship(
        self,
        source,
        relationship_type,
        target
    ):

        relationship = {
            "source": source,
            "relationship": relationship_type,
            "target": target
        }

        if relationship not in self.relationships:

            self.relationships.append(relationship)

    def map_user_group_relationships(self):

        users = self.data.get("users", [])

        groups = self.data.get("groups", [])

        group_lookup = {
            group["name"].lower(): group
            for group in groups
        }

        for user in users:

            username = user.get("username", "")

            for group_name in user.get("groups", []):

                group = group_lookup.get(
                    group_name.lower()
                )

                if group:

                    self.add_relationship(
                        username,
                        "MEMBER_OF",
                        group["name"]
                    )

        return self.relationships

    def map_group_member_relationships(self):

        groups = self.data.get("groups", [])

        for group in groups:

            group_name = group.get("name", "")

            for member in group.get("members", []):

                self.add_relationship(
                    member,
                    "MEMBER_OF",
                    group_name
                )

        return self.relationships

    def map_computer_relationships(self):

        computers = self.data.get("computers", [])

        domain = self.data.get("domain", {})

        domain_name = domain.get("name", "")

        for computer in computers:

            computer_name = computer.get("name", "")

            if domain_name:

                self.add_relationship(
                    computer_name,
                    "BELONGS_TO_DOMAIN",
                    domain_name
                )

        return self.relationships

    def map_ou_relationships(self):

        ous = self.data.get("organizational_units", [])

        for ou in ous:

            ou_name = ou.get("name", "")

            distinguished_name = ou.get(
                "distinguished_name", ""
            )

            if distinguished_name:

                self.add_relationship(
                    ou_name,
                    "HAS_DISTINGUISHED_NAME",
                    distinguished_name
                )

        return self.relationships

    def build_relationships(self):

        self.relationships = []

        self.map_user_group_relationships()

        self.map_group_member_relationships()

        self.map_computer_relationships()

        self.map_ou_relationships()

        return self.relationships

    def get_relationships_for_object(self, object_name):

        object_name = object_name.lower()

        return [
            relationship
            for relationship in self.relationships
            if relationship["source"].lower() == object_name
            or relationship["target"].lower() == object_name
        ]

    def get_relationship_summary(self):

        summary = {}

        for relationship in self.relationships:

            relationship_type = relationship["relationship"]

            summary[relationship_type] = (
                summary.get(relationship_type, 0) + 1
            )

        return summary