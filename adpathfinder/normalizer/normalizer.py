from datetime import datetime


class DataNormalizer:
    """
    Normalizes Active Directory data into a consistent format.
    """

    @staticmethod
    def normalize_domain(domain):

        return {
            "object_type": "domain",
            "name": domain.get("domain_name", ""),
            "netbios_name": domain.get("domain_netbios", ""),
            "domain_controller": domain.get("domain_controller", ""),
            "sid": domain.get("domain_sid", ""),
            "domain_mode": domain.get("domain_mode", ""),
            "forest_name": domain.get("forest_name", ""),
            "password_policy": domain.get(
                "password_policy",
                {}
            ),
            "collected_at": datetime.now().isoformat()
        }

    @staticmethod
    def normalize_user(user):

        return {
            "object_type": "user",
            "name": user.get("name", ""),
            "username": user.get("username", ""),
            "enabled": bool(user.get("enabled", False)),
            "department": user.get("department", ""),
            "password_never_expires": bool(
                user.get("password_never_expires", False)
            ),
            "password_not_required": bool(
                user.get("password_not_required", False)
            ),
            "groups": user.get("groups", []),
            "collected_at": datetime.now().isoformat()
        }

    @staticmethod
    def normalize_group(group):

        return {
            "object_type": "group",
            "name": group.get("name", ""),
            "scope": group.get("scope", ""),
            "category": group.get("category", ""),
            "members": group.get("members", []),
            "collected_at": datetime.now().isoformat()
        }

    @staticmethod
    def normalize_computer(computer):

        return {
            "object_type": "computer",
            "name": computer.get("name", ""),
            "operating_system": computer.get(
                "operating_system", ""
            ),
            "enabled": bool(computer.get("enabled", False)),
            "ip_address": computer.get("ip_address", ""),
            "role": computer.get("role", ""),
            "collected_at": datetime.now().isoformat()
        }

    @staticmethod
    def normalize_ou(ou):

        return {
            "object_type": "organizational_unit",
            "name": ou.get("name", ""),
            "distinguished_name": ou.get(
                "distinguished_name", ""
            ),
            "collected_at": datetime.now().isoformat()
        }

    def normalize_all(self, collected_data):

        normalized_data = {
            "domain": self.normalize_domain(
                collected_data["domain"]
            ),

            "users": [
                self.normalize_user(user)
                for user in collected_data["users"]
            ],

            "groups": [
                self.normalize_group(group)
                for group in collected_data["groups"]
            ],

            "computers": [
                self.normalize_computer(computer)
                for computer in collected_data["computers"]
            ],

            "organizational_units": [
                self.normalize_ou(ou)
                for ou in collected_data["organizational_units"]
            ]
        }

        return normalized_data