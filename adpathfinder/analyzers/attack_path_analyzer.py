from collections import defaultdict, deque


PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
    "group policy creator owners",
    "gg-it-admins",
    "gg-server-admins",
}


class AttackPathAnalyzer:

    def __init__(self, max_depth=10):

        self.max_depth = max_depth
        self.membership_graph = defaultdict(list)
        self.attack_paths = []


    @staticmethod
    def normalize_name(name):

        return str(name).strip().lower()


    @staticmethod
    def get_member_name(member):

        if isinstance(member, dict):

            return (
                member.get("username")
                or member.get("sam_account_name")
                or member.get("name")
                or member.get("distinguished_name")
                or ""
            )

        return str(member)


    def build_graph(self, groups):

        self.membership_graph = defaultdict(list)

        for group in groups:

            group_name = group.get("name", "")

            members = group.get("members", [])

            normalized_group = self.normalize_name(group_name)

            for member in members:

                member_name = self.get_member_name(member)

                normalized_member = self.normalize_name(member_name)

                if not normalized_member:
                    continue

                self.membership_graph[
                    normalized_member
                ].append(normalized_group)


    def find_privileged_paths(self, users, groups):

        self.attack_paths = []

        self.build_graph(groups)

        privileged_groups = {
            self.normalize_name(group.get("name", ""))

            for group in groups

            if self.normalize_name(group.get("name", ""))
            in PRIVILEGED_GROUPS
        }


        for user in users:

            display_name = user.get("name", "")

            username = user.get("username") or display_name

            if not username:
                continue


            start_node = self.normalize_name(username)

            queue = deque([
                (start_node, [start_node], 0)
            ])

            visited = set()


            while queue:

                current_node, current_path, depth = queue.popleft()

                if depth >= self.max_depth:
                    continue

                if current_node in visited:
                    continue

                visited.add(current_node)


                parent_groups = self.membership_graph.get(
                    current_node,
                    []
                )


                for group in parent_groups:

                    new_path = current_path + [group]


                    # Found a privileged destination
                    if group in privileged_groups:

                        path_exists = any(
                            existing["source_username"]
                            == username

                            and existing["target_group"]
                            == group

                            and existing["path"]
                            == new_path

                            for existing in self.attack_paths
                        )


                        if not path_exists:

                            self.attack_paths.append({

                                "source_user": display_name,

                                "source_username": username,

                                "target_group": group,

                                "path": new_path,

                                "path_length": len(new_path) - 1,

                                "risk": "High",

                                "description": (
                                    f"User '{display_name}' "
                                    f"({username}) has a membership "
                                    f"path to privileged group "
                                    f"'{group}'."
                                )

                            })


                    else:

                        queue.append(
                            (group, new_path, depth + 1)
                        )


        return self.attack_paths


    def get_summary(self):

        return {

            "total_attack_paths": len(
                self.attack_paths
            ),

            "high_risk_paths": sum(

                1

                for path in self.attack_paths

                if path.get("risk") == "High"

            ),

        }