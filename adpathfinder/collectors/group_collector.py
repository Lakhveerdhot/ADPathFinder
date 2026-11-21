from adpathfinder.utils.data_loader import load_json_file


class GroupCollector:
    """
    Collects Active Directory group information.
    """

    def collect(self):

        groups = load_json_file("groups.json")

        return groups