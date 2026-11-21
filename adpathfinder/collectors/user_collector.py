from adpathfinder.utils.data_loader import load_json_file


class UserCollector:
    """
    Collects Active Directory user information.
    """

    def collect(self):

        users = load_json_file("users.json")

        return users