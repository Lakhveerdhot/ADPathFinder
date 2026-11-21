from adpathfinder.utils.data_loader import load_json_file


class ComputerCollector:
    """
    Collects Active Directory computer information.
    """

    def collect(self):

        computers = load_json_file("computers.json")

        return computers