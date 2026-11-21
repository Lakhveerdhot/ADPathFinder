from adpathfinder.utils.data_loader import load_json_file


class DomainCollector:
    """
    Collects Active Directory domain information.
    """

    def collect(self):

        domain_data = load_json_file("domain.json")

        return domain_data