from adpathfinder.utils.data_loader import load_json_file


class OUCollector:
    """
    Collects Active Directory Organizational Unit information.
    """

    def collect(self):

        organizational_units = load_json_file("ous.json")

        return organizational_units