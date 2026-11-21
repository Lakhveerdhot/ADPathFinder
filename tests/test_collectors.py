from adpathfinder.collectors.domain_collector import DomainCollector
from adpathfinder.collectors.user_collector import UserCollector
from adpathfinder.collectors.group_collector import GroupCollector
from adpathfinder.collectors.computer_collector import ComputerCollector
from adpathfinder.collectors.ou_collector import OUCollector


def main():

    print("\nADPathFinder Collector Test")
    print("=" * 35)

    # Domain
    domain = DomainCollector().collect()

    print("\n[+] Domain Information")
    print(domain)

    # Users
    users = UserCollector().collect()

    print("\n[+] Users")
    print(f"Total Users: {len(users)}")

    for user in users:

        print(f"- {user['username']}")

    # Groups
    groups = GroupCollector().collect()

    print("\n[+] Groups")
    print(f"Total Groups: {len(groups)}")

    for group in groups:

        print(f"- {group['name']}")

    # Computers
    computers = ComputerCollector().collect()

    print("\n[+] Computers")
    print(f"Total Computers: {len(computers)}")

    for computer in computers:

        print(f"- {computer['name']}")

    # Organizational Units
    ous = OUCollector().collect()

    print("\n[+] Organizational Units")
    print(f"Total OUs: {len(ous)}")

    for ou in ous:

        print(f"- {ou['name']}")

    print("\nCollector test completed successfully.")


if __name__ == "__main__":

    main()