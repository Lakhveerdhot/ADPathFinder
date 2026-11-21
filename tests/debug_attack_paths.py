import json

with open(
    "data/processed/normalized_data.json",
    "r",
    encoding="utf-8"
) as file:
    data = json.load(file)


print("\nUSER OBJECTS")
print("=" * 70)

for user in data.get("users", []):
    print(json.dumps(user, indent=4))


print("\nGROUP OBJECTS")
print("=" * 70)

for group in data.get("groups", []):
    print(json.dumps(group, indent=4))