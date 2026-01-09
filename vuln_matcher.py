import json
import sys
import requests
import os

OSV_API_URL = "https://api.osv.dev/v1/query"

def load_inventory(filepath="inventory.json"):
    """Loads the packages from the inventory"""
    if not os.path.exists(filepath):
        print(f"Error: {filepath} does not exist")
        sys.exit(1)
    with open(filepath, "r")  as f:
        return json.load(f)
    
def check_vulnerabilities(packageName, version):
    """Checks the OSV API for vulnerabilities"""
    payload = {
        "version" : version,
        "package":{
            "name" : packageName,
            "ecosystem" : "Alpine"
        }
    }

    try: 
        r = requests.post(OSV_API_URL, json=payload)
        data = r.json()
        return data.get("vulns", [])
    except Exception as e:
        print(f"Network error for {packageName}:{e}")
        return []
    
def main():
    inventory = load_inventory()
    print(f"Analyzing {len(inventory)} packages against OSV")
    print ("=" * 60)

    stats = {
        "checked" : 0,
        "vulnerable" : 0,
        "clean" : 0
    }

    found_vulns = []

    for item in inventory:
        pkg_name = item.get("P")
        pkg_version = item.get("V")
        if not pkg_name or not pkg_version:
            continue
        stats["checked"] += 1
        print(f"Checking {pkg_name} v{pkg_version}...", end="\r")
        vulns = check_vulnerabilities(pkg_name, pkg_version)

        if vulns:
            stats["vulnerable"] += 1
            found_vulns.append({
                "name": pkg_name,
                "version": pkg_version,
                "issues": vulns
            })
            print(f"Vulnerable: {pkg_name} v{pkg_version}", end="\r")
        else:
            stats["clean"] += 1

    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)

    if found_vulns:
        print(f"Found {len(found_vulns)} packages with vulnerabilities")

        for item in found_vulns:
            print(f"Package: {item['name']} (v{item['version']})")
            for v in item['issues']:
                cve_id = v.get('id', 'N/A')
                summary = v.get('summary', 'No description available')
                print(f"    {cve_id}: {summary[:100]}...")
                print(f"      Link: https://osv.dev/vulnerability/{cve_id}")
            print("-" * 40)
    else:
        print("No vulnerabilities found")
    
    print("=" * 60)
    print(f"Checked {stats['checked']} packages")
    print(f"Vulnerable: {stats['vulnerable']} packages")
    print(f"Clean: {stats['clean']} packages")
    print("=" * 60)
    
if __name__ == "__main__":
    main()
    