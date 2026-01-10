import json
import sys
import requests
import os

OSV_API_URL = "https://api.osv.dev/v1/query"

def load_inventory(filepath="inventory.json"):
    """Loads the packages from the inventory.
    
    Returns:
        dict: Contains 'os', 'os_packages', and 'app_packages' keys
    """
    if not os.path.exists(filepath):
        print(f"Error: {filepath} does not exist")
        sys.exit(1)
    with open(filepath, "r") as f:
        data = json.load(f)
    
    # Return the new structure
    return {
        "os": data.get("os"),
        "os_packages": data.get("os_packages", []),
        "app_packages": data.get("app_packages", [])
    }
    
def check_vulnerabilities(packageName, version, ecosystem):
    """Checks the OSV API for vulnerabilities.
    
    Args:
        packageName: Name of the package
        version: Version string
        ecosystem: The ecosystem (e.g., 'Debian', 'Alpine', 'PyPI')
    
    Returns:
        list: List of vulnerabilities found
    """
    payload = {
        "version": version,
        "package": {
            "name": packageName,
            "ecosystem": ecosystem
        }
    }

    try:
        r = requests.post(OSV_API_URL, json=payload)
        data = r.json()
        return data.get("vulns", [])
    except Exception as e:
        print(f"Network error for {packageName}: {e}")
        return []
    
def scan_packages(packages, ecosystem, category_name):
    """Scan a list of packages for vulnerabilities.
    
    Args:
        packages: List of package dicts with 'name' and 'version' keys
        ecosystem: The ecosystem to use for OSV queries
        category_name: Display name for this category (e.g., 'OS', 'Application')
    
    Returns:
        tuple: (stats dict, list of found vulnerabilities)
    """
    stats = {
        "checked": 0,
        "vulnerable": 0,
        "clean": 0
    }
    found_vulns = []
    
    for item in packages:
        pkg_name = item.get("name")
        pkg_version = item.get("version")
        
        if not pkg_name or not pkg_version:
            continue
        
        # Skip unspecified versions for app packages
        if pkg_version == "unspecified":
            continue
            
        stats["checked"] += 1
        print(f"  Checking {pkg_name} v{pkg_version}...", end="\r")
        
        vulns = check_vulnerabilities(pkg_name, pkg_version, ecosystem)
        
        if vulns:
            stats["vulnerable"] += 1
            found_vulns.append({
                "name": pkg_name,
                "version": pkg_version,
                "category": category_name,
                "issues": vulns
            })
            print(f"  VULNERABLE: {pkg_name} v{pkg_version}")
        else:
            stats["clean"] += 1
    
    return stats, found_vulns


def print_vulnerabilities(vulns, category_name):
    """Print vulnerability details for a category."""
    category_vulns = [v for v in vulns if v["category"] == category_name]
    
    if not category_vulns:
        print(f"  No {category_name.lower()} vulnerabilities found.")
        return
    
    print(f"  Found {len(category_vulns)} vulnerable packages:")
    for item in category_vulns:
        print(f"\n  Package: {item['name']} (v{item['version']})")
        for v in item['issues']:
            cve_id = v.get('id', 'N/A')
            summary = v.get('summary', 'No description available')
            print(f"    - {cve_id}: {summary[:80]}...")
            print(f"      Link: https://osv.dev/vulnerability/{cve_id}")


def main():
    inventory = load_inventory()
    
    os_ecosystem = inventory["os"]
    os_packages = inventory["os_packages"]
    app_packages = inventory["app_packages"]
    
    print("=" * 60)
    print("Docker Image Vulnerability Scanner")
    print("=" * 60)
    
    if os_ecosystem:
        print(f"Detected OS: {os_ecosystem}")
    print(f"OS packages to scan: {len(os_packages)}")
    print(f"App packages to scan: {len(app_packages)}")
    print("=" * 60)
    
    all_vulns = []
    total_stats = {
        "checked": 0,
        "vulnerable": 0,
        "clean": 0
    }
    
    # --- OS Package Scanning ---
    if os_packages and os_ecosystem:
        print("\n--- OS Package Scanning ---")
        print(f"Using ecosystem: {os_ecosystem}")
        print("-" * 40)
        
        os_stats, os_vulns = scan_packages(os_packages, os_ecosystem, "OS")
        all_vulns.extend(os_vulns)
        
        for key in total_stats:
            total_stats[key] += os_stats[key]
        
        print(f"\nOS Scan Complete: {os_stats['checked']} checked, {os_stats['vulnerable']} vulnerable")
    elif not os_ecosystem:
        print("\n--- OS Package Scanning ---")
        print("Skipped: No OS detected")
    
    # --- Application Package Scanning ---
    if app_packages:
        print("\n--- Application Package Scanning ---")
        print("Using ecosystem: PyPI")
        print("-" * 40)
        
        app_stats, app_vulns = scan_packages(app_packages, "PyPI", "Application")
        all_vulns.extend(app_vulns)
        
        for key in total_stats:
            total_stats[key] += app_stats[key]
        
        print(f"\nApp Scan Complete: {app_stats['checked']} checked, {app_stats['vulnerable']} vulnerable")
    else:
        print("\n--- Application Package Scanning ---")
        print("Skipped: No application packages found")
    
    # --- Final Report ---
    print("\n" + "=" * 60)
    print("VULNERABILITY REPORT")
    print("=" * 60)
    
    if all_vulns:
        print("\n[OS Vulnerabilities]")
        print_vulnerabilities(all_vulns, "OS")
        
        print("\n[Application Vulnerabilities]")
        print_vulnerabilities(all_vulns, "Application")
    else:
        print("\nNo vulnerabilities found in any packages!")
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total packages checked: {total_stats['checked']}")
    print(f"Vulnerable packages: {total_stats['vulnerable']}")
    print(f"Clean packages: {total_stats['clean']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
    