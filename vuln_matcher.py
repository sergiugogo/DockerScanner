import json
import sys
import requests
import os
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
from datetime import datetime

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
        "app_packages": data.get("app_packages", []),
        "secrets": data.get("secrets", [])
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
    
def scan_packages(packages, ecosystem, category_name, pkg_type=None):
    """Scan a list of packages for vulnerabilities.
    
    Args:
        packages: List of package dicts with 'name' and 'version' keys
        ecosystem: The ecosystem to use for OSV queries
        category_name: Display name for this category (e.g., 'OS', 'Application')
        pkg_type: Optional package type (e.g., 'python', 'npm', 'go')
    
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
        item_type = item.get("type", pkg_type)  # Use item's type or fallback to passed type
        
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
                "pkg_type": item_type,
                "issues": vulns
            })
            print(f"  VULNERABLE: {pkg_name} v{pkg_version}")
        else:
            stats["clean"] += 1
    
    return stats, found_vulns


def print_vulnerabilities(vulns, category_name, pkg_type=None):
    """Print vulnerability details for a category.
    
    Args:
        vulns: List of vulnerability findings
        category_name: Category to filter by ('OS' or 'Application')
        pkg_type: Optional package type to filter by ('python', 'npm', 'go')
    """
    if pkg_type:
        category_vulns = [v for v in vulns if v["category"] == category_name and v.get("pkg_type") == pkg_type]
    else:
        category_vulns = [v for v in vulns if v["category"] == category_name]
    
    if not category_vulns:
        return 0
    
    print(f"  Found {len(category_vulns)} vulnerable packages:")
    for item in category_vulns:
        print(f"\n  Package: {item['name']} (v{item['version']})")
        for v in item['issues']:
            cve_id = v.get('id', 'N/A')
            summary = v.get('summary', 'No description available')
            print(f"    - {cve_id}: {summary[:80]}...")
            print(f"      Link: https://osv.dev/vulnerability/{cve_id}")
    
    return len(category_vulns)


def main():
    inventory = load_inventory()
    
    os_ecosystem = inventory["os"]
    os_packages = inventory["os_packages"]
    app_packages = inventory["app_packages"]
    secrets = inventory["secrets"]
    
    # Track if we should exit with failure
    has_security_issues = False
    
    print("=" * 60)
    print("Docker Image Vulnerability Scanner")
    print("=" * 60)
    
    # === SECRETS AUDIT (CRITICAL - SHOW FIRST) ===
    if secrets:
        has_security_issues = True
        print("\n" + "!" * 60)
        print("!!! SECURITY AUDIT: SECRETS DETECTED !!!")
        print("!" * 60)
        print(f"\n⚠️  Found {len(secrets)} potential secret(s) in the image:\n")
        
        for secret in secrets:
            print(f"  File: {secret['file']}")
            print(f"  Issue: {secret['issue']}")
            print()
        
        print("!" * 60)
        print("ACTION REQUIRED: Remove secrets before deploying!")
        print("!" * 60)
    
    print("\n" + "=" * 60)
    print("VULNERABILITY SCAN")
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
    
    # Initialize report data for HTML generation (stats will be updated after scanning)
    report_data = {
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "total_scanned": 0,
            "secrets": len(secrets),
            "vulnerable_pkgs": 0,
            "clean": True
        },
        "secrets": secrets,
        "vulnerabilities": {
            "OS Packages": [],
            "Application Packages": []
        }
    }
    
    if secrets:
        report_data["stats"]["clean"] = False
    
    # --- OS Package Scanning ---
    if os_packages and os_ecosystem:
        print("\n--- OS Package Scanning ---")
        print(f"Using ecosystem: {os_ecosystem}")
        print("-" * 40)
        
        os_stats, os_vulns = scan_packages(os_packages, os_ecosystem, "OS")
        all_vulns.extend(os_vulns)
        
        # Add OS vulnerabilities to report data
        for vuln in os_vulns:
            report_data["vulnerabilities"]["OS Packages"].append(vuln)
        
        for key in total_stats:
            total_stats[key] += os_stats[key]
        
        print(f"\nOS Scan Complete: {os_stats['checked']} checked, {os_stats['vulnerable']} vulnerable")
    elif not os_ecosystem:
        print("\n--- OS Package Scanning ---")
        print("Skipped: No OS detected")
    
    # --- Application Package Scanning ---
    if app_packages:
        print("\n--- Application Package Scanning ---")
        print("-" * 40)
        
        # Group packages by type for correct ecosystem mapping
        # OSV ecosystem names: PyPI for Python, npm for Node.js, Go for Go, Maven for Java
        ecosystem_map = {
            'python': 'PyPI',
            'npm': 'npm',
            'go': 'Go',
            'maven': 'Maven'
        }
        
        # Group packages by their type
        packages_by_type = {}
        for pkg in app_packages:
            pkg_type = pkg.get('type', 'unknown')
            if pkg_type not in packages_by_type:
                packages_by_type[pkg_type] = []
            packages_by_type[pkg_type].append(pkg)
        
        # Scan each group with its correct ecosystem
        for pkg_type, pkgs in packages_by_type.items():
            ecosystem = ecosystem_map.get(pkg_type, pkg_type)
            print(f"\n  [{pkg_type.upper()}] Scanning {len(pkgs)} packages (ecosystem: {ecosystem})")
            
            app_stats, app_vulns = scan_packages(pkgs, ecosystem, "Application", pkg_type)
            all_vulns.extend(app_vulns)
            
            # Add App vulnerabilities to report data
            for vuln in app_vulns:
                report_data["vulnerabilities"]["Application Packages"].append(vuln)
            
            for key in total_stats:
                total_stats[key] += app_stats[key]
        
        print(f"\nApp Scan Complete: {total_stats['checked'] - (os_stats['checked'] if os_packages and os_ecosystem else 0)} app packages checked")
    else:
        print("\n--- Application Package Scanning ---")
        print("Skipped: No application packages found")
    
    # --- Final Report ---
    print("\n" + "=" * 60)
    print("VULNERABILITY REPORT")
    print("=" * 60)
    
    if all_vulns:
        # Print OS Vulnerabilities
        print("\n[OS Vulnerabilities]")
        os_count = print_vulnerabilities(all_vulns, "OS")
        if os_count == 0:
            print("  No OS vulnerabilities found.")
        
        # Print Application Vulnerabilities grouped by language
        print("\n[Application Vulnerabilities]")
        
        # Language display names
        language_names = {
            'python': 'Python',
            'npm': 'Node.js', 
            'go': 'Go',
            'maven': 'Java/Maven'
        }
        
        app_total = 0
        for pkg_type, display_name in language_names.items():
            type_vulns = [v for v in all_vulns if v["category"] == "Application" and v.get("pkg_type") == pkg_type]
            if type_vulns:
                print(f"\n  --- {display_name} Vulnerabilities ---")
                count = print_vulnerabilities(all_vulns, "Application", pkg_type)
                app_total += count
        
        if app_total == 0:
            print("  No application vulnerabilities found.")
    else:
        print("\nNo vulnerabilities found in any packages!")
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Secrets found: {len(secrets)}")
    print(f"Total packages checked: {total_stats['checked']}")
    print(f"Vulnerable packages: {total_stats['vulnerable']}")
    print(f"Clean packages: {total_stats['clean']}")
    print("=" * 60)
    # Update report stats
    report_data["stats"]["total_scanned"] = total_stats["checked"]
    report_data["stats"]["vulnerable_pkgs"] = total_stats["vulnerable"]
    if total_stats["vulnerable"] > 0:
        report_data["stats"]["clean"] = False
    
    # Generate PDF Report
    try:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('report_template.html')
        source_html = template.render(**report_data)
        
        with open('security_report.pdf', 'w+b') as output_file:
            pisa_status = pisa.CreatePDF(source_html, dest=output_file)
            
            if pisa_status.err == 0:
                print("\n📄 PDF Report generated: security_report.pdf")
            else:
                print(f"\n⚠️  Warning: PDF generation completed with errors")
    except Exception as e:
        print(f"\n⚠️  Warning: Could not generate PDF report: {e}")
    
    # Exit with failure code if secrets or vulnerabilities found
    if has_security_issues or total_stats['vulnerable'] > 0:
        print("\n❌ SCAN FAILED: Security issues detected!")
        sys.exit(1)
    else:
        print("\n✅ SCAN PASSED: No critical security issues found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
