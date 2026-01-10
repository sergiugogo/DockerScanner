import subprocess
import sys
import os

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def run_command(command):
    """
    Rulează o comandă în terminal și returnează codul de eroare (0 = succes).
    """
    try:
        result = subprocess.run(command, shell=True, check=True)
        return result.returncode
    except subprocess.CalledProcessError:
        return 1

def main():
    if len(sys.argv) < 2:
        print(f"{Colors.WARNING}Utilizare: python full_scan.py <nume_imagine>{Colors.ENDC}")
        print(f"Exemplu: python full_scan.py nginx:latest")
        sys.exit(1)

    image_name = sys.argv[1]
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}🚀 PORNIT: Docker Full Scanner Pipeline{Colors.ENDC}")
    print(f"{Colors.HEADER}========================================{Colors.ENDC}")
    
    print(f"\n{Colors.BLUE}[1/3] Extragere SBOM și Secrete pentru '{image_name}'...{Colors.ENDC}")

    python_cmd = "python" if sys.platform == "win32" else "python3"
    
    cmd_scanner = f"{python_cmd} remote_scanner.py {image_name}"
    exit_code = run_command(cmd_scanner)
    
    if exit_code != 0:
        print(f"\n{Colors.FAIL}⛔ EROARE CRITICĂ: Extractorul a eșuat.{Colors.ENDC}")
        sys.exit(1)
        
    print(f"{Colors.GREEN}✅ Extragere completă! (inventory.json generat){Colors.ENDC}")

    print(f"\n{Colors.BLUE}[2/3] Analiză Vulnerabilități și Generare Raport...{Colors.ENDC}")
    
    cmd_matcher = f"{python_cmd} vuln_matcher.py"
    exit_code = run_command(cmd_matcher)
    
    if exit_code != 0:
        print(f"\n{Colors.FAIL}⛔ EROARE: Au fost găsite probleme de securitate sau erori de execuție.{Colors.ENDC}")
        # Dar într-un CI/CD, aici am da sys.exit(1)
    else:
        print(f"{Colors.GREEN}✅ Analiză completă!{Colors.ENDC}")

    print(f"\n{Colors.HEADER}========================================{Colors.ENDC}")
    if os.path.exists("security_report.pdf"):
        print(f"{Colors.BOLD}📊 Raportul tău este gata: security_report.pdf{Colors.ENDC}")
        if sys.platform == "win32":
            os.startfile("security_report.pdf")
    else:
        print(f"{Colors.WARNING}⚠️  Nu am găsit raportul PDF.{Colors.ENDC}")

if __name__ == "__main__":
    main()