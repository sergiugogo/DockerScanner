# 🛡️ Docker Vuln Scanner

> **A fast, lightweight, and agentless vulnerability scanner for Docker containers.**  
> Detects OS vulnerabilities, application dependency issues, and hardcoded secrets directly from Docker Hub — **without pulling the full image**.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-compatible-blue)

## 🚀 Key Features

* **Agentless & Lightweight:** Doesn't require Docker daemon or pulling heavy images to your local disk. Streams layer data directly from the registry.
* **Polyglot Scanning:**
    * 🐧 **OS Packages:** Alpine (APK), Debian/Ubuntu (DPKG).
    * 🐍 **Python:** `requirements.txt`.
    * 📦 **Node.js:** `package.json` (npm/yarn).
    * 🐹 **Go:** `go.mod`.
    * ☕ **Java:** `pom.xml` (Maven).
* **Secret Detection:** Finds hardcoded credentials (AWS keys, SSH keys, tokens) and suspicious files (`.env`).
* **Vulnerability Database:** Powered by the [Google OSV API](https://osv.dev) for real-time CVE data.
* **Professional Reporting:** Generates a detailed **PDF Security Report** for audits.

---

## 🛠️ Architecture

The tool is split into three modular components:

1.  **Scanner (`remote_scanner.py`):** Connects to Docker Registry, streams layers, parses package managers, and extracts the SBOM (Software Bill of Materials).
2.  **Matcher (`vuln_matcher.py`):** Queries the OSV API for vulnerabilities, detects secrets, and generates the PDF report.
3.  **Orchestrator (`containerScan.py`):** A wrapper script that runs the entire pipeline in one command.

---

## 📦 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/sergiugogo/DockerScanner.git
    cd DockerScanner
    ```

2.  **Set up a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Credentials:**
    Create a `.env` file in the root directory with your Docker Hub credentials (required to scan private and public images):
    ```env
    DOCKER_USER=your_dockerhub_username
    DOCKER_PASSWORD=your_dockerhub_access_token
    ```
    *(Note: Use a Personal Access Token (PAT), not your login password.)*

---

## 🚦 Usage

Run the full pipeline with a single command:

```bash
python containerScan.py <image_name>
```

### Examples

**Scan a public image (e.g., Nginx):**
```bash
python containerScan.py nginx:latest
```

**Scan a Python app:**
```bash
python containerScan.py python:3.9-slim
```

**Scan your own private image:**
```bash
python containerScan.py myuser/my-private-app:v1
```

---

## 📊 Sample Report

After a scan completes, check the `security_report.pdf` file generated in your project folder. It includes:

* **Summary Dashboard:** Total packages, critical issues, and pass/fail status.
* **Secret Audit:** A list of detected sensitive files or regex matches.
* **Vulnerability Table:** Detailed list of CVEs with links to the OSV database.

---

## 🧪 Testing

To verify the scanner's detection capabilities, you can build a local "trap" image:

1. Create a Dockerfile with vulnerable packages and fake secrets.
2. Build and push it to your registry.
3. Run the scanner against it.

**Expected output:**
```
⚠️ SECURITY AUDIT: SECRETS DETECTED
❌ SCAN FAILED: Security issues detected!
```

---

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

---

Built with 💙 by Sergiu
