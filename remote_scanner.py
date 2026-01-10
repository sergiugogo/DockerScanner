import requests
import tarfile
import io
import gzip
import sys
import os
import re
import argparse
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
load_dotenv()

#This is where the docker hub token will go
DOCKER_USER = os.getenv("DOCKER_USER")
DOCKER_PAT = os.getenv("DOCKER_PASSWORD")

REGISTRY_URL = "https://registry-1.docker.io/v2"
AUTH_URL = "https://auth.docker.io/token"

# Mapping of file paths to OS types for package detection
OS_PACKAGE_FILES = {
    "lib/apk/db/installed": "Alpine",
    "var/lib/dpkg/status": "Debian"
}


def parse_image_reference(image_ref):
    """Parse image:tag into (image_name, tag)"""
    if ':' in image_ref:
        name, tag = image_ref.split(':', 1)
    else:
        name, tag = image_ref, 'latest'
    return name, tag

def get_auth_token(imageName):
    #All this function does is to basically authenticate in docker hub so we can read images freely
    service = "registry.docker.io"
    scope = f"repository:library/{imageName}:pull"

    params = {'service' : service, 'scope' : scope}

    #This is the actual request with the user and password
    r = requests.get(AUTH_URL, params = params, auth = HTTPBasicAuth(DOCKER_USER, DOCKER_PAT))

    if r.status_code != 200:
        raise Exception(f"Failed to get auth token: {r.text}")
        print(f"Failed to authenticate: {r.status_code}")
        sys.exit(1)
    return r.json()['token']

def get_manifest(imageName, tag, token):
    #This function helps by returning a json containing the list of all layers of the image from OS to the latest added file
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
    }

    url = f"{REGISTRY_URL}/library/{imageName}/manifests/{tag}"
    r = requests.get(url, headers=headers)
    manifest = r.json()

    # Check if this is a manifest list (multi-platform image) - Docker or OCI format
    media_type = manifest.get('mediaType', '')
    if media_type in ['application/vnd.docker.distribution.manifest.list.v2+json', 
                       'application/vnd.oci.image.index.v1+json']:
        print("Detected multi-platform image, fetching linux/amd64 manifest...")
        # Find the amd64 linux manifest
        for m in manifest.get('manifests', []):
            platform = m.get('platform', {})
            if platform.get('architecture') == 'amd64' and platform.get('os') == 'linux':
                # Fetch the actual manifest using the digest
                digest = m['digest']
                headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
                url = f"{REGISTRY_URL}/library/{imageName}/manifests/{digest}"
                r = requests.get(url, headers=headers)
                return r.json()
        print("Warning: Could not find linux/amd64 platform, using first available")
        if manifest.get('manifests'):
            digest = manifest['manifests'][0]['digest']
            headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
            url = f"{REGISTRY_URL}/library/{imageName}/manifests/{digest}"
            r = requests.get(url, headers=headers)
            return r.json()

    return manifest

def scan_layer_stream(layerDigest, token, imageName):
    """Scan a layer for package database files and application dependency files.
    
    Returns:
        list: List of tuples (content, file_type, metadata)
              file_type is 'os' or 'app'
              metadata contains os_type for OS files, or app_type for app files
    """
    findings = []
    headers = {
        "Authorization": f"Bearer {token}"}
    url = f"{REGISTRY_URL}/library/{imageName}/blobs/{layerDigest}"

    with requests.get(url, headers=headers, stream=True) as r:
        try:
            with gzip.GzipFile(fileobj=r.raw) as gzfile:
                with tarfile.open(fileobj=gzfile, mode='r|*') as tar:
                    for member in tar:
                        if not member.isfile():
                            continue
                        
                        cleanName = member.name.lstrip('./')
                        
                        # Check for OS package database files
                        if cleanName in OS_PACKAGE_FILES:
                            os_type = OS_PACKAGE_FILES[cleanName]
                            print(f"\n   Found {os_type} package DB")
                            f = tar.extractfile(member)
                            content = f.read().decode('utf-8')
                            findings.append((content, 'os', os_type))
                        
                        # Check for Python requirements.txt
                        elif cleanName.endswith('requirements.txt'):
                            print(f"\n   Found requirements.txt: {cleanName}")
                            f = tar.extractfile(member)
                            content = f.read().decode('utf-8')
                            findings.append((content, 'app', 'python'))
                            
        except gzip.BadGzipFile:
            pass
        except tarfile.ReadError as e:
            print(f"Warning: Failed to read layer {layerDigest[:12]}: {e}")
        except requests.RequestException as e:
            print(f"Error: Network error for layer {layerDigest[:12]}: {e}")

    return findings


def parse_apk(content):
    """Parse Alpine APK installed database.
    
    Returns:
        list: List of dicts with 'name' and 'version' keys
    """
    packages = []
    current = {}
    for line in content.splitlines():
        line = line.strip()
        if not line:
            if 'P' in current and 'V' in current:
                packages.append({
                    'name': current['P'],
                    'version': current['V']
                })
            current = {}
            continue
        if len(line) > 2 and line[1] == ':':
            current[line[0]] = line[2:]
    if 'P' in current and 'V' in current:
        packages.append({
            'name': current['P'],
            'version': current['V']
        })
    return packages


def parse_dpkg(content):
    """Parse Debian/Ubuntu dpkg status file.
    
    Returns:
        list: List of dicts with 'name' and 'version' keys
    """
    packages = []
    current = {}
    
    for line in content.splitlines():
        if not line.strip():
            # Empty line marks end of a block
            if 'name' in current and 'version' in current:
                packages.append(current)
            current = {}
            continue
        
        if line.startswith("Package: "):
            current['name'] = line[9:].strip()
        elif line.startswith("Version: "):
            current['version'] = line[9:].strip()
    
    # Don't forget the last block if file doesn't end with empty line
    if 'name' in current and 'version' in current:
        packages.append(current)
    
    return packages


def parse_requirements(content):
    """Parse Python requirements.txt file.
    
    Handles formats like:
        flask==2.0.1
        requests>=2.25.0
        numpy
        # comments
        -e git+https://...
    
    Returns:
        list: List of dicts with 'name', 'version', and 'type' keys
    """
    packages = []
    # Regex to match package specs: name followed by optional version specifier
    # Matches: flask==2.0.1, requests>=2.25, numpy, django<4.0, etc.
    pattern = re.compile(r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)?\s*([a-zA-Z0-9._-]+)?')
    
    for line in content.splitlines():
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Skip editable installs, URLs, and other special formats
        if line.startswith('-') or line.startswith('git+') or '://' in line:
            continue
        
        # Remove inline comments
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # Remove environment markers (e.g., ; python_version >= "3.6")
        if ';' in line:
            line = line.split(';')[0].strip()
        
        # Remove extras (e.g., package[extra1,extra2])
        if '[' in line:
            line = re.sub(r'\[.*?\]', '', line)
        
        match = pattern.match(line)
        if match:
            name = match.group(1)
            version = match.group(3) if match.group(3) else 'unspecified'
            packages.append({
                'name': name,
                'version': version,
                'type': 'python'
            })
    
    return packages

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Scan Docker images for installed packages (Alpine/Debian/Ubuntu) and app dependencies"
    )
    parser.add_argument(
        "image_input",
        help="Docker image to scan (e.g., alpine:3.10, nginx:latest, python:3.9)"
    )
    args = parser.parse_args()

    # Parse the image reference into name and tag
    image_name, image_tag = parse_image_reference(args.image_input)

    print(f"Scanning image: {args.image_input}")
    print(f"Authenticating as user: {DOCKER_USER}")
    token = get_auth_token(image_name)
    print(f"Authenticated successfully")

    print("Fetching manifest...")
    manifest = get_manifest(image_name, image_tag, token)

    if 'layers' not in manifest:
        print("Error: Failed to read the layers. Image might be of a different format")
        sys.exit(1)

    layers = manifest['layers']
    print(f"Found {len(layers)} layers")

    # Collect packages from all layers
    os_packages = []
    app_packages = []
    detected_os = None
    
    for layer in reversed(layers):
        digest = layer['digest']
        print(f" > Scanning layer {digest[:12]}.. ", end="", flush=True)

        findings = scan_layer_stream(digest, token, image_name)
        
        if not findings:
            print("(empty)")
            continue
        
        for content, file_type, metadata in findings:
            if file_type == 'os' and not detected_os:
                # Only use the first OS package DB found (most recent layer)
                detected_os = metadata
                if metadata == "Alpine":
                    os_packages.extend(parse_apk(content))
                elif metadata == "Debian":
                    os_packages.extend(parse_dpkg(content))
            elif file_type == 'app':
                if metadata == 'python':
                    app_packages.extend(parse_requirements(content))
        
        print("")

    # Build and save the inventory
    if os_packages or app_packages:
        print(f"\n=== Scan Results ===")
        if detected_os:
            print(f"Detected OS: {detected_os}")
            print(f"OS packages found: {len(os_packages)}")
        print(f"App packages found: {len(app_packages)}")
        
        import json
        result = {
            "os": detected_os,
            "os_packages": os_packages,
            "app_packages": app_packages
        }
        with open("inventory.json", "w") as f:
            json.dump(result, f, indent=2)
        print("\nInventory saved to inventory.json")
    else:
        print("No packages found in the image.")

if __name__ == "__main__":
    main()