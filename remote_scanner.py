import requests
import tarfile
import io
import gzip
import sys
import os
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
TARGET_FILES = {
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
    """Scan a layer for package database files.
    
    Returns:
        tuple: (content, os_type) if a package file is found, (None, None) otherwise
    """
    headers = {
        "Authorization" : f"Bearer {token}"}
    url = f"{REGISTRY_URL}/library/{imageName}/blobs/{layerDigest}"

    with requests.get(url, headers = headers, stream= True) as r:
        try:
            with gzip.GzipFile(fileobj = r.raw) as gzfile:
                with tarfile.open(fileobj = gzfile, mode = 'r|*') as tar:
                    for member in tar:
                        cleanName = member.name.lstrip('./')
                        # Check if this file matches any of our target paths
                        if cleanName in TARGET_FILES:
                            os_type = TARGET_FILES[cleanName]
                            print(f"Found {os_type} package file in layer {layerDigest[:12]}")
                            f = tar.extractfile(member)
                            return f.read().decode('utf-8'), os_type
        except gzip.BadGzipFile:
            pass
        except tarfile.ReadError as e:
            print(f"Warning: Failed to read layer {layerDigest[:12]}: {e}")
        except requests.RequestException as e:
            print(f"Error: Network error for layer {layerDigest[:12]}: {e}")

    return None, None


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

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Scan Docker images for installed packages (Alpine/Debian/Ubuntu)"
    )
    parser.add_argument(
        "image_input",
        help="Docker image to scan (e.g., alpine:3.10, nginx:latest, ubuntu:22.04)"
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

    inventory = []
    detected_os = None
    
    for layer in reversed(layers):
        digest = layer['digest']
        print(f" > Stream layer {digest[:12]}.. ", end="", flush=True)

        content, os_type = scan_layer_stream(digest, token, image_name)
        if content:
            detected_os = os_type
            # Select the appropriate parser based on detected OS
            if os_type == "Alpine":
                inventory.extend(parse_apk(content))
            elif os_type == "Debian":
                inventory.extend(parse_dpkg(content))
            break
        else:
            print("Content is empty")

    if inventory and detected_os:
        print(f"Detected OS: {detected_os}")
        print(f"Found {len(inventory)} packages.")
        
        import json
        result = {
            "ecosystem": detected_os,
            "packages": inventory
        }
        with open("inventory.json", "w") as f:
            json.dump(result, f, indent=2)
        print("Inventory saved to inventory.json")
    else:
        print("Failed to save the inventory.")

if __name__ == "__main__":
    main()