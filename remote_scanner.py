import requests
import tarfile
import io
import gzip
import sys
import os 
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
load_dotenv()

#This is where the docker hub token will go
DOCKER_USER = os.getenv("DOCKER_USER")
DOCKER_PAT = os.getenv("DOCKER_PASSWORD")
TARGET_IMAGE = "alpine"

REGISTRY_URL = "https://registry-1.docker.io/v2"
AUTH_URL = "https://auth.docker.io/token"

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

def get_manifest(imageName, token):
    #This function helps by returning a json containing the list of all layers of the image from OS to the latest added file
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
    }

    url = f"{REGISTRY_URL}/library/{imageName}/manifests/latest"
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
    headers = {
        "Authorization" : f"Bearer {token}"}
    url = f"{REGISTRY_URL}/library/{imageName}/blobs/{layerDigest}"

    with requests.get(url, headers = headers, stream= True) as r:
        try:
            with gzip.GzipFile(fileobj = r.raw) as gzfile:
                with tarfile.open(fileobj = gzfile, mode = 'r|*') as tar:
                    for member in tar:
                        if member.name == "lib/apk/db/installed":
                            print(f"Found apk installed file in layer {layerDigest[:12]}")
                            f = tar.extractfile(member)
                            return f.read().decode('utf-8')
        except gzip.BadGzipFile:
            pass
        except tarfile.ReadError as e:
            print(f"Warning: Failed to read layer {layerDigest[:12]}: {e}")
        except requests.RequestException as e:
            print(f"Error: Network error for layer {layerDigest[:12]}: {e}")

    return None


def parse_apk(content):
    packages = []
    current = {}
    for line in content.splitlines():
        line = line.strip()
        if not line:
            if 'P' in current: packages.append(current)
            current = {}
            continue
        if len(line) > 2 and line[1] == ':':
            current[line[0]] = line[2:]
    if 'P' in current: packages.append(current)
    return packages

def main():
    print(f"Authenticating as user: {DOCKER_USER}")
    token = get_auth_token(TARGET_IMAGE)
    print(f"Authenticated successfully")

    print("Fetching manifest...")
    manifest = get_manifest(TARGET_IMAGE, token)

    if 'layers' not in manifest:
        print("Error: Failed to read the layers. Image might be of a different format")
        sys.exit(1)

    layers = manifest['layers']
    print(f"Found {len(layers)} layers")

    inventory = []
    for layer in reversed(layers):
        digest = layer['digest']
        print(f" > Stream layer {digest[:12]}.. ", end = "", flush = True)

        content = scan_layer_stream(digest,token,TARGET_IMAGE)
        if content:
            inventory.extend(parse_apk(content))
            break
        else:
            print("Content is empty")

    if inventory:
        print(f"Found {len(inventory)} packages.")
        import json
        with open("inventory.json", "w") as f:
            json.dump(inventory, f, indent = 2)
        print("Inventory saved to inventory.json")
    else:
        print("Failed to save the inventory.")

if __name__ == "__main__":
    main()