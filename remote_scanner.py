import requests
import tarfile
import io
import gzip
import sys
import os 
from requests.auth import HTTPBasicAuth

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

