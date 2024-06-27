import requests
import json
from dotenv import load_dotenv
import os
import re

# Load the environment variables from the .env file
load_dotenv()

# Get the API key and secret from environment variables
ENDOR_NAMESPACE = os.getenv("ENDOR_NAMESPACE")
API_URL = 'https://api.endorlabs.com/v1'

def get_token():
    api_key = os.getenv("API_KEY")
    api_secret = os.getenv("API_SECRET")
    url = f"{API_URL}/auth/api-key"
    payload = {
        "key": api_key,
        "secret": api_secret
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        token = response.json().get('token')
        return token
    else:
        raise Exception(f"Failed to get token: {response.status_code}, {response.text}")

API_TOKEN = get_token()
HEADERS = {
    "User-Agent": "curl/7.68.0",
    "Accept": "*/*",
    "Authorization": f"Bearer {API_TOKEN}"
}

def sanitize_filename(filename):
    # Remove any character that is not a letter, number, underscore, or hyphen
    return re.sub(r'[^\w\-_\.]', '_', filename)

def get_projects():
    url = f"{API_URL}/namespaces/{ENDOR_NAMESPACE}/projects"
    # Make the request to get all projects
    response = requests.get(url, headers=HEADERS, timeout=10)

    if response.status_code != 200:
        print(f"Failed to get projects, Status Code: {response.status_code}, Response: {response.text}")
        exit()

    projects = response.json().get('list', {}).get('objects', [])

    # Extract project UUIDs
    project_uuids = [project['uuid'] for project in projects]
    return project_uuids

def get_package_uuids_and_names(project_uuid):
    url_package_versions = f'{API_URL}/namespaces/{ENDOR_NAMESPACE}/package-versions'
    params = {
        'list_parameters.filter': f'spec.project_uuid=={project_uuid}'
    }
    response = requests.get(url_package_versions, headers=HEADERS, params=params, timeout=10)
    package_versions = response.json().get('list', {}).get('objects', [])
    return [(package['uuid'], package['meta']['name']) for package in package_versions]

def create_sbom(package_uuid, package_name, success_counter, failure_counter):
    url_export_sbom = f'{API_URL}/namespaces/{ENDOR_NAMESPACE}/sbom-export'
    payload = {
        "meta": {
            "parent_kind": "PackageVersion",
            "parent_uuid": package_uuid,
            "name": f"SBOM for package UUID: {package_uuid}"
        },
        "spec": {
            "component_type": "COMPONENT_TYPE_APPLICATION",
            "format": "FORMAT_JSON",
            "kind": "SBOM_KIND_CYCLONEDX"
        }
    }
    try:
        response = requests.post(url_export_sbom, headers=HEADERS, data=json.dumps(payload), timeout=30)
        if response.status_code == 200:
            sbom_data = response.json()
            # Sanitize the package name for use as a filename
            sanitized_name = sanitize_filename(package_name)
            # Ensure the directory exists
            os.makedirs('sboms_exported', exist_ok=True)
            # Save the SBOM data to a file in the sboms_exported directory
            filename = f'sboms_exported/sbom_{sanitized_name}.json'
            with open(filename, 'w') as f:
                print(f"Creating SBOM for package {package_name} (UUID: {package_uuid})")
                f.write(sbom_data['spec']['data'])
            success_counter += 1
        else:
            print(f"Failed to create SBOM for package {package_name} (UUID: {package_uuid}), Status Code: {response.status_code}, Response: {response.text}")
            failure_counter += 1
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        failure_counter += 1
    return success_counter, failure_counter

def main():
    project_uuids = get_projects()
    total_sboms = 0
    success_counter = 0
    failure_counter = 0

    for project_uuid in project_uuids:
        packages = get_package_uuids_and_names(project_uuid)
        total_sboms += len(packages)
        for package_uuid, package_name in packages:
            success_counter, failure_counter = create_sbom(package_uuid, package_name, success_counter, failure_counter)

    print(f"SBOM creation complete. Produced: {success_counter}, Failed: {failure_counter}, Total: {total_sboms}")

if __name__ == '__main__':
    main()
    