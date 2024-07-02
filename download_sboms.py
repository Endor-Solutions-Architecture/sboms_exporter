import requests
import json
from dotenv import load_dotenv
import os
import re
import argparse

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
        "Content-Type": "application/json",
        "Request-Timeout": "60"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=60)
    
    if response.status_code == 200:
        token = response.json().get('token')
        return token
    else:
        raise Exception(f"Failed to get token: {response.status_code}, {response.text}")

API_TOKEN = get_token()
HEADERS = {
    "User-Agent": "curl/7.68.0",
    "Accept": "*/*",
    "Authorization": f"Bearer {API_TOKEN}",
    "Request-Timeout": "60"  # Set the request timeout to 60 seconds
}

def sanitize_filename(filename):
    # Remove any character that is not a letter, number, underscore, or hyphen
    return re.sub(r'[^\w\-_\.]', '_', filename)

def get_projects(tags=None):
    print("Fetching projects...")
   
    url = f"{API_URL}/namespaces/{ENDOR_NAMESPACE}/projects"
    
    params = {'list_parameters.mask': 'uuid'}
    if tags:
        tags_filter = " or ".join([f'meta.tags=="{tag}"' for tag in tags])
        params['list_parameters.filter'] = tags_filter
    
    project_uuids = []
    next_page_id = None

    while True:
        if next_page_id:
            params['list_parameters.page_id'] = next_page_id

        response = requests.get(url, headers=HEADERS, params=params, timeout=60)

        if response.status_code != 200:
            print(f"Failed to get projects, Status Code: {response.status_code}, Response: {response.text}")
            exit()

        response_data = response.json()
        projects = response_data.get('list', {}).get('objects', [])
        project_uuids.extend([project['uuid'] for project in projects])

        next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
        if not next_page_id:
            break

    print(f"Total projects fetched: {len(project_uuids)}")
    print(f"Project UUIDs: {project_uuids}")
    return project_uuids

def get_package_uuids_and_names(project_uuid):
    print(f"Fetching packages for project {project_uuid}...")
    url_package_versions = f'{API_URL}/namespaces/{ENDOR_NAMESPACE}/package-versions'
    params = {
        'list_parameters.filter': f'spec.project_uuid=={project_uuid} and context.type==CONTEXT_TYPE_MAIN',
        'list_parameters.mask': 'uuid,meta.name'
    }
    packages = []
    next_page_id = None

    while True:
        if next_page_id:
            params['list_parameters.page_id'] = next_page_id

        response = requests.get(url_package_versions, headers=HEADERS, params=params, timeout=60)
        if response.status_code != 200:
            print(f"Failed to get package versions for project {project_uuid}, Status Code: {response.status_code}, Response: {response.text}")
            break

        response_data = response.json()
        package_versions = response_data.get('list', {}).get('objects', [])
        packages.extend([(package['uuid'], package['meta']['name']) for package in package_versions])

        next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
        if not next_page_id:
            break

    print(f"Total packages fetched for project {project_uuid}: {len(packages)}")
    return packages

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
        response = requests.post(url_export_sbom, headers=HEADERS, data=json.dumps(payload), timeout=60)
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
    parser = argparse.ArgumentParser(description="SBOM Exporter")
    parser.add_argument('--project_tags', type=str, help="Comma-separated list of project tags to filter by")
    args = parser.parse_args()

    tags = args.project_tags.split(',') if args.project_tags else None
    if tags:
        tags = [tag.strip() for tag in tags]

    project_uuids = get_projects(tags)
    if not project_uuids:
        print("No projects found with the specified tags.")
        return

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