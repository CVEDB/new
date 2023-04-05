import os
import requests
import zipfile
import datetime
import json
from github import Github

# Define the API endpoint for the CVE Services API
API_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

def get_api_key(api_key_secret_name):
    api_key = os.environ.get(api_key_secret_name)
    if api_key is None:
        raise ValueError(f"API key '{api_key_secret_name}' not found in environment variables")
    return api_key

def get_all_cves(api_key):
    response = requests.get(API_URL, headers={"API_KEY": api_key})
    if response.status_code == 200:
        all_cves = response.json()['result']['CVE_Items']
        return all_cves
    else:
        raise ValueError(f"Failed to retrieve all CVEs. Response code: {response.status_code}")
        
def get_delta_cves(api_key, start_time):
    url = f'{API_URL}?modStartDate={start_time}'
    response = requests.get(url, headers={"API_KEY": api_key})
    if response.status_code == 200:
        delta_cves = response.json()['result']['CVE_Items']
        return delta_cves
    else:
        raise ValueError(f"Failed to retrieve delta CVEs. Response code: {response.status_code}")

def create_zip_file(file_name, file_list):
    with zipfile.ZipFile(file_name, 'w', compression=zipfile.ZIP_DEFLATED) as zip_file:
        for file in file_list:
            zip_file.write(file)
    print(f'Generated {file_name} with {len(file_list)} files')

def create_cve_files(api_key, directory):
    # Get all CVEs and delta CVEs
    all_cves = get_all_cves(api_key)
    delta_cves = get_delta_cves(api_key, datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z')

    # Set the file names
    date_prefix = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    all_cves_file_name = f"{date_prefix}_all_CVEs.zip"
    delta_cves_file_name = f"{date_prefix}_delta_CVEs.zip"

    # Create the directory structure
    if not os.path.exists(directory):
        os.makedirs(directory)

    os.makedirs(f"{directory}/recent_activities")
    for year in range(1999, datetime.datetime.today().year + 1):
        os.makedirs(f"{directory}/{year}")
        for cve_id in range(1, 10000):
            os.makedirs(f"{directory}/{year}/{str(cve_id).zfill(4)}")

    # Create the all CVEs zip file
    with open(f"{directory}/recent_activities.json", 'w') as f:
        f.write(json.dumps(all_cves))
    create_zip_file(all_cves_file_name, [f"{directory}/recent_activities.json"])
    os.remove(f"{directory}/recent_activities.json")
    
    # Create the delta CVEs zip file
    with open(f"{directory}/{date_prefix}_delta_CVEs.json", 'w') as f:
        f.write(json
