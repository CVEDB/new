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

    # Create the all CVEs zip file
    with open(f"{directory}/{date_prefix}_all_CVEs.json", 'w') as f:
        f.write(json.dumps(all_cves))
    create_zip_file(all_cves_file_name, [f"{directory}/{date_prefix}_all_CVEs.json"])
    os.remove(f"{directory}/{date_prefix}_all_CVEs.json")
    
    # Create the delta CVEs zip file
    with open(f"{directory}/{date_prefix}_delta_CVEs.json", 'w') as f:
        f.write(json.dumps(delta_cves))
    create_zip_file(delta_cves_file_name, [f"{directory}/{date_prefix}_delta_CVEs.json"])
    os.remove(f"{directory}/{date_prefix}_delta_CVEs.json")
    
    # Create the release notes file
    release_notes_file_name = f"{date_prefix}_Release_Notes.txt"
    with open(release_notes_file_name, 'w') as f:
        f.write("Release Notes for CVE List")
    create_zip_file(release_notes_file_name, [release_notes_file_name])
    os.remove(release_notes_file_name)

    return (all_cves_file_name, delta_cves_file_name)

def commit_cve_files_to_repo(github_token, repo_full_name, branch_name, file_names):
    g = Github(github_token)
    repo = g.get_repo(repo_full_name)
    branch = repo.get_branch(branch_name)
    commit_title = f'Update CVE release list {datetime.datetime.now().strftime("%Y-%m-%d")}'
    commit_message = 'Add new CVE release list'

    # Remove old files
    contents = repo.get_contents('')
    for content_file in contents:
        if content_file.type == 'file' and content_file.name.endswith('.zip'):
            if content_file.name not in file_names:
                print(f'Removing {content_file.name}')
                repo.delete_file(content_file.path, commit_message, content_file.sha, branch=branch_name)

    # Upload new files
    for file_name in file_names:
        with open(file_name, 'rb') as f:
            content = f.read()

        if repo.get_contents(file_name) is None:
            print(f'Adding {file_name}')
            repo.create_file(file_name, commit_message, content, branch=branch_name)
        else:
            print(f'Updating {file_name}')
            repo.update_file(file_name, commit
