import os
import time
import zipfile
import datetime
import json
from github import Github

# Define the base URL for the NVD data feeds
NVD_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1/'

def retrieve_cve_data(file_name, url):
    response = requests.get(url)
    with open(file_name, 'wb') as f:
        f.write(response.content)

def create_zip_file(file_name, file_list):
    with zipfile.ZipFile(file_name, 'w', compression=zipfile.ZIP_DEFLATED) as zip_file:
        for file in file_list:
            zip_file.write(file)
    print(f'Generated {file_name} with {len(file_list)} files')

def create_cve_files(directory):
    # Set the date prefix
    date_prefix = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    
    # Retrieve the data feed files
    cve_feed_meta_file_name = f"{date_prefix}_cve_feed_meta.json"
    cve_modified_file_name = f"{date_prefix}_modified.json"
    cve_recent_file_name = f"{date_prefix}_recent.json"
    retrieve_cve_data(cve_feed_meta_file_name, f"{NVD_BASE_URL}nvdcve-1.1-%%d.meta")
    retrieve_cve_data(cve_modified_file_name, f"{NVD_BASE_URL}nvdcve-1.1-modified.json.gz")
    retrieve_cve_data(cve_recent_file_name, f"{NVD_BASE_URL}nvdcve-1.1-recent.json.gz")
    
    # Create the recent activities directory
    os.makedirs(f"{directory}/recent_activities")
    with open(f"{directory}/recent_activities/{cve_recent_file_name}", 'wb') as f:
        with open(cve_recent_file_name, 'rb') as cve_file:
            f.write(cve_file.read())
    os.remove(cve_recent_file_name)
    
    # Create the CVE files for each year and CVE ID
    for year in range(1999, datetime.datetime.today().year + 1):
        os.makedirs(f"{directory}/{year}")
        for cve_id in range(1, 10000):
            cve_id_str = str(cve_id).zfill(4)
            cve_file_name = f"{directory}/{year}/{cve_id_str}/CVE-{year}-{cve_id_str}.json"
            if os.path.exists(cve_file_name):
                continue
            retrieve_cve_data(cve_file_name, f"{NVD_BASE_URL}CVE-%d-%04d.json" % (year, cve_id))
            if os.path.getsize(cve_file_name) == 0:
                os.remove(cve_file_name)
        time.sleep(0.1)
    
    # Create the all CVEs zip file
    all_cves_file_name = f"{date_prefix}_all_CVEs.zip"
    all_cve_files = []
    for year in range(1999, datetime.datetime.today().year + 1):
        for cve_id in range(1, 10000):
            cve_id_str = str(cve_id).zfill(4)
            cve_file_name = f"{directory}/{year}/{cve_id_str}/CVE-{year}-{cve_id_str}.json"
            if os.path.exists(cve_file_name):
                all_cve_files.append(cve_file_name)
    create_zip_file(all_cves_file_name, all_cve_files)
    
    # Create the release notes file
    release_notes_file_name = f"{date_prefix}_Release_Notes.txt"
    with open(release_notes_file_name, 'w') as f:
        f.write("Release Notes for CVE List")
    create_zip_file(release_notes_file_name, [release_notes_file_name])
    os.remove(release_notes_file_name)

    return (all_cves_file_name, cve_feed_meta_file_name, cve_modified_file_name, cve_recent_file_name)

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
