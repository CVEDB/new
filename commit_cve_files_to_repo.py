import argparse
import os
import time
import zipfile
import datetime
import json
import requests
from github import Github

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
                repo.delete_file(content_file.path, commit_message, content_file.sha, branch=branch_name)
                print(f"Deleted old file: {content_file.name}")
    # Upload new files
    for file_name in file_names:
        file_path = os.path.join(os.getcwd(), file_name)
        with open(file_path, 'rb') as f:
            content = f.read()
        try:
            repo.get_contents(file_name, branch=branch_name)
            print('File already exists: ' + file_name)
        except Exception:
            repo.create_file(file_name, commit_title, content, branch=branch_name)
            print('File created: ' + file_name)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Commit CVE files to Github repo')
    parser.add_argument('--token', dest='github_token', help='Github personal access token', required=True)
    parser.add_argument('--repo', dest='repo_full_name', help='Github repo full name (e.g. username/repo)', required=True)
    parser.add_argument('--branch', dest='branch_name', help='Github repo branch', required=True)
    parser.add_argument('--files', dest='file_names', help='Comma-separated names of files to commit', required=True)
    args = parser.parse_args()
    commit_cve_files_to_repo(args.github_token, args.repo_full_name, args.branch_name, args.file_names.split(','))
