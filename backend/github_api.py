# backend/github_api.py
from github import Github
import requests
import yaml
from typing import Dict, List

def get_workflow_yaml(repo_url: str, github_pat: str = None) -> Dict[str, str]:
    """
    Fetch GitHub Actions workflow YAMLs for a repo.

    Args:
        repo_url (str): Full repo URL, e.g. "https://github.com/owner/repo-name"
        github_pat (str, optional): Personal Access Token if private repo.

    Returns:
        Dict[str, str]: {workflow_filename: workflow_content}
    """
    # Extract owner & repo name
    try:
        parts = repo_url.rstrip("/").split("/")
        owner, repo_name = parts[-2], parts[-1]
    except IndexError:
        raise ValueError("Invalid GitHub repo URL")

    # Initialize GitHub API
    if github_pat:
        g = Github(github_pat)
    else:
        g = Github()  # unauthenticated, only public repos

    repo = g.get_repo(f"{owner}/{repo_name}")

    # List workflow files in .github/workflows
    workflows = {}
    try:
        contents = repo.get_contents(".github/workflows")
    except:
        return {}  # No workflows found

    for file in contents:
        if file.name.endswith(".yml") or file.name.endswith(".yaml"):
            workflows[file.name] = file.decoded_content.decode("utf-8")

    return workflows

# Optional helper: validate YAML
def parse_yaml(yaml_str: str) -> Dict:
    """
    Convert YAML string to Python dict
    """
    return yaml.safe_load(yaml_str)