from github import Github
from typing import Dict  # removed unused List
import yaml

def get_workflow_yaml(repo_url: str, github_pat: str = None) -> Dict[str, str]:
    """Fetch GitHub Actions workflow YAMLs for a repo."""
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 2:
        raise ValueError("Invalid GitHub repo URL")
    owner, repo_name = parts[-2], parts[-1]

    g = Github(github_pat) if github_pat else Github()
    repo = g.get_repo(f"{owner}/{repo_name}")

    workflows = {}
    try:
        contents = repo.get_contents(".github/workflows")
    except Exception:
        return {}

    for file in contents:
        if file.name.endswith((".yml", ".yaml")):
            workflows[file.name] = file.decoded_content.decode("utf-8")

    return workflows

def parse_yaml(yaml_str: str) -> Dict:
    """Convert YAML string to Python dict."""
    return yaml.safe_load(yaml_str)