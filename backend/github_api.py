# backend/github_api.py
"""
GitHub Workflow Fetcher

Fetches GitHub Actions workflow YAML files from a repository using PyGitHub.
Supports both public and private repos via optional PAT.
"""

import logging
from typing import Dict, Optional

from github import Github, GithubException
import yaml

logger = logging.getLogger(__name__)


def get_workflow_yaml(repo_url: str, github_pat: Optional[str] = None) -> Dict[str, str]:
    """
    Fetch all GitHub Actions workflow YAML files from a repository.

    Args:
        repo_url: Full GitHub repo URL (e.g. "https://github.com/owner/repo")
        github_pat: Optional Personal Access Token for private repos or higher rate limits.

    Returns:
        Dict[str, str]: {workflow_filename: raw_yaml_content}
    """
    try:
        # Extract owner and repo name
        if not repo_url.startswith("https://github.com/"):
            raise ValueError("Invalid GitHub URL. Must start with https://github.com/")

        parts = repo_url.rstrip("/").split("/")
        if len(parts) < 5:
            raise ValueError("Invalid GitHub repo URL format")

        owner = parts[-2]
        repo_name = parts[-1]

        logger.info(f"Fetching workflows for {owner}/{repo_name}")

        # Initialize GitHub client
        if github_pat and github_pat.strip():
            g = Github(github_pat)
            logger.info("Using authenticated GitHub client (with PAT)")
        else:
            g = Github()  # unauthenticated - works for public repos
            logger.info("Using unauthenticated GitHub client")

        repo = g.get_repo(f"{owner}/{repo_name}")

        # Fetch workflow files
        workflows: Dict[str, str] = {}

        try:
            contents = repo.get_contents(".github/workflows")
            for file in contents:
                if file.name.endswith((".yml", ".yaml")):
                    content = file.decoded_content.decode("utf-8")
                    workflows[file.name] = content
                    logger.info(f"Loaded workflow: {file.name}")
        except GithubException as e:
            if e.status == 404:
                logger.warning(f"No .github/workflows directory found in {owner}/{repo_name}")
                return {}
            raise

        logger.info(f"Successfully fetched {len(workflows)} workflow file(s)")
        return workflows

    except GithubException as e:
        logger.error(f"GitHub API error ({e.status}): {e.data.get('message', str(e))}")
        raise RuntimeError(f"GitHub API error: {e.data.get('message')}") from e

    except Exception as e:
        logger.error(f"Unexpected error fetching workflows from {repo_url}: {e}")
        raise RuntimeError(f"Failed to fetch workflows: {str(e)}") from e


def parse_yaml(yaml_str: str) -> Dict:
    """Safely parse YAML string into Python dict."""
    try:
        return yaml.safe_load(yaml_str) or {}
    except Exception as e:
        logger.warning(f"Failed to parse YAML: {e}")
        return {}