# tests/test_github_api.py
import os
from backend.github_api import get_workflow_yaml, parse_yaml


def test_fetch_workflows():
    pat = os.getenv("GITHUB_TOKEN")
    if not pat:
        # skip the test if no token is available (safe in CI)
        import pytest
        pytest.skip("GITHUB_TOKEN not set")

    repo_url = (
        "https://github.com/kamisara/"
        "AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform-for-Industrial-CI-CD-Pipelines"
    )

    workflows = get_workflow_yaml(repo_url, github_pat=pat)
    for filename, content in workflows.items():
        yaml_dict = parse_yaml(content)
        assert isinstance(yaml_dict, dict)
