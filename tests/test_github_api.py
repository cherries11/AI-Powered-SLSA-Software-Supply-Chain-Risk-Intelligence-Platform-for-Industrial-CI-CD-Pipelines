# tests/test_github_api.py
import sys
import os

# Add repo root to sys.path so 'backend' is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now the imports will work
from backend.github_api import get_workflow_yaml, parse_yaml

# Load .env file
from dotenv import load_dotenv
load_dotenv()

# Repo info
repo_url = "https://github.com/kamisara/AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform-for-Industrial-CI-CD-Pipelines"

# Get PAT from environment variable
pat = os.getenv("GITHUB_TOKEN")
if not pat:
    raise ValueError("GITHUB_TOKEN not set in .env file!")

# Fetch workflows
workflows = get_workflow_yaml(repo_url, github_pat=pat)

# Print YAMLs as Python dict
for filename, content in workflows.items():
    print(f"--- {filename} ---")
    yaml_dict = parse_yaml(content)
    print(yaml_dict)