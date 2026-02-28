from backend.github_api import get_workflow_yaml, parse_yaml

repo_url = "https://github.com/kamisara/AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform-for-Industrial-CI-CD-Pipelines"

workflows = get_workflow_yaml(repo_url)

for filename, content in workflows.items():
    print(f"--- {filename} ---")
    yaml_dict = parse_yaml(content)
    print(yaml_dict)