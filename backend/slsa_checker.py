"""
SLSA Compliance Checker

Performs both static analysis of GitHub Actions workflow YAML files
and dynamic provenance verification using slsa-verifier.

Features:
- Static: Detects unpinned actions,
untrusted runners, missing attest steps, etc.
- Dynamic: Verifies actual provenance artifact (Level 3+)
- Returns structured result ready for API response and dashboard
"""

import logging
import subprocess
from typing import Dict, List, Any, Optional

from ruamel.yaml import YAML, YAMLError

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

yaml = YAML(typ="safe")


class SLSAComplianceError(Exception):
    """Base exception for SLSA checker errors."""
    pass


class InvalidWorkflowError(SLSAComplianceError):
    """Raised when YAML is invalid or not a workflow."""
    pass


def estimate_slsa_level_from_static(issues: List[Dict]) -> int:
    """
    Simple heuristic to estimate SLSA level based on static findings.
    Can be replaced with ML later.
    """
    if not issues:
        return 3  # No issues → assume good practices (optimistic)

    high_issues = sum(1 for i in issues if i.get("severity") == "high")
    medium_issues = sum(1 for i in issues if i.get("severity") == "medium")

    if high_issues >= 2 or medium_issues >= 4:
        return 1
    if high_issues >= 1 or medium_issues >= 2:
        return 2
    return 3


def static_slsa_analysis(workflow_dict: Dict[str, str]) -> Dict[str, Any]:
    """
    Perform static analysis on workflow YAML files.

    Args:
        workflow_dict: {filename: yaml_content_str}

    Returns:
        Dict with level, issues, suggestions
    """
    issues: List[Dict] = []
    suggestions: List[str] = set()

    for filename, yaml_str in workflow_dict.items():
        try:
            data = yaml.load(yaml_str)
            if not isinstance(data, dict):
                raise InvalidWorkflowError(f"Workflow {filename} is not a mapping")

            # Missing jobs
            if "jobs" not in data:
                issues.append(
                    {
                        "file": filename,
                        "type": "missing_jobs",
                        "details": "Workflow has no jobs defined",
                        "severity": "high",
                    }
                )
                continue

            # Analyze each job
            for job_name, job in data.get("jobs", {}).items():
                # Runner pinning
                runs_on = job.get("runs-on")
                if isinstance(runs_on, str):
                    if "latest" in runs_on.lower():
                        issues.append(
                            {
                                "file": filename,
                                "job": job_name,
                                "type": "unpinned_runner",
                                "details": f"uses '{runs_on}' – should be specific version or self-hosted",
                                "severity": "medium",
                            }
                        )
                        suggestions.add(
                            "Replace 'runs-on: latest' with specific version or self-hosted label"
                        )

                # Step-level checks
                for idx, step in enumerate(job.get("steps", [])):
                    step_name = step.get("name", f"step {idx + 1}")
                    uses = step.get("uses")

                    if uses and isinstance(uses, str):
                        # Unpinned action
                        if "@" not in uses or uses.endswith(("@main", "@master", "@head")):
                            issues.append(
                                {
                                    "file": filename,
                                    "job": job_name,
                                    "step": step_name,
                                    "type": "unpinned_action",
                                    "details": f"uses: {uses}",
                                    "severity": "high",
                                }
                            )
                            suggestions.add(
                                f"Pin action in '{job_name}' → '{step_name}': use SHA digest"
                            )

                        # Missing attestation step (heuristic)
                        if (
                            "slsa" not in uses.lower()
                            and "attest" not in uses.lower()
                            and "provenance" not in uses.lower()
                        ):
                            issues.append(
                                {
                                    "file": filename,
                                    "job": job_name,
                                    "step": step_name,
                                    "type": "missing_attestation",
                                    "details": "No SLSA provenance generation step detected",
                                    "severity": "high",
                                }
                            )
                            suggestions.add(
                                f"Add SLSA provenance step in job '{job_name}', "
                                "e.g. uses: slsa-framework/slsa-github-generator@v2"
                            )

        except YAMLError as e:
            issues.append(
                {
                    "file": filename,
                    "type": "yaml_parse_error",
                    "details": str(e),
                    "severity": "critical",
                }
            )
        except Exception as e:
            logger.exception(f"Unexpected error analyzing {filename}")
            issues.append(
                {
                    "file": filename,
                    "type": "analysis_error",
                    "details": str(e),
                    "severity": "critical",
                }
            )

    level = estimate_slsa_level_from_static(issues)

    return {
        "level": level,
        "issues": issues,
        "suggestions": list(set(suggestions)),  # deduplicate
    }


def dynamic_provenance_verification(
    artifact_path: str,
    provenance_path: str,
    verifier_bin: str = "tools/slsa-verifier.exe",
    source_uri: str = "",
    source_branch: str = "main",
) -> Dict[str, Any]:
    """
    Verify SLSA provenance using slsa-verifier binary.

    Args:
        artifact_path: Path to built artifact (e.g. image tar, digest)
        provenance_path: Path to downloaded provenance file
        verifier_bin: Path to slsa-verifier executable
        source_uri: Expected source repo URI
        source_branch: Expected branch

    Returns:
        Verification result dict
    """
    try:
        cmd = [
            verifier_bin,
            "verify-artifact",
            "--provenance-path",
            provenance_path,
            "--source-uri",
            "https://github.com/kamisara/AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform-for-Industrial-CI-CD-Pipelines.git",
            "--source-branch",
            "main",
        ]

        if source_uri:
            cmd.extend(["--source-uri", source_uri])
        if source_branch:
            cmd.extend(["--source-branch", source_branch])

        cmd.append(artifact_path)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,  # safety timeout
        )

        if result.returncode == 0:
            return {
                "verified": True,
                "level": 3,
                "output": result.stdout.strip(),
                "error": None,
            }
        else:
            return {
                "verified": False,
                "level": 0,
                "output": result.stdout.strip(),
                "error": result.stderr.strip() or "Verification failed",
            }

    except subprocess.TimeoutExpired:
        return {"verified": False, "level": 0, "error": "Verifier timeout"}
    except FileNotFoundError:
        return {"verified": False, "level": 0, "error": f"Verifier binary not found: {verifier_bin}"}
    except Exception as e:
        logger.exception("Dynamic provenance verification failed")
        return {"verified": False, "level": 0, "error": str(e)}


def full_slsa_check(
    workflow_dict: Dict[str, str],
    artifact_path: Optional[str] = None,
    provenance_path: Optional[str] = None,
    verifier_bin: str = "tools/slsa-verifier.exe",
) -> Dict[str, Any]:
    """
    Full SLSA compliance check: static analysis + dynamic verification (if artifact given).

    Returns unified result ready for API response.
    """
    # Static analysis first
    static_result = static_slsa_analysis(workflow_dict)

    result = {
        "level": static_result["level"],
        "issues": static_result["issues"],
        "suggestions": static_result["suggestions"],
        "verification": None,
    }

    # Dynamic verification (if artifact and provenance provided)
    if artifact_path and provenance_path:
        verification = dynamic_provenance_verification(
            artifact_path=artifact_path,
            provenance_path=provenance_path,
            verifier_bin=verifier_bin,
        )
        result["verification"] = verification

        # Upgrade level if dynamic verify passes
        if verification["verified"]:
            result["level"] = max(result["level"], 3)

    return result


# ────────────────────────────────────────────────
# Example usage (for testing)
# ────────────────────────────────────────────────
if __name__ == "__main__":
    # Dummy test data for static analysis
    test_workflows = {
        "build.yml": """
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo hello
"""
    }

    print("=== Static analysis only ===")
    static_result = full_slsa_check(test_workflows)
    print(static_result)

    # ── Dynamic verification test ──
    print("\n=== Dynamic verification test (fake files) ===")

    # Use these fake files (create them if not present)
    artifact_path = "dummy-scada.tar"
    provenance_path = "provenance.json"

    full_result = full_slsa_check(
        test_workflows,
        artifact_path=artifact_path,
        provenance_path=provenance_path,
        verifier_bin="tools/slsa-verifier.exe",  # adjust if path is different
    )

    print(full_result)
