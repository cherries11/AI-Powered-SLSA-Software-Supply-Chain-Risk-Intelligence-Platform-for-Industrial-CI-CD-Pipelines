"""
SLSA Compliance Checker

Performs static analysis of GitHub Actions workflow YAML files
and optional dynamic provenance verification using slsa-verifier.

Features:
- Static:  Detects unpinned actions, unpinned runners,
           missing attestation steps, missing jobs.
- Dynamic: Verifies actual provenance artifact (SLSA Level 3+).
- Returns structured result ready for FastAPI response and Streamlit dashboard.
"""

import logging
import subprocess
from typing import Any, Dict, List, Optional

from ruamel.yaml import YAML, YAMLError

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

_yaml = YAML(typ="safe")


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

# Jobs that are infra/utility — skip attestation check for these
UTILITY_JOB_KEYWORDS = ("warmup", "lint", "notify", "cache", "setup", "dummy", "debug")

# Keywords that indicate a job handles attestation (in uses: or run: steps)
ATTESTATION_KEYWORDS = ("attest", "slsa", "provenance", "cosign", "sigstore")


# ─────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────

class SLSAComplianceError(Exception):
    """Base exception for SLSA checker errors."""


class InvalidWorkflowError(SLSAComplianceError):
    """Raised when YAML is invalid or not a valid workflow."""


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _is_unpinned(uses: str) -> bool:
    """Return True if an action reference is not pinned to a SHA or specific tag."""
    if "@" not in uses:
        return True
    ref = uses.split("@", 1)[-1].lower()
    return ref in ("main", "master", "head", "latest")


def _is_utility_job(job_name: str) -> bool:
    """Return True if job is a utility/infra job that doesn't need attestation."""
    name_lower = job_name.lower()
    return any(kw in name_lower for kw in UTILITY_JOB_KEYWORDS)


def _has_attestation(steps: List[Dict]) -> bool:
    """
    Return True if any step references attestation/provenance tooling.
    Checks both 'uses:' (action) and 'run:' (shell command) fields.
    """
    for step in steps:
        if not isinstance(step, dict):
            continue
        # Check uses: field (action-based attestation)
        uses = step.get("uses", "") or ""
        if any(kw in uses.lower() for kw in ATTESTATION_KEYWORDS):
            return True
        # Check run: field (e.g. cosign attest, slsa-verifier)
        run = step.get("run", "") or ""
        if any(kw in run.lower() for kw in ATTESTATION_KEYWORDS):
            return True
    return False


def estimate_slsa_level(issues: List[Dict]) -> int:
    """
    Estimate SLSA level from static findings.

    Level 1 → many/critical issues
    Level 2 → moderate issues
    Level 3 → clean or near-clean
    """
    if not issues:
        return 3

    high     = sum(1 for i in issues if i.get("severity") == "high")
    medium   = sum(1 for i in issues if i.get("severity") == "medium")
    critical = sum(1 for i in issues if i.get("severity") == "critical")

    if critical >= 1 or high >= 2 or medium >= 4:
        return 1
    if high >= 1 or medium >= 2:
        return 2
    return 3


# ─────────────────────────────────────────────
# Static Analysis
# ─────────────────────────────────────────────

def static_slsa_analysis(workflow_dict: Dict[str, str]) -> Dict[str, Any]:
    """
    Perform static analysis on one or more workflow YAML files.

    Args:
        workflow_dict: { filename: yaml_content_str }

    Returns:
        {
            "level":       int,
            "issues":      List[Dict],
            "suggestions": List[str],
        }
    """
    issues: List[Dict] = []
    suggestions: set = set()

    for filename, yaml_str in workflow_dict.items():
        try:
            data = _yaml.load(yaml_str)

            if not isinstance(data, dict):
                raise InvalidWorkflowError(f"'{filename}' is not a valid YAML mapping.")

            # ── Top-level: missing jobs ──────────────────────────
            if "jobs" not in data:
                issues.append({
                    "file":     filename,
                    "type":     "missing_jobs",
                    "details":  "Workflow has no jobs defined.",
                    "severity": "high",
                })
                continue

            # ── Job-level checks ─────────────────────────────────
            for job_name, job in data.get("jobs", {}).items():
                if not isinstance(job, dict):
                    continue

                steps = job.get("steps") or []

                # 1. Unpinned runner
                runs_on = job.get("runs-on", "")
                if isinstance(runs_on, str) and "latest" in runs_on.lower():
                    issues.append({
                        "file":     filename,
                        "job":      job_name,
                        "type":     "unpinned_runner",
                        "details":  f"'runs-on: {runs_on}' should be a pinned version or self-hosted label.",
                        "severity": "medium",
                    })
                    suggestions.add(
                        f"[{job_name}] Replace 'runs-on: {runs_on}' with a specific version "
                        "(e.g. ubuntu-22.04) or a self-hosted runner."
                    )

                # 2. Unpinned actions (step-level)
                for idx, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    uses = step.get("uses")
                    step_label = step.get("name") or f"step {idx + 1}"

                    if uses and isinstance(uses, str) and _is_unpinned(uses):
                        issues.append({
                            "file":     filename,
                            "job":      job_name,
                            "step":     step_label,
                            "type":     "unpinned_action",
                            "details":  f"uses: {uses}  →  not pinned to a commit SHA.",
                            "severity": "high",
                        })
                        suggestions.add(
                            f"[{job_name} / {step_label}] Pin '{uses}' to a full commit SHA "
                            "(e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683)."
                        )

                # 3. Missing attestation — skip utility jobs
                if not _is_utility_job(job_name) and not _has_attestation(steps):
                    issues.append({
                        "file":     filename,
                        "job":      job_name,
                        "type":     "missing_attestation",
                        "details":  f"Job '{job_name}' has no SLSA provenance or attestation step.",
                        "severity": "high",
                    })
                    suggestions.add(
                        f"[{job_name}] Add a provenance step, e.g. "
                        "'uses: slsa-framework/slsa-github-generator/"
                        ".github/workflows/generator_generic_slsa3.yml@v2'."
                    )

        except YAMLError as e:
            issues.append({
                "file":     filename,
                "type":     "yaml_parse_error",
                "details":  str(e),
                "severity": "critical",
            })
        except InvalidWorkflowError as e:
            issues.append({
                "file":     filename,
                "type":     "invalid_workflow",
                "details":  str(e),
                "severity": "critical",
            })
        except Exception as e:
            logger.exception("Unexpected error while analysing '%s'.", filename)
            issues.append({
                "file":     filename,
                "type":     "analysis_error",
                "details":  str(e),
                "severity": "critical",
            })

    return {
        "level":       estimate_slsa_level(issues),
        "issues":      issues,
        "suggestions": sorted(suggestions),
    }


# ─────────────────────────────────────────────
# Dynamic Provenance Verification
# ─────────────────────────────────────────────

def dynamic_provenance_verification(
    artifact_path: str,
    provenance_path: str,
    source_uri: str,
    source_branch: str = "main",
    verifier_bin: str = "tools/slsa-verifier",
) -> Dict[str, Any]:
    """
    Verify SLSA provenance using the slsa-verifier binary.

    Args:
        artifact_path:   Path to the built artifact (binary, image digest, etc.)
        provenance_path: Path to the downloaded provenance JSON file.
        source_uri:      Expected source repo URI (e.g. "github.com/owner/repo").
        source_branch:   Expected branch name (default: "main").
        verifier_bin:    Path to the slsa-verifier executable.

    Returns:
        {
            "verified": bool,
            "level":    int,   # 3 if verified, 0 otherwise
            "output":   str,
            "error":    str | None,
        }
    """
    cmd = [
        verifier_bin,
        "verify-artifact",
        "--provenance-path", provenance_path,
        "--source-uri",      source_uri,
        "--source-branch",   source_branch,
        artifact_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

        if result.returncode == 0:
            return {
                "verified": True,
                "level":    3,
                "output":   result.stdout.strip(),
                "error":    None,
            }

        return {
            "verified": False,
            "level":    0,
            "output":   result.stdout.strip(),
            "error":    result.stderr.strip() or "Verification failed (non-zero exit).",
        }

    except subprocess.TimeoutExpired:
        return {"verified": False, "level": 0, "output": "", "error": "Verifier timed out after 60 s."}
    except FileNotFoundError:
        return {"verified": False, "level": 0, "output": "", "error": f"Verifier binary not found: '{verifier_bin}'."}
    except Exception as e:
        logger.exception("Unexpected error during dynamic provenance verification.")
        return {"verified": False, "level": 0, "output": "", "error": str(e)}


# ─────────────────────────────────────────────
# Unified Entry Point
# ─────────────────────────────────────────────

def full_slsa_check(
    workflow_dict: Dict[str, str],
    artifact_path: Optional[str] = None,
    provenance_path: Optional[str] = None,
    source_uri: str = "",
    source_branch: str = "main",
    verifier_bin: str = "tools/slsa-verifier",
) -> Dict[str, Any]:
    """
    Run a full SLSA compliance check:
      1. Static analysis on all provided workflow YAMLs.
      2. (Optional) Dynamic provenance verification if artifact + provenance are given.

    Returns a unified dict ready for the FastAPI /scan response.
    """
    static = static_slsa_analysis(workflow_dict)

    result: Dict[str, Any] = {
        "level":        static["level"],
        "issues":       static["issues"],
        "suggestions":  static["suggestions"],
        "verification": None,
    }

    if artifact_path and provenance_path:
        verification = dynamic_provenance_verification(
            artifact_path=artifact_path,
            provenance_path=provenance_path,
            source_uri=source_uri,
            source_branch=source_branch,
            verifier_bin=verifier_bin,
        )
        result["verification"] = verification

        if verification["verified"]:
            result["level"] = max(result["level"], 3)

    return result


# ─────────────────────────────────────────────
# Quick test (run directly)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import json

    SAMPLE_WORKFLOW = {
        "build.yml": """
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo "hello"
"""
    }

    print("=== Static analysis ===")
    print(json.dumps(full_slsa_check(SAMPLE_WORKFLOW), indent=2))