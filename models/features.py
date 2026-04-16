"""
Risk Feature Schema
───────────────────
Defines the feature set used by the RandomForest risk classifier.
Teammate A will populate these features from real scan outputs (Phase 3).
For now, synthetic data is used to train and validate the stub model.

Feature descriptions:
    slsa_level              SLSA compliance level estimated by static checker (0-3)
    unpinned_actions_count  Number of unpinned GitHub Actions detected
    unpinned_runners_count  Number of jobs using 'ubuntu-latest' or similar
    missing_attestation_count  Number of jobs missing provenance/attestation
    critical_issues_count   Number of critical-severity issues found
    high_issues_count       Number of high-severity issues found
    medium_issues_count     Number of medium-severity issues found
    total_issues_count      Total issue count across all checks
    has_dynamic_verify      1 if dynamic provenance verification passed, else 0
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any


# ── Ordered list used by the model (must stay consistent) ──────────────
FEATURE_NAMES = [
    "slsa_level",
    "unpinned_actions_count",
    "unpinned_runners_count",
    "missing_attestation_count",
    "critical_issues_count",
    "high_issues_count",
    "medium_issues_count",
    "total_issues_count",
    "has_dynamic_verify",
]

# ── Risk label mapping ──────────────────────────────────────────────────
RISK_LABELS = {
    0: "Low",
    1: "Medium",
    2: "High",
}


@dataclass
class RiskFeatures:
    """
    Structured feature vector extracted from a full SLSA check result.
    Pass a full_slsa_check() output dict to RiskFeatures.from_slsa_result().
    """
    slsa_level: int               = 3
    unpinned_actions_count: int   = 0
    unpinned_runners_count: int   = 0
    missing_attestation_count: int = 0
    critical_issues_count: int    = 0
    high_issues_count: int        = 0
    medium_issues_count: int      = 0
    total_issues_count: int       = 0
    has_dynamic_verify: int       = 0   # binary: 1 or 0

    @classmethod
    def from_slsa_result(cls, result: Dict[str, Any]) -> "RiskFeatures":
        """
        Build a RiskFeatures instance from a full_slsa_check() output dict.

        Args:
            result: Output of full_slsa_check()

        Returns:
            RiskFeatures instance ready for model prediction.
        """
        issues = result.get("issues", [])

        def count_type(issue_type: str) -> int:
            return sum(1 for i in issues if i.get("type") == issue_type)

        def count_severity(severity: str) -> int:
            return sum(1 for i in issues if i.get("severity") == severity)

        verification = result.get("verification") or {}
        has_verify = int(verification.get("verified", False))

        return cls(
            slsa_level=result.get("level", 0),
            unpinned_actions_count=count_type("unpinned_action"),
            unpinned_runners_count=count_type("unpinned_runner"),
            missing_attestation_count=count_type("missing_attestation"),
            critical_issues_count=count_severity("critical"),
            high_issues_count=count_severity("high"),
            medium_issues_count=count_severity("medium"),
            total_issues_count=len(issues),
            has_dynamic_verify=has_verify,
        )

    def to_vector(self) -> list:
        """Return features as an ordered list matching FEATURE_NAMES."""
        return [getattr(self, name) for name in FEATURE_NAMES]

    def to_dict(self) -> dict:
        """Return features as a plain dict."""
        return asdict(self)