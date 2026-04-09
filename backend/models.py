from pydantic import BaseModel
from typing import Optional, List

# Request model - what the user sends
class ScanRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = "main"  # Defaults to "main" if not provided

# Vulnerability model
class Vulnerability(BaseModel):
    package: str
    version: str
    severity: str
    cve: str
    description: str

# SBOM summary model
class SBOMSummary(BaseModel):
    total_dependencies: int
    direct: int
    outdated: int

# Scan results model
class ScanResults(BaseModel):
    sbom_summary: SBOMSummary
    vulnerabilities: List[Vulnerability]

# Full response model (simplified for now - you'll add more later)
class ScanResponse(BaseModel):
    status: str
    repo: str
    branch: str
    timestamp: str
    scan: ScanResults