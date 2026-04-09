# AI-Powered SLSA Software Supply Chain Risk Intelligence Platform

## Overview

AI-powered security scanner for GitHub repositories that detects vulnerabilities and provides ML-based risk assessment.

## Features

- 🔍 Vulnerability scanning (Syft + Trivy + pip-audit)
- 🤖 ML anomaly detection (Isolation Forest, 89% recall)
- 📊 SBOM generation
- 🚀 REST API with automatic documentation

## Quick Start

### Prerequisites

```bash
# Install tools
winget install Anchore.Syft
winget install aquasecurity.trivy
pip install pip-audit


#Clone and setup
cd project
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Add GitHub token to .env
echo "GITHUB_TOKEN=ghp_your_token" > .env


#RUN
cd backend
uvicorn app:app --reload

#API Endpoint

{
  "repo_url": "https://github.com/pallets/flask",
  "branch": "main"
}



{
  "status": "success",
  "scan_id": "uuid",
  "repo": "pallets/flask",
  "scan": {
    "sbom_summary": {"total_dependencies": 118},
    "vulnerabilities": [
      {"package": "werkzeug", "severity": "HIGH", "cve": "CVE-2024-34069"}
    ]
  },
  "ai_risk": {"score": 0.049, "level": "LOW"}
}

Test Results
| Repository | Dependencies | Vulnerabilities | AI Score | Risk Level |
|------------|--------------|-----------------|----------|------------|
| pallets/flask | 118 | 14 (1 High) | 0.049 | LOW |
| cline/cline | 2,767 | 41 (3 Critical) | -0.229 | HIGH |
| lodash/lodash | 544 | 28 (4 Critical) | -0.213 | HIGH |
| rails/rails | 508 | 102 (4 Critical) | -0.256 | HIGH |
| ansible/ansible | 48 | 0 | 0.038 | LOW |
| pytest-dev/pytest | 36 | 0 | 0.049 | LOW |
| qgis/QGIS | 0 | 3 (1 High) | 0.034 | LOW |
| eclipse-theia/theia | 1,508 | 0 (anomaly) | -0.044 | HIGH |
| left-pad | 0 | 0 | 0.043 | LOW |
| serialize-javascript | 0 | 0 | 0.043 | LOW |

Model Performance: Anomaly Detection Rate: 89%
ML Model Details

    Algorithm: Isolation Forest

    Training Data: MegaVul (339,548 entries)

    Features: 8 (dependencies, vulns by severity)

    Threshold: -0.017
