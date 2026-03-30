# API Documentation

## POST /api/v1/scan

Scan a GitHub repository.

### Request

```json
{
  "repo_url": "https://github.com/pallets/flask",
  "branch": "main"
}

{
  "status": "success",
  "scan_id": "uuid",
  "repo": "pallets/flask",
  "branch": "main",
  "scan": {
    "sbom_summary": {
      "total_dependencies": 118
    },
    "vulnerabilities": [
      {
        "package": "werkzeug",
        "severity": "HIGH",
        "cve": "CVE-2024-34069"
      }
    ]
  },
  "ai_risk": {
    "score": 0.049,
    "level": "LOW"
  }
}

{
  "status": "error",
  "code": "scan_failed",
  "message": "Repository not found"
}

{
  "status": "ok",
  "message": "Scanner API is running"
}

http://localhost:8000/docs

