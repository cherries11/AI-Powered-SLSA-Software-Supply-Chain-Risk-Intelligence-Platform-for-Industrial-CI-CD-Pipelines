# AI-Powered SLSA Software Supply Chain Risk Intelligence Platform

## Overview

The **AI-Powered SLSA Software Supply Chain Risk Intelligence Platform** is a cybersecurity analysis tool designed to evaluate the security posture of software repositories used in CI/CD pipelines. The platform analyzes GitHub repositories, checks **SLSA (Supply‑chain Levels for Software Artifacts) compliance**, generates a **Software Bill of Materials (SBOM)** summary, identifies **vulnerabilities**, and computes an **AI‑based risk score** that highlights potential supply chain threats.

This project demonstrates how modern DevSecOps tools can combine **automated scanning, vulnerability analysis, and machine‑assisted risk evaluation** to improve the security of software supply chains.

The platform currently includes a **Streamlit-based frontend dashboard**, mock backend integration, and a JSON schema that allows easy expansion into a full backend scanning system.

---

# Key Features

### Repository Security Analysis

* Analyze GitHub repositories used in CI/CD pipelines
* Extract repository metadata (owner, repo name, branch)
* Simulated repository cloning and workflow analysis

### SLSA Compliance Evaluation

* Determines SLSA level compliance
* Identifies CI/CD security issues such as:

  * Unpinned GitHub Actions
  * Insecure runners
  * Missing provenance guarantees

### SBOM Summary

Displays dependency statistics:

* Total dependencies
* Direct dependencies
* Outdated dependencies

### Vulnerability Detection

Shows detected vulnerabilities including:

* Package name
* Version
* CVE identifier
* Severity level
* Vulnerability description

### AI‑Based Risk Intelligence

The platform calculates a **risk score (0–100)** based on multiple factors:

* Vulnerability severity
* SLSA compliance level
* Behavioral anomalies

It also provides:

* Risk explanation
* Detected anomalies
* Top risk contributing factors

### Interactive Security Dashboard

The Streamlit UI includes:

* SLSA compliance indicator
* AI risk gauge visualization
* Vulnerability table with severity coloring
* Risk factor charts
* Exportable JSON scan reports

### Exportable Security Reports

Users can download a complete **JSON scan report** containing:

* Repository metadata
* SLSA analysis
* SBOM summary
* Vulnerabilities
* AI risk analysis

---

# System Architecture

The platform is structured into multiple components that simulate a modern supply‑chain security system.

```
User
  │
  ▼
Frontend Dashboard (Streamlit)
  │
  ▼
Scan Request
  │
  ▼
Backend Scanner (Planned)
  │
  ├─ GitHub Repository Analyzer
  ├─ CI/CD Workflow Parser
  ├─ SBOM Generator
  ├─ Vulnerability Scanner
  └─ AI Risk Engine
  │
  ▼
JSON Security Report
  │
  ▼
Frontend Visualization
```

Currently, the frontend simulates backend responses using **mock data following the project JSON schema**.

---

# Project Structure

```
AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform/

frontend/
  app.py

backend/ (future implementation)
  api/
  scanner/
  slsa/
  vulnerabilities/
  ai_risk_engine/

schemas/
  scan_schema.json

examples/
  sample_scan.json

README.md
```

---

# Technology Stack

## Frontend

* **Streamlit** – interactive web dashboard
* **Plotly** – risk gauge visualizations
* **Pandas** – data handling

## Backend (Planned)

* **Python / FastAPI** – scanning API
* **GitHub API** – repository access
* **Dependency scanners** – vulnerability detection
* **SBOM generators** – dependency analysis

## Security Standards

* **SLSA Framework**
* **SBOM principles**
* **CVE vulnerability tracking**

---

# Installation

## 1. Clone the repository

```
git clone https://github.com/<your-username>/AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform.git
cd AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform
```

## 2. Create a virtual environment (recommended)

```
python -m venv venv
```

Activate the environment:

Windows

```
venv\Scripts\activate
```

Linux / Mac

```
source venv/bin/activate
```

## 3. Install dependencies

```
pip install streamlit pandas plotly
```

---

# Running the Application

Start the Streamlit dashboard:

```
streamlit run frontend/app.py
```

The application will open in your browser at:

```
http://localhost:8501
```

---

# How the Platform Works

1. User enters a GitHub repository URL.
2. The system simulates repository analysis.
3. SLSA compliance checks are performed.
4. Dependencies and vulnerabilities are analyzed.
5. The AI engine calculates a risk score.
6. Results are visualized in the dashboard.
7. Users can export the security report as JSON.

---

# JSON Scan Report Schema

Each scan produces a structured JSON report containing:

```
{
  "status": "success",
  "scan_id": "uuid",
  "repo": "owner/repository",
  "branch": "main",
  "timestamp": "ISO8601",

  "slsa": {
    "level": 0-4,
    "issues": [],
    "suggestions": []
  },

  "scan": {
    "sbom_summary": {
      "total_dependencies": number,
      "direct": number,
      "outdated": number
    },
    "vulnerabilities": []
  },

  "ai_risk": {
    "score": 0-100,
    "level": "LOW|MEDIUM|HIGH",
    "explanation": "text",
    "anomalies": [],
    "top_factors": []
  },

  "errors": []
}
```

This schema allows integration with external tools, dashboards, or security pipelines.

---

# Future Improvements

Planned enhancements for the project include:

* Real backend repository scanning
* Automatic SBOM generation
* Integration with vulnerability databases
* Machine learning based anomaly detection
* CI/CD pipeline security scoring
* Multi‑repository monitoring
* Historical risk tracking

---

# Use Cases

This platform can be used for:

* DevSecOps security monitoring
* Software supply chain risk analysis
* CI/CD pipeline auditing
* Security research and education

---

# Educational Purpose

This project is developed as part of a **Cybersecurity / Software Engineering academic project** to demonstrate practical supply chain security concepts.

---

# License

This project is released under the MIT License.

---

# Author

Developed as part of a cybersecurity project focused on **software supply chain security and SLSA compliance analysis**.
