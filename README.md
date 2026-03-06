# AI-Powered-SLSA-Software-Supply-Chain-Risk-Intelligence-Platform-for-Industrial-CI-CD-Pipelines

# AI-Powered SLSA Supply Chain Risk Intelligence Platform

This project automates SLSA (Supply-chain Levels for Software Artifacts) compliance checks
and provides AI-powered risk intelligence for CI/CD pipelines, specifically tailored
for industrial software projects in Algeria.

## Value Proposition

- **Automate SLSA Compliance:** Static and dynamic verification of GitHub Actions workflows.
- **AI Risk Intelligence:** Identify potential supply chain risks using ML heuristics.
- **Industrial CI/CD Focus:** Designed to align with Algeria’s cybersecurity strategy for critical infrastructure (energy, telecom, etc.).

## Local Setup Guide
1. Clone repo: git clone <url>
2. Create/activate venv: python -m venv .venv; .venv\Scripts\activate (on Windows)
3. Install reqs: pip install -r requirements.txt
4. GitHub PAT: Create with repo/workflow scopes.
5. Run frontend: streamlit run frontend/app.py