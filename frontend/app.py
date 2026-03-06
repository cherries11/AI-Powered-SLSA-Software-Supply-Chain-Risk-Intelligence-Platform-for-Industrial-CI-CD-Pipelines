import streamlit as st
import pandas as pd
import json
import uuid
from datetime import datetime

# ── Page config ──
st.set_page_config(page_title="SLSA Risk Intelligence Platform", page_icon="🔒", layout="wide")
st.title("AI-Powered SLSA Supply Chain Risk Scanner")

# ── Input form ──
github_url = st.text_input("Enter GitHub Repo URL", placeholder="https://github.com/username/repo")

if st.button("Scan Repo"):
    if not github_url:
        st.error("Please enter a GitHub URL")
        st.stop()  # stops execution if URL empty

    with st.spinner("Scanning..."):
        try:
            # ── Mock results (Phase 2) ──
            mock_results = {
                "status": "success",
                "scan_id": str(uuid.uuid4()),
                "repo": github_url,  # show user input
                "branch": "main",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "slsa": {
                    "level": 2,
                    "issues": [
                        {
                            "type": "unpinned_action",
                            "step": "checkout",
                            "details": "uses: actions/checkout@v3"
                        }
                    ],
                    "suggestions": [
                        "Pin all actions to SHA256 digest"
                    ]
                },
                "scan": {
                    "sbom_summary": {
                        "total_dependencies": 147,
                        "direct": 32,
                        "outdated": 8
                    },
                    "vulnerabilities": [
                        {
                            "package": "requests",
                            "version": "2.25.0",
                            "severity": "CRITICAL",
                            "cve": "CVE-2023-1234",
                            "description": "Remote code execution via crafted URL"
                        }
                    ]
                },
                "ai_risk": {
                    "score": 78,
                    "level": "HIGH",
                    "explanation": "High risk due to 3 critical CVEs + anomaly: new untrusted action added recently",
                    "anomalies": [
                        "Sudden dependency increase: +15 packages in last commit"
                    ],
                    "top_factors": [
                        {"factor": "critical_vulns", "weight": 45},
                        {"factor": "slsa_level", "weight": 30},
                        {"factor": "anomaly_score", "weight": 25}
                    ]
                },
                "errors": []
            }

            # Store results for session
            st.session_state.results = mock_results
            st.success("Scan complete!")

        except Exception as e:
            st.error(f"Error: {e}")

# ── Display results if available ──
if 'results' in st.session_state:
    results = st.session_state.results

    st.subheader("Repository Info")
    st.markdown(f"**Repo:** {results['repo']}")
    st.markdown(f"**Branch:** {results['branch']}")
    st.markdown(f"**Scan ID:** {results['scan_id']}")
    st.markdown(f"**Timestamp:** {results['timestamp']}")

    # ── SLSA Compliance ──
    st.subheader("SLSA Compliance")
    st.metric("SLSA Level", results['slsa']['level'])
    if results['slsa']['issues']:
        st.markdown("**Issues:**")
        for issue in results['slsa']['issues']:
            st.write(f"- {issue['type']} (Step: {issue.get('step','N/A')}) → {issue.get('details','')}")
    if results['slsa']['suggestions']:
        st.markdown("**Suggestions:**")
        for s in results['slsa']['suggestions']:
            st.write(f"- {s}")

    # ── Vulnerabilities ──
    st.subheader("Vulnerabilities / SBOM Summary")
    sbom = results['scan']['sbom_summary']
    st.markdown(f"**Total dependencies:** {sbom['total_dependencies']}, **Direct:** {sbom['direct']}, **Outdated:** {sbom['outdated']}")
    vulns_df = pd.DataFrame(results['scan']['vulnerabilities'])
    if not vulns_df.empty:
        st.dataframe(vulns_df)
    else:
        st.info("No vulnerabilities found.")

    # ── AI Risk Assessment ──
    st.subheader("AI Risk Assessment")
    st.metric("Score", results['ai_risk']['score'])
    st.metric("Level", results['ai_risk']['level'])
    st.markdown(f"**Explanation:** {results['ai_risk']['explanation']}")
    if results['ai_risk']['anomalies']:
        st.markdown("**Detected Anomalies:**")
        for anomaly in results['ai_risk']['anomalies']:
            st.write(f"- {anomaly}")
    if results['ai_risk']['top_factors']:
        st.markdown("**Top Factors:**")
        for f in results['ai_risk']['top_factors']:
            st.write(f"- {f['factor']}: {f['weight']}%")

    # ── Download results ──
    st.download_button(
        label="Download Scan Results (JSON)",
        data=json.dumps(results, indent=2),
        file_name=f"scan_{results['scan_id']}.json",
        mime="application/json"
    )