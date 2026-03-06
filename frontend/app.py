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
        st.stop()  # Stop if empty

    with st.spinner("Scanning..."):
        # ── Mock results (Phase 2) ──
        mock_results = {
            "status": "success",
            "scan_id": str(uuid.uuid4()),
            "repo": github_url,
            "branch": "main",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "slsa": {
                "level": 2,
                "issues": [
                    {"type": "unpinned_action", "step": "checkout", "details": "uses: actions/checkout@v3"}
                ],
                "suggestions": ["Pin all actions to SHA256 digest"]
            },
            "scan": {
                "sbom_summary": {"total_dependencies": 147, "direct": 32, "outdated": 8},
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
                "anomalies": ["Sudden dependency increase: +15 packages in last commit"],
                "top_factors": [
                    {"factor": "critical_vulns", "weight": 45},
                    {"factor": "slsa_level", "weight": 30},
                    {"factor": "anomaly_score", "weight": 25}
                ]
            },
            "errors": []
        }

        st.session_state.results = mock_results
        st.success("Scan complete!")

# ── Display results if available ──
if 'results' in st.session_state:
    results = st.session_state.results

    # ── Tabs ──
    tab_overview, tab_vulns, tab_ai = st.tabs(["Overview", "Vulnerabilities", "AI Risk"])

    # ── Overview Tab ──
    with tab_overview:
        st.subheader("Repository Info")
        st.markdown(f"**Repo:** {results['repo']}")
        st.markdown(f"**Branch:** {results['branch']}")
        st.markdown(f"**Scan ID:** {results['scan_id']}")
        st.markdown(f"**Timestamp:** {results['timestamp']}")

        # SLSA Compliance Gauge
        st.subheader("SLSA Compliance")
        slsa = results['slsa']
        level = slsa["level"] if slsa["level"] is not None else "Unknown"
        color = "green" if level >= 3 else "orange" if level == 2 else "red"

        st.metric("SLSA Level", f"{level}/4")
        st.markdown(
            f"<p style='color:{color};'>Issues: {len(slsa['issues'])} | Suggestions: {len(slsa['suggestions'])}</p>",
            unsafe_allow_html=True
        )

        if slsa["issues"]:
            st.markdown("**Issues:**")
            for issue in slsa["issues"]:
                st.write(f"- {issue['type']} (Step: {issue.get('step','N/A')}) → {issue.get('details','')}")
        if slsa["suggestions"]:
            st.markdown("**Suggestions:**")
            for s in slsa["suggestions"]:
                st.write(f"- {s}")

    # ── Vulnerabilities Tab ──
    with tab_vulns:
        st.subheader("Vulnerabilities / SBOM Summary")
        sbom = results['scan']['sbom_summary']
        st.markdown(f"**Total dependencies:** {sbom['total_dependencies']}, **Direct:** {sbom['direct']}, **Outdated:** {sbom['outdated']}")

        vulns = results['scan']['vulnerabilities']
        if vulns:
            vuln_df = pd.DataFrame(vulns)

            def color_severity(val):
                if val == "CRITICAL":
                    return 'background-color: red; color: white'
                elif val == "HIGH":
                    return 'background-color: orange; color: white'
                elif val == "MEDIUM":
                    return 'background-color: yellow; color: black'
                return 'background-color: green; color: white'

            styled_df = vuln_df.style.applymap(color_severity, subset=['severity'])
            st.dataframe(styled_df)  # Interactive table
        else:
            st.info("No vulnerabilities found.")

    # ── AI Risk Tab ──
    with tab_ai:
        st.subheader("AI Risk Assessment")
        ai_risk = results['ai_risk']
        st.metric("Score", ai_risk['score'])
        st.metric("Level", ai_risk['level'])
        st.markdown(f"**Explanation:** {ai_risk['explanation']}")

        if ai_risk['anomalies']:
            st.markdown("**Detected Anomalies:**")
            for anomaly in ai_risk['anomalies']:
                st.write(f"- {anomaly}")

        if ai_risk['top_factors']:
            st.markdown("**Top Factors:**")
            for f in ai_risk['top_factors']:
                st.write(f"- {f['factor']}: {f['weight']}%")

    # ── Export JSON ──
    st.download_button(
        label="Download Scan Results (JSON)",
        data=json.dumps(results, indent=2),
        file_name=f"scan_{results['scan_id']}.json",
        mime="application/json"
    )
    