import streamlit as st
import pandas as pd
import json
import uuid
from datetime import datetime
import time  # for fake delay in spinner

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
        time.sleep(2)  # fake delay for UX realism

        try:
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

# ── Display results with tabs if available ──
if 'results' in st.session_state:
    results = st.session_state.results
    scan = results["scan"]
    slsa = results["slsa"]

    tab1, tab2, tab3 = st.tabs(["Overview", "Vulnerabilities", "Export"])

    # ── Tab 1: Overview ──
    with tab1:
        st.subheader("SLSA Compliance")
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

        st.subheader("SBOM Summary")
        sbom = scan["sbom_summary"]
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Deps", sbom["total_dependencies"] or "N/A")
        col2.metric("Direct Deps", sbom["direct"] or "N/A")
        col3.metric("Outdated Deps", sbom["outdated"] or "N/A")

        st.subheader("AI Risk Assessment")
        st.metric("Score", results['ai_risk']['score'])
        st.metric("Level", results['ai_risk']['level'])
        st.markdown(f"**Explanation:** {results['ai_risk']['explanation']}")
        if results['ai_risk']['anomalies']:
            st.markdown("**Detected Anomalies:**")
            for anomaly in results['ai_risk']['anomalies']:
                st.write(f"- {anomaly}")

    # ── Tab 2: Vulnerabilities ──
    with tab2:
        if scan["vulnerabilities"]:
            vuln_df = pd.DataFrame(scan["vulnerabilities"])

            def color_severity(val):
                if val == "CRITICAL":
                    return 'background-color: red; color: white'
                elif val == "HIGH":
                    return 'background-color: orange; color: white'
                elif val == "MEDIUM":
                    return 'background-color: yellow; color: black'
                return 'background-color: green; color: white'

            styled_df = vuln_df.style.applymap(color_severity, subset=['severity'])
            st.subheader("Vulnerabilities")
            st.dataframe(styled_df)
        else:
            st.info("No vulnerabilities found.")

    # ── Tab 3: Export ──
    with tab3:
        json_str = json.dumps(results, indent=4)
        st.download_button(
            label="Export JSON",
            data=json_str,
            file_name=f"scan_{results['scan_id']}.json",
            mime="application/json"
        )
          