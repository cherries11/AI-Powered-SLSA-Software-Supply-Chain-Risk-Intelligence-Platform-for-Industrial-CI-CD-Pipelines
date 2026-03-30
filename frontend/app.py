import streamlit as st
import pandas as pd
import json
import uuid
import requests
from datetime import datetime
import time
import plotly.graph_objects as go
import plotly.express as px

# ==================== CONFIG ====================
USE_REAL_BACKEND = False   # ← Change to True when backend is ready
BACKEND_URL = "http://backend:8000/api/v1/scan"

# ===============================================

# ── Cyber-Industrial Minimalism Theme ──
st.markdown(
    """
    <style>
    .stApp { background-color: #0E1117; color: #E0E0E0; }
    .stTextInput input {
        background-color: #1E1E2E;
        color: #E0E0E0;
        border: 1px solid #00F5FF44;
        border-radius: 8px;
    }
    .stButton > button {
        background-color: #00F5FF;
        color: #0E1117;
        border: none;
        border-radius: 8px;
        font-weight: bold;
    }
    .stButton > button:hover { background-color: #00D4E0; }
    .card {
        background: rgba(38,39,48,0.65);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(0,245,255,0.18);
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 4px 30px rgba(0,0,0,0.4);
    }
    .badge {
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 0.9rem;
        display: inline-block;
    }
    .critical { background: #FF4B4B; color: white; }
    .warning   { background: #FFB800; color: black; }
    .safe      { background: #00F5FF; color: #0E1117; }
    .issue-item { margin: 0.8rem 0; padding-left: 1rem; border-left: 3px solid #FFB800; }
    hr { border-color: #333; margin: 1.5rem 0; }
    </style>
    """,
    unsafe_allow_html=True
)


# ── Page Config ──
st.set_page_config(
    page_title="SLSA Risk Intelligence Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ── Hero Section ──
st.markdown(
    "<h1 style='text-align:center; color:#00F5FF; margin-bottom:0.3rem;'>SLSA Risk Intelligence</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align:center; color:#A0A0C0; margin-bottom:2rem;'>AI-Powered Supply Chain Security Scanner for Industrial CI/CD</p>",
    unsafe_allow_html=True
)


repo_url = st.text_input("", placeholder="https://github.com/owner/repository", label_visibility="collapsed")


# ── Scan Trigger ──
if st.button("Analyze Repository", type="primary", use_container_width=True):
    if not repo_url.strip().startswith("https://github.com/"):
        st.error("Please enter a valid GitHub repository URL")
    else:
        with st.spinner(""):
            placeholder = st.empty()
            steps = [
                "Cloning repository...",
                "Fetching GitHub Actions workflows...",
                "Performing SLSA compliance analysis...",
                "Generating SBOM & scanning vulnerabilities...",
                "Detecting anomalies & calculating AI risk...",
                "Assembling intelligence report..."
            ]
            for step in steps:
                placeholder.markdown(
                    f"<div style='text-align:center; color:#00F5FF; font-size:1.1rem;'>{step}</div>",
                    unsafe_allow_html=True
                )
                time.sleep(0.7)
            placeholder.empty()

        results = None

        if USE_REAL_BACKEND:
            try:
                response = requests.post(
                    BACKEND_URL,
                    json={"repo_url": repo_url, "branch": "main"},
                    timeout=90
                )
                
                if response.status_code == 200:
                    results = response.json()
                    st.success("Real backend response received", icon="✅")
                elif response.status_code == 400:
                    st.error("Invalid request. Please check the repository URL.")
                    results = None
                elif response.status_code == 403:
                    st.error("Access denied. Private repository may require a valid GitHub PAT.")
                    results = None
                else:
                    st.warning(f"Backend returned error {response.status_code}. Using mock data.")
                    results = None
                    
            except requests.exceptions.ConnectionError:
                st.warning("Backend is not running or unreachable. Using mock data as fallback.")
                results = None
            except requests.exceptions.Timeout:
                st.warning("Backend request timed out. Using mock data.")
                results = None
            except Exception as e:
                st.warning(f"Unexpected error connecting to backend: {e}. Using mock data.")
                results = None

        # Fallback to mock data if backend is disabled or failed
        if results is None:
            results = {
                "status": "success",
                "scan_id": str(uuid.uuid4()),
                "repo": repo_url.split("github.com/")[-1].rstrip("/") if "github.com/" in repo_url else "unknown/repo",
                "branch": "main",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "slsa": {
                    "level": 2,
                    "issues": [
                        {"type": "unpinned_action", "step": "checkout", "details": "uses: actions/checkout@v3"}
                    ],
                    "suggestions": [
                        "Pin all actions to full SHA256 digest",
                        "Replace ubuntu-latest with specific runner version"
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
                        },
                        {
                            "package": "urllib3",
                            "version": "1.26.5",
                            "severity": "HIGH",
                            "cve": "CVE-2024-5678",
                            "description": "HTTP request smuggling vulnerability"
                        }
                    ]
                },
                "ai_risk": {
                    "score": 78,
                    "level": "HIGH",
                    "explanation": "High risk due to 3 critical CVEs + anomaly: new untrusted action added recently",
                    "anomalies": [
                        "Sudden dependency increase: +15 packages in last commit",
                        "Unusual commit time: 03:00 AM UTC"
                    ],
                    "top_factors": [
                        {"factor": "critical_vulns", "weight": 45},
                        {"factor": "slsa_level", "weight": 30},
                        {"factor": "anomaly_score", "weight": 25}
                    ]
                },
                "errors": []
            }

        st.session_state.results = results
        st.success("Analysis complete", icon="✅")


# ── Results Display ──
if "results" in st.session_state:
    r = st.session_state.results
    slsa = r.get("slsa", {})
    scan = r.get("scan", {})
    ai = r.get("ai_risk", {})

    # ── Vital Signs (Header Cards) ──
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    cols = st.columns(4)

    with cols[0]:
        lvl = slsa.get("level")
        lvl_text = lvl if lvl is not None else "Pending"
        lvl_color = "#00F5FF" if lvl and lvl >= 3 else "#FFB800" if lvl == 2 else "#FF4B4B"
        st.markdown(
            f"<div style='text-align:center;'><div class='badge' style='background:{lvl_color};'>SLSA LEVEL {lvl_text}</div></div>",
            unsafe_allow_html=True
        )

    with cols[1]:
        score = ai.get("score")
        if score is not None:
            risk_color = "#FF4B4B" if score >= 70 else "#FFB800" if score >= 40 else "#00F5FF"
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=score,
                title={'text': "AI Risk Score"},
                number={'font': {'size': 36, 'color': risk_color}},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': risk_color},
                    'steps': [
                        {'range': [0, 40], 'color': "rgba(0,245,255,0.15)"},
                        {'range': [40, 70], 'color': "rgba(255,184,0,0.15)"},
                        {'range': [70, 100], 'color': "rgba(255,75,75,0.15)"}
                    ],
                    'threshold': {'line': {'color': risk_color, 'width': 5}, 'thickness': 0.8, 'value': score}
                }
            ))
            fig.update_layout(
                height=160,
                margin=dict(l=0, r=0, t=30, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#E0E0E0"
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.metric("AI Risk Score", "Pending")

    with cols[2]:
        sbom = scan.get("sbom_summary", {})
        st.metric(
            "Total Dependencies",
            sbom.get("total_dependencies") or "N/A",
            delta=f"{sbom.get('outdated') or 0} outdated"
        )

    with cols[3]:
        vulns_count = len(scan.get("vulnerabilities", []))
        badge_class = "critical" if vulns_count > 0 else "safe"
        st.markdown(
            f"<div style='text-align:center;'><div class='badge {badge_class}'>{vulns_count} Vulnerabilities</div></div>",
            unsafe_allow_html=True
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # ── Tabs ──
    tab1, tab2, tab3 = st.tabs(["Risk Intelligence", "Vulnerabilities", "Remediation & Export"])

    with tab1:
        st.markdown("<div class='card'>", unsafe_allow_html=True)

        st.subheader("AI Risk Score")
        score = ai.get("score") or "N/A"
        level = ai.get("level") or "Pending"
        color = "red" if level == "HIGH" else "orange" if level == "MEDIUM" else "green"
        st.metric("Score", f"{score}/100", delta_color="inverse")
        st.markdown(f"<p style='color:{color}; font-weight:bold; font-size:1.2rem;'>{level} Risk</p>", unsafe_allow_html=True)

        st.subheader("Risk Factor Breakdown")
        if ai.get("top_factors"):
            factors = [f["factor"] for f in ai["top_factors"]]
            weights = [f["weight"] for f in ai["top_factors"]]

            sorted_data = sorted(zip(factors, weights), key=lambda x: x[1], reverse=True)
            sorted_factors, sorted_weights = zip(*sorted_data)

            fig = go.Figure(go.Bar(
                y=sorted_factors,
                x=sorted_weights,
                orientation='h',
                marker=dict(
                    color=sorted_weights,
                    colorscale='Bluered_r',
                    line=dict(color='#00F5FF', width=2)
                ),
                text=[f"{w}%" for w in sorted_weights],
                textposition='auto',
                hovertemplate="%{y}: <b>%{x}%</b> impact<extra></extra>",
                marker_opacity=0.92
            ))

            fig.update_layout(
                title="Contribution to Overall Risk Score",
                title_x=0.5,
                xaxis_title="Weight (%)",
                yaxis_title="Risk Factor",
                height=320,
                margin=dict(l=20, r=20, t=60, b=40),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E0E0E0"),
                yaxis=dict(autorange="reversed")
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No risk factor breakdown available yet.")

        st.subheader("AI Explanation")
        st.write(ai.get("explanation") or "No detailed explanation available yet.")
        if ai.get("anomalies"):
            st.markdown("**Detected Anomalies**")
            for a in ai["anomalies"]:
                st.markdown(f"→ {a}")
        if ai.get("top_factors"):
            max_factor = max(ai["top_factors"], key=lambda x: x["weight"])
            st.markdown(f"**Top contributor:** {max_factor['factor']} with {max_factor['weight']}% impact")

        st.markdown("</div>", unsafe_allow_html=True)

    with tab2:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        vulns = scan.get("vulnerabilities", [])
        if vulns:
            df = pd.DataFrame(vulns)

            def color_severity(val):
                if val == "CRITICAL":
                    return 'background-color:#FF4B4B; color:white'
                if val == "HIGH":
                    return 'background-color:#FFB800; color:black'
                if val == "MEDIUM":
                    return 'background-color:#FFD700; color:black'
                return ''

            st.dataframe(
                df.style.map(color_severity, subset=["severity"]),
                use_container_width=True
            )

            # Vulnerability Heatmap
            st.subheader("Vulnerability Heatmap")
            if len(vulns) >= 2:
                pivot = df.pivot_table(index="package", columns="severity", aggfunc="size", fill_value=0)
                fig = px.imshow(
                    pivot,
                    text_auto=True,
                    color_continuous_scale="Reds",
                    aspect="auto",
                    title="Severity Distribution by Package"
                )
                fig.update_layout(xaxis_title="Severity", yaxis_title="Package")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Not enough vulnerabilities to generate meaningful heatmap.")
        else:
            st.info("No vulnerabilities detected in this scan.")
        st.markdown("</div>", unsafe_allow_html=True)

    with tab3:
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        st.subheader("SLSA Issues & Suggestions")
        if slsa.get("issues"):
            for issue in slsa["issues"]:
                st.markdown(
                    f"<div class='issue-item'>⚠ **{issue.get('type','Unknown')}** (step: {issue.get('step','N/A')})<br>{issue.get('details','')}</div>",
                    unsafe_allow_html=True
                )
        else:
            st.success("No SLSA compliance issues found.")

        if slsa.get("suggestions"):
            st.markdown("**Recommended Actions**")
            for s in slsa["suggestions"]:
                st.markdown(f"- {s}")

        if r.get("errors"):
            st.warning("Scan Errors")
            for e in r["errors"]:
                st.write(e)

        st.subheader("Export Report")
        json_str = json.dumps(r, indent=2)
        st.download_button("Download Full JSON Report", json_str, f"slsa-report-{r['scan_id'][:8]}.json", "application/json")
        st.markdown("</div>", unsafe_allow_html=True)


    # ── Reset button (only visible after scan) ──
    if st.button("Clear Results & Scan New Repo", type="secondary"):
        if "results" in st.session_state:
            del st.session_state.results
        st.rerun()
                                 