import streamlit as st

st.set_page_config(page_title="SLSA Risk Intelligence Platform", page_icon="🔒", layout="wide")
st.title("AI-Powered SLSA Supply Chain Risk Scanner")

github_url = st.text_input("Enter GitHub Repo URL", placeholder="https://github.com/username/repo")

if st.button("Scan Repo"):
    with st.spinner("Scanning..."):
        # Use dummy result until backend endpoint is ready
        result = {
            "status": "setup",
            "issues": [
                {"file": "build.yml", "type": "unpinned_action", "details": "uses: actions/checkout@main", "severity": "high"}
            ],
            "level": 2,
            "suggestions": ["Pin GitHub actions with SHA digest"]
        }
        st.success("Scan complete!")
        st.json(result)