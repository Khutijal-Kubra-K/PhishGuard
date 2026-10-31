
import streamlit as st
from app.detector import analyze_url

# Page configuration
st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)

# Header
st.title("🛡️ PhishGuard")
st.subheader("Suspicious URL Analysis")
st.write(
    "Analyze URL structure for potentially suspicious indicators. "
    "This tool uses simple rules and does not guarantee that a URL is safe."
)

# URL input
url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com/login"
)

if st.button("Analyze URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL first.")

    else:
        try:
            report = analyze_url(url.strip())

            st.divider()
            st.subheader("Analysis Results")

            score = report["risk_score"]
            st.metric("Heuristic Risk Score", f"{score}/100")
            if score >= 50:
                st.error("Risk level: High")
            elif score >= 20:
                st.warning("Risk level: Moderate")
            elif score > 0:
                st.info("Risk level: Low")
            else:
                st.success("No current rules triggered")
            if score >= 50:
                st.error("Multiple suspicious indicators detected.")
            elif score > 0:
                st.warning("Some suspicious indicators detected.")
            else:
                st.info(
                    "No indicators from the current rules were detected. "
                    "This does not mean the URL is safe."
                )

            st.subheader("Detection Findings")

            if report["findings"]:
                for finding in report["findings"]:
                    with st.container(border=True):
                        st.markdown(f"**{finding['rule'].replace('_', ' ').title()}**")
                        st.caption(f"Severity: {finding['severity'].title()}")
                        st.write(finding["reason"])
            else:
                st.write("No current detection rules were triggered.")
                st.caption(
                    "This does not guarantee that the URL is safe."
                )

            with st.expander("View extracted URL features"):
                st.json(report["features"])

            st.caption(report["note"])

        except (ValueError, TypeError) as error:
            st.error(f"Could not analyze this input: {error}")
