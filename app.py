
import streamlit as st
import json
from app.report_export import generate_csv_report
from app.detector import analyze_url
from app.reputation import check_url_reputation



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
            reputation = check_url_reputation(url.strip())
            report["reputation"] = reputation
            st.divider()
            st.divider()
            st.subheader("Threat Intelligence — Google Safe Browsing")

            if reputation["status"] == "unsafe":
                st.error("Known threat detected")
                st.write(reputation["message"])

                if reputation["threat_types"]:
                    st.write(
                        "Threat types: "
                    + ", ".join(reputation["threat_types"])
                )

            elif reputation["status"] == "safe":
                st.success("No known threats reported")
                st.write(reputation["message"])

            else:
                st.warning("Threat intelligence check unavailable")
                st.write(reputation["message"])

            st.caption(
                "Threat intelligence is one signal, not a guarantee of safety. "
                "An unavailable check does not mean the URL is safe."
        )
            st.subheader("Analysis Results")

            score = report["risk_score"]
            st.metric("Heuristic Risk Score", f"{score}/100")
            
            if score >= 50:
                st.error("Risk level: High — multiple suspicious indicators detected.")
            elif score >= 20:
                st.warning("Risk level: Moderate — suspicious indicators detected.")
            elif score > 0:
                st.info("Risk level: Low — some indicators were detected.")
            else:
                st.success("No current rules triggered.")

            st.caption(
                "A low score or zero findings does not guarantee that a URL is safe."
        )

            
            st.subheader("Detection Summary")

            findings = report["findings"]
            st.metric("Total Findings", len(findings))

            severity_order = {
                "low": 1,
                "medium": 2,
                "high": 3,
            }

            if findings:
                highest_severity = max(
                    findings,
                    key=lambda finding: severity_order.get(
                        finding["severity"].lower(), 0
                    ),
                )["severity"].title()

                st.write(f"Highest Severity: **{highest_severity}**")
                st.write("Assessment: Suspicious indicators detected")
            else:
                st.write("Highest Severity: **None**")
                st.write("Assessment: No current rules triggered")

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
            
            csv_data = generate_csv_report(report)

            st.download_button(
                label="Download Analysis Report (JSON)",
                data=json.dumps(report, indent=4),
                file_name="phishguard_report.json",
                mime="application/json",
            )
            
            st.download_button(
                label="Download Analysis Report (CSV)",
                data=csv_data,
                file_name="phishguard_report.csv",
                mime="text/csv",
            )


        except (ValueError, TypeError) as error:
            st.error(f"Could not analyze this input: {error}")
