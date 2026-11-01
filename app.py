
import streamlit as st
import json

from app.report_export import generate_csv_report
from app.detector import analyze_url
from app.reputation import check_url_reputation
from app.urlscan import (
    get_urlscan_result,
    submit_url_for_scanning,
)


# Page configuration
st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered",
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
    placeholder="https://example.com/login",
)


# Initialize session state
if "analysis_report" not in st.session_state:
    st.session_state["analysis_report"] = None

if "urlscan_scan_id" not in st.session_state:
    st.session_state["urlscan_scan_id"] = None

if "urlscan_result_url" not in st.session_state:
    st.session_state["urlscan_result_url"] = None

if "urlscan_details" not in st.session_state:
    st.session_state["urlscan_details"] = None


# Analyze URL
if st.button("Analyze URL", type="primary"):
    if not url.strip():
        st.warning("Please enter a URL first.")

    else:
        try:
            clean_url = url.strip()

            # Run URL analysis and reputation checks
            report = analyze_url(clean_url)
            reputation = check_url_reputation(clean_url)

            report["reputation"] = reputation

            # Submit URL to URLScan.io
            urlscan_result = submit_url_for_scanning(clean_url)
            report["urlscan"] = urlscan_result

            # Save report so it survives Streamlit reruns
            st.session_state["analysis_report"] = report

            # Reset previous scan details
            st.session_state["urlscan_details"] = None

            if urlscan_result["status"] == "submitted":
                st.session_state["urlscan_scan_id"] = (
                    urlscan_result["scan_id"]
                )
                st.session_state["urlscan_result_url"] = (
                    urlscan_result["result_url"]
                )
            else:
                st.session_state["urlscan_scan_id"] = None
                st.session_state["urlscan_result_url"] = None

        except (ValueError, TypeError) as error:
            st.error(f"Could not analyze this input: {error}")


# Retrieve URLScan.io results independently of Analyze URL
if st.session_state["urlscan_scan_id"]:
    if st.button("Check URLScan.io Results"):
        with st.spinner("Retrieving URLScan.io scan results..."):
            scan_details = get_urlscan_result(
                st.session_state["urlscan_scan_id"]
            )

        st.session_state["urlscan_details"] = scan_details


# Display the saved report after every rerun
report = st.session_state["analysis_report"]

if report is not None:
    st.divider()

    # Google Safe Browsing
    st.subheader("Threat Intelligence — Google Safe Browsing")

    reputation = report["reputation"]

    if reputation["status"] == "unsafe":
        st.error("Known threat detected")
        st.write(reputation["message"])

        if reputation.get("threat_types"):
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

    # URLScan.io investigation
    st.subheader("URLScan.io Investigation")

    urlscan_result = report["urlscan"]

    if urlscan_result["status"] == "submitted":
        st.success("URL submitted to URLScan.io")
        st.write(urlscan_result["message"])

        st.link_button(
            "Open URLScan.io Results",
            st.session_state["urlscan_result_url"],
        )

        st.caption(
            "The scan may take time to complete. "
            "Use Check URLScan.io Results to retrieve the report."
        )

    else:
        st.warning("URLScan.io scan could not be submitted")
        st.write(urlscan_result["message"])

    # Display retrieved scan details
    scan_details = st.session_state["urlscan_details"]

    if scan_details:
        st.subheader("URLScan.io Scan Results")

        if scan_details["status"] == "complete":
            st.write(
                f"**Page title:** {scan_details['page_title']}"
            )
            st.write(f"**Domain:** {scan_details['domain']}")
            st.write(f"**IP address:** {scan_details['ip']}")
            st.write(f"**Country:** {scan_details['country']}")

            if scan_details["malicious"] is True:
                st.error(
                    "URLScan.io reports a malicious verdict."
                )
            elif scan_details["malicious"] is False:
                st.success(
                    "URLScan.io does not report a malicious verdict."
                )
            else:
                st.info("No malicious verdict is available.")

            st.write(
                f"**Verdict score:** {scan_details['score']}"
            )

            categories = scan_details.get("categories") or []
            st.write(
                "**Categories:** "
                + (
                    ", ".join(categories)
                    if categories
                    else "None reported"
                )
            )

            st.link_button(
                "View Full URLScan.io Report",
                scan_details["result_url"],
            )

        elif scan_details["status"] == "pending":
            st.info(
                "The scan is still processing. "
                "Wait a little, then click Check URLScan.io Results again."
            )

        else:
            st.warning(scan_details["message"])

    # Heuristic analysis
    st.subheader("Analysis Results")

    score = report["risk_score"]
    st.metric("Heuristic Risk Score", f"{score}/100")

    if score >= 50:
        st.error(
            "Risk level: High — multiple suspicious indicators detected."
        )
    elif score >= 20:
        st.warning(
            "Risk level: Moderate — suspicious indicators detected."
        )
    elif score > 0:
        st.info(
            "Risk level: Low — some indicators were detected."
        )
    else:
        st.success("No current rules triggered.")

    st.caption(
        "A low score or zero findings does not guarantee that a URL is safe."
    )

    # Detection summary
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

    # Detection findings
    st.subheader("Detection Findings")

    if findings:
        for finding in findings:
            with st.container(border=True):
                st.markdown(
                    f"**{finding['rule'].replace('_', ' ').title()}**"
                )
                st.caption(
                    f"Severity: {finding['severity'].title()}"
                )
                st.write(finding["reason"])
    else:
        st.write("No current detection rules were triggered.")
        st.caption("This does not guarantee that the URL is safe.")

    # Extracted URL features
    with st.expander("View extracted URL features"):
        st.json(report["features"])

    st.caption(report["note"])

    # Export reports
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
