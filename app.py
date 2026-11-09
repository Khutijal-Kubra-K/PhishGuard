
import streamlit as st
import json

from app.report_export import generate_csv_report
from app.detector import analyze_url
from app.reputation import check_url_reputation
from app.urlscan import (
    get_urlscan_result,
    submit_url_for_scanning,
)
from app.risk_engine import build_risk_assessment


# Page configuration
st.set_page_config(
    page_title="PhishGuard",
    page_icon="\U0001F6E1",
    layout="centered",
)


# Header
st.title("\U0001F6E1 PhishGuard")
st.subheader("Suspicious URL Analysis")
st.write(
    "Analyze URLs using heuristic detection, "
    "Google Safe Browsing, and URLScan.io."
)
st.caption(
    "A low risk score does not guarantee that a URL is safe."
)


# URL input
url = st.text_input(
    "Enter a URL",
    placeholder="https://example.com/login",
)


# Initialize session state
defaults = {
    "analysis_report": None,
    "urlscan_scan_id": None,
    "urlscan_result_url": None,
    "urlscan_details": None,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


# Analyze URL
if st.button("Analyze URL", type="primary"):

    if not url.strip():
        st.warning("Please enter a URL first.")

    else:
        try:
            clean_url = url.strip()

            with st.spinner("Analyzing URL..."):

                # Heuristic analysis
                heuristic_report = analyze_url(clean_url)

                # Google Safe Browsing
                reputation = check_url_reputation(clean_url)

                # Submit URL to URLScan.io
                urlscan_submission = submit_url_for_scanning(
                    clean_url
                )

                # Save scan information
                scan_id = None
                result_url = None

                if urlscan_submission["status"] == "submitted":
                    scan_id = urlscan_submission["scan_id"]
                    result_url = urlscan_submission["result_url"]

                # URLScan submission is not a completed verdict.
                # Keep it pending until the actual report is retrieved.
                initial_urlscan_result = {
                    "status": (
                        "pending"
                        if scan_id
                        else "error"
                    ),
                    "message": urlscan_submission["message"],
                }

                # Build unified assessment
                assessment = build_risk_assessment(
                    heuristic_report,
                    reputation,
                    initial_urlscan_result,
                )

                # Combine all report data
                report = {
                    **heuristic_report,
                    "reputation": reputation,
                    "urlscan": urlscan_submission,
                    "risk_assessment": assessment,
                }

                st.session_state["analysis_report"] = report
                st.session_state["urlscan_scan_id"] = scan_id
                st.session_state["urlscan_result_url"] = result_url
                st.session_state["urlscan_details"] = None

        except (ValueError, TypeError, KeyError) as error:
            st.error(f"Could not analyze this input: {error}")


# Retrieve URLScan.io results
if st.session_state["urlscan_scan_id"]:

    if st.button("Check URLScan.io Results"):

        with st.spinner("Retrieving URLScan.io results..."):

            scan_details = get_urlscan_result(
                st.session_state["urlscan_scan_id"]
            )
            st.session_state["urlscan_details"] = scan_details

            # Rebuild assessment using completed scan results
            report = st.session_state["analysis_report"]

            report["risk_assessment"] = build_risk_assessment(
                report,
                report["reputation"],
                scan_details,
            )


# Display saved report
report = st.session_state["analysis_report"]

if report is not None:

    st.divider()

    assessment = report["risk_assessment"]

    # Unified Risk Assessment
    st.header("Unified Risk Assessment")

    risk_score = assessment["risk_score"]
    risk_level = assessment["risk_level"]

    st.metric(
        "Overall Risk Score",
        f"{risk_score}/100",
    )

    st.progress(risk_score / 100)

    if risk_level == "Critical":
        st.error(f"CRITICAL RISK — {assessment['verdict']}")

    elif risk_level == "High":
        st.error(f"HIGH RISK — {assessment['verdict']}")

    elif risk_level == "Medium":
        st.warning(f"MEDIUM RISK — {assessment['verdict']}")

    else:
        st.success(f"LOW RISK — {assessment['verdict']}")

    st.caption(assessment["note"])

    # Evidence breakdown
    st.subheader("Detection Evidence")

    for item in assessment["evidence"]:

        with st.container(border=True):

            st.markdown(f"**{item['source']}**")

            status = item["status"]

            if status in ("unsafe", "malicious"):
                st.error(status.replace("_", " ").title())

            elif status == "no_match":
                st.success("No known threat reported")

            elif status == "no_malicious_verdict":
                st.info("No malicious verdict reported")

            elif status == "pending":
                st.info("Scan pending")

            elif status == "complete":
                st.success("Scan completed")

            elif status == "inconclusive":
                st.warning("Verdict inconclusive")

            else:
                st.warning(status.replace("_", " ").title())

            st.write(item["message"])

            if item.get("threat_types"):
                st.write(
                    "**Threat types:** "
                    + ", ".join(item["threat_types"])
                )

            if item.get("categories"):
                st.write(
                    "**Categories:** "
                    + ", ".join(item["categories"])
                )

            if item.get("urlscan_score") is not None:
                st.write(
                    f"**URLScan verdict score:** "
                    f"{item['urlscan_score']}"
                )

            if item.get("result_url"):
                st.link_button(
                    "Open URLScan.io Report",
                    item["result_url"],
                )

    # Google Safe Browsing details
    st.subheader("Google Safe Browsing")

    reputation = report["reputation"]

    if reputation["status"] == "unsafe":
        st.error("Known threat detected")

    elif reputation["status"] == "safe":
        st.success("No known threats reported")

    else:
        st.warning("Threat intelligence unavailable")

    st.write(reputation["message"])

    # URLScan.io details
    st.subheader("URLScan.io Investigation")

    urlscan_submission = report["urlscan"]
    scan_details = st.session_state["urlscan_details"]

    if urlscan_submission["status"] == "submitted":

        st.success("URL submitted successfully")

        st.link_button(
            "Open URLScan.io Results",
            st.session_state["urlscan_result_url"],
        )

        if scan_details and scan_details["status"] == "complete":
            st.success("URLScan.io investigation completed successfully.")
        else:
            st.caption(
                "Wait for the scan to complete, then click "
                "Check URLScan.io Results."
            )

    else:
        st.warning(urlscan_submission["message"])

    if scan_details:

        if scan_details["status"] == "complete":

            st.markdown("**Retrieved scan information**")

            st.write(
                f"Page title: {scan_details['page_title']}"
            )

            st.write(
                f"Domain: {scan_details['domain']}"
            )

            st.write(
                f"IP address: {scan_details['ip']}"
            )

            st.write(
                f"Country: {scan_details['country']}"
            )

        elif scan_details["status"] == "pending":

            st.info(
                "The scan is still processing. "
                "Check again later."
            )

        else:
            st.warning(scan_details["message"])

    # Heuristic findings
    st.subheader("Heuristic Analysis")

    st.metric(
        "Heuristic Risk Score",
        f"{report['risk_score']}/100",
    )

    findings = report["findings"]

    st.metric("Total Findings", len(findings))

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
        st.success("No heuristic rules were triggered.")

    # Extracted features
    with st.expander("View extracted URL features"):
        st.json(report["features"])

    # Export reports
    st.subheader("Export Security Report")

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
