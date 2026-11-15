
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
    page_title="PhishGuard | URL Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom PhishGuard Theme
st.markdown(
    """
    <style>
    /* Main application */
    .stApp {
        background-color: #0B1120;
        color: #E2E8F0;
    }

    /* Main content spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #263449;
    }

    /* Headings */
    h1, h2, h3 {
        color: #F8FAFC;
        font-weight: 700;
    }

    /* Body text */
    p, label, .stMarkdown {
        color: #CBD5E1;
    }

    
    div[data-testid="stMetric"] {
        background-color: #111C2E;
        border: 1px solid #263B53;
        padding: 18px;
        border-radius: 12px;
        transition: all 0.25s ease;
    }

    div[data-testid="stMetric"]:hover {
        border-color: #22C55E;
        box-shadow: 0 4px 16px rgba(34, 197, 94, 0.18);
        transform: translateY(-3px);
    }

    div[data-testid="stMetricLabel"] {
        color: #94A3B8;
    }

    div[data-testid="stMetricValue"] {
        color: #F8FAFC;
    }

    
    /* Containers and cards */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #111C2E;
        border: 1px solid #263B53;
        border-radius: 12px;
        transition: border-color 0.25s ease,
                    box-shadow 0.25s ease,
                    transform 0.25s ease;
    }

    div[data-testid="stVerticalBlockBorderWrapper"]:hover {
        border-color: #22C55E !important;
        box-shadow: 0 4px 16px rgba(34, 197, 94, 0.18);
        transform: translateY(-2px);
    }

    


    /* Buttons */
    .stButton > button {
        background-color: #16A34A;
        color: #FFFFFF;
        border: 1px solid #16A34A;
        border-radius: 9px;
        padding: 0.65rem 1.2rem;
        font-weight: 600;
        transition: all 0.2s ease;
    }

    
    .stButton > button:hover {
        background-color: #15803D;
        border-color: #4ADE80;
        color: #FFFFFF;
        box-shadow: 0 0 12px rgba(34, 197, 94, 0.45);
        transform: translateY(-2px);
    }


    /* URL input */
    .stTextInput input {
        background-color: #172337;
        color: #F8FAFC;
        border: 1px solid #334155;
        border-radius: 9px;
    }

    .stTextInput input:focus {
        border-color: #4ADE80;
        box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.25),
                    0 0 12px rgba(34, 197, 94, 0.15);
        outline: none;
        transition: all 0.2s ease;
    }

    

    /* Dividers */
    hr {
        border-color: #263449;
    }

    /* Progress bar */
    div[data-testid="stProgressBar"] > div > div {
        background-color: #22C55E;
    }

    /* Expander */
    details {
        background-color: #111C2E;
        border: 1px solid #263B53;
        border-radius: 10px;
    }

    /* Captions */
    .stCaption {
        color: #94A3B8;
    }

    /* Threat Intelligence card hover effect */
    div[data-testid="stVerticalBlockBorderWrapper"]:has(.st-key-threat_card) {
        transition: transform 0.25s ease,
                    box-shadow 0.25s ease,
                    border-color 0.25s ease;
    }

    div[data-testid="stVerticalBlockBorderWrapper"]:has(.st-key-threat_card):hover {
        border-color: #22C55E !important;
        box-shadow: 0 4px 16px rgba(34, 197, 94, 0.25);
        transform: translateY(-3px);
    }

    


    </style>
    """,
    unsafe_allow_html=True,
)


# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ PHISHGUARD")
    st.caption("URL THREAT INTELLIGENCE")

    st.divider()

    st.markdown("### Navigation")

    page = st.radio(
        "Go to",
        [
            "URL Scanner",
            "About PhishGuard",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    
    st.markdown("### System Status")

    st.markdown(
        """
        <div style="
            background-color: #123C32;
            border: 1px solid #166534;
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 8px;
            color: #86EFAC;
            font-size: 13px;
        ">
        ● Detection Engine Ready
        </div>

        <div style="
            background-color: #172B45;
            border: 1px solid #294766;
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 8px;
            color: #93C5FD;
            font-size: 13px;
        ">
            ● Google Safe Browsing
        </div>

        <div style="
            background-color: #172B45;
            border: 1px solid #294766;
            border-radius: 8px;
            padding: 10px;
            color: #93C5FD;
            font-size: 13px;
        ">
            ● URLScan.io Integration
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()

    st.caption("PhishGuard | Cybersecurity Project")




# Main Dashboard Header
st.markdown(
    """
<div style="background:linear-gradient(120deg,#172554,#0F766E);padding:30px;border-radius:14px;border:1px solid #256D70;margin-bottom:25px;">
<div style="color:#86EFAC;font-size:13px;font-weight:bold;letter-spacing:2px;">URL THREAT INTELLIGENCE PLATFORM</div>
<h1 style="color:#FFFFFF;margin:12px 0 8px 0;font-size:36px;">🛡️ PhishGuard</h1>
<p style="color:#D1FAE5;font-size:17px;margin-bottom:15px;">Detect suspicious URLs. Investigate threats. Make informed security decisions.</p>
<span style="background-color:#14532D;color:#BBF7D0;padding:7px 12px;border-radius:20px;font-size:12px;font-weight:bold;">● ANALYSIS ENGINE READY</span>
</div>
""",
    unsafe_allow_html=True,
)

st.caption(
    "A low risk score does not guarantee that a URL is safe."
)

# URL Scanner Card
with st.container(border=True):
    st.markdown("### 🔎 Suspicious URL Scanner")

    st.caption(
        "Enter a website URL below to check for suspicious "
        "patterns and known security threats."
    )

    url = st.text_input(
        "Website URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed",
    )

    analyze_clicked = st.button(
        "🛡️ Analyze URL",
        type="primary",
        use_container_width=True,
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
if analyze_clicked:

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
    st.header("🛡️ Security Risk Assessment")

    risk_score = assessment["risk_score"]
    risk_level = assessment["risk_level"]
    total_findings = len(report["findings"])

    # Three dashboard metric cards
    col1, col2, col3 = st.columns(3)

    with col1:
        with st.container(border=True):
            st.metric(
                "Overall Risk Score",
                f"{risk_score}/100",
            )

    with col2:
        with st.container(border=True):
            st.metric(
                "Risk Level",
                risk_level,
            )

    with col3:
        with st.container(border=True):
            st.metric(
                "Detection Findings",
                total_findings,
            )

    # Risk progress indicator
    st.markdown("#### Risk Score Indicator")
    st.progress(risk_score / 100)

    if risk_level == "Critical":
        st.error(f"🚨 CRITICAL RISK — {assessment['verdict']}")

    elif risk_level == "High":
        st.error(f"🔴 HIGH RISK — {assessment['verdict']}")

    elif risk_level == "Medium":
        st.warning(f"🟠 MEDIUM RISK — {assessment['verdict']}")

    else:
        st.success(f"🟢 LOW RISK — {assessment['verdict']}")

    st.caption(assessment["note"])

    # Evidence breakdown
    st.subheader("Threat Intelligence Sources")

    evidence_items = assessment["evidence"]
    columns = st.columns(3)

    for index, item in enumerate(evidence_items):

        with columns[index % 3]:

            
            with st.container(border=True, key=f"threat_card_{index}"):
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
                    st.caption(
                        "Threat types: "
                        + ", ".join(item["threat_types"])
                    )

                if item.get("categories"):
                    st.caption(
                        "Categories: "
                        + ", ".join(item["categories"])
                    )

                if item.get("urlscan_score") is not None:
                    st.write(
                        f"URLScan verdict score: "
                        f"{item['urlscan_score']}"
                    )

                if item.get("result_url"):
                    st.link_button(
                        "Open URLScan.io Report",
                        item["result_url"],
                        use_container_width=True,
                    )


   

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

    findings = report["findings"]

    # Heuristic metric cards
    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            st.metric(
                "Heuristic Risk Score",
                f"{report['risk_score']}/100",
            )

    with col2:
        with st.container(border=True):
            st.metric(
                "Total Findings",
                len(findings),
            )

    # Display individual findings
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
