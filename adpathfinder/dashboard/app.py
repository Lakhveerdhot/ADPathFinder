import json
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.express as px


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DATA_DIR = (
    PROJECT_ROOT / "data" / "processed"
)


st.set_page_config(
    page_title="ADPathFinder",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# DATA LOADING
# ============================================================

@st.cache_data
def load_json(filename):

    file_path = (
        PROCESSED_DATA_DIR / filename
    )

    if not file_path.exists():

        return None

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        return {
            "error": str(error)
        }


def get_data():

    return {

        "normalized":
            load_json("normalized_data.json"),

        "security_findings":
            load_json("security_findings.json"),

        "risk_report":
            load_json("risk_report.json"),

        "relationship_findings":
            load_json("relationship_findings.json"),

        "attack_paths":
            load_json("attack_paths.json"),

        "attack_path_risk":
            load_json("attack_path_risk_report.json"),

        "relationships":
            load_json("relationships.json"),

    }


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def extract_list(data, key):

    if not isinstance(data, dict):

        return []

    result = data.get(key, [])

    if isinstance(result, list):

        return result

    return []


def safe_number(value):

    try:

        return float(value)

    except (TypeError, ValueError):

        return 0


def get_severity_color(severity):

    colors = {

        "Critical": "#ff4b4b",

        "High": "#ff8700",

        "Medium": "#ffd43b",

        "Low": "#4dabf7",

        "Informational": "#868e96",

        "Minimal": "#51cf66",

    }

    return colors.get(
        severity,
        "#868e96"
    )


def display_status(message):

    st.info(message)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ ADPathFinder")

st.markdown(
    """
    ### Active Directory Security Analysis Platform

    Analyze Active Directory objects, security findings,
    relationships, attack paths, and risk priorities.
    """
)


data = get_data()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ ADPathFinder")

st.sidebar.markdown(
    "Security Analysis Dashboard"
)


page = st.sidebar.radio(

    "Navigation",

    [

        "Overview",

        "Security Findings",

        "Attack Paths",

        "Risk Analysis",

        "Directory Explorer",

    ]

)


st.sidebar.divider()


if st.sidebar.button(
    "🔄 Refresh Data",
    use_container_width=True
):

    st.cache_data.clear()

    st.rerun()


st.sidebar.markdown(
    """
    **Data Source**

    Local processed JSON reports
    """
)


# ============================================================
# DATA EXTRACTION
# ============================================================

normalized_data = data.get(
    "normalized"
) or {}


users = extract_list(
    normalized_data,
    "users"
)


groups = extract_list(
    normalized_data,
    "groups"
)


computers = extract_list(
    normalized_data,
    "computers"
)


ous = extract_list(
    normalized_data,
    "ous"
)


security_findings_data = (
    data.get("security_findings")
    or {}
)


security_findings = extract_list(
    security_findings_data,
    "findings"
)


risk_report = (
    data.get("risk_report")
    or {}
)


relationship_findings_data = (
    data.get("relationship_findings")
    or {}
)


relationship_findings = extract_list(
    relationship_findings_data,
    "findings"
)


attack_paths_data = (
    data.get("attack_paths")
    or {}
)


attack_paths = extract_list(
    attack_paths_data,
    "attack_paths"
)


attack_path_risk_data = (
    data.get("attack_path_risk")
    or {}
)


prioritized_attack_paths = extract_list(
    attack_path_risk_data,
    "prioritized_attack_paths"
)


attack_path_summary = (
    attack_path_risk_data.get(
        "summary",
        {}
    )
)


# ============================================================
# OVERVIEW PAGE
# ============================================================

if page == "Overview":

    st.header("Security Overview")


    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.metric(
            "Users",
            len(users)
        )


    with col2:

        st.metric(
            "Groups",
            len(groups)
        )


    with col3:

        st.metric(
            "Security Findings",
            len(security_findings)
        )


    with col4:

        st.metric(
            "Attack Paths",
            len(attack_paths)
        )


    st.divider()


    # --------------------------------------------------------
    # RISK METRICS
    # --------------------------------------------------------

    st.subheader(
        "Overall Security Risk"
    )


    risk_score = safe_number(
        risk_report.get(
            "total_score",
            risk_report.get(
                "risk_score",
                0
            )
        )
    )


    risk_level = risk_report.get(
        "risk_level",
        risk_report.get(
            "overall_risk",
            "Unknown"
        )
    )


    col1, col2, col3 = st.columns(3)


    with col1:

        st.metric(
            "Risk Score",
            risk_score
        )


    with col2:

        st.metric(
            "Risk Level",
            risk_level
        )


    with col3:

        st.metric(
            "High-Risk Attack Paths",
            attack_path_summary.get(
                "high_risk_paths",
                0
            )
        )


    st.divider()


    # --------------------------------------------------------
    # FINDINGS CHART
    # --------------------------------------------------------

    st.subheader(
        "Security Findings by Severity"
    )


    severity_counts = {}


    for finding in security_findings:

        severity = finding.get(
            "severity",
            "Unknown"
        )


        severity_counts[severity] = (
            severity_counts.get(
                severity,
                0
            ) + 1
        )


    if severity_counts:

        severity_df = pd.DataFrame(

            {

                "Severity":
                    list(severity_counts.keys()),

                "Count":
                    list(severity_counts.values()),

            }

        )


        fig = px.bar(

            severity_df,

            x="Severity",

            y="Count",

            color="Severity",

            color_discrete_map={

                "Critical": "#ff4b4b",

                "High": "#ff8700",

                "Medium": "#ffd43b",

                "Low": "#4dabf7",

                "Informational": "#868e96",

            },

            title="Finding Distribution"

        )


        fig.update_layout(
            showlegend=False
        )


        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        display_status(
            "No security findings available."
        )


    # --------------------------------------------------------
    # ATTACK PATH DISTRIBUTION
    # --------------------------------------------------------

    st.subheader(
        "Attack Path Risk Distribution"
    )


    path_risk_counts = {}


    for path in prioritized_attack_paths:

        risk = path.get(
            "risk_level",
            "Unknown"
        )


        path_risk_counts[risk] = (
            path_risk_counts.get(
                risk,
                0
            ) + 1
        )


    if path_risk_counts:

        path_df = pd.DataFrame(

            {

                "Risk Level":
                    list(path_risk_counts.keys()),

                "Paths":
                    list(path_risk_counts.values()),

            }

        )


        fig = px.pie(

            path_df,

            names="Risk Level",

            values="Paths",

            title="Attack Path Risk Levels",

            hole=0.4,

        )


        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        display_status(
            "No prioritized attack paths available."
        )


    # --------------------------------------------------------
    # TOP ATTACK PATHS
    # --------------------------------------------------------

    st.subheader(
        "Top Prioritized Attack Paths"
    )


    if prioritized_attack_paths:

        top_paths = prioritized_attack_paths[:5]


        for index, path in enumerate(
            top_paths,
            start=1
        ):

            risk_level = path.get(
                "risk_level",
                "Unknown"
            )


            with st.expander(

                f"#{index} | "
                f"{path.get('source_user')} → "
                f"{path.get('target_group')} | "
                f"{risk_level} | "
                f"Score: {path.get('risk_score', 0)}"

            ):

                st.write(
                    "**Attack Path:**"
                )


                path_nodes = path.get(
                    "path",
                    []
                )


                st.code(
                    " → ".join(path_nodes)
                )


                st.write(
                    "**Risk Breakdown:**"
                )


                st.json(
                    path.get(
                        "risk_breakdown",
                        {}
                    )
                )

    else:

        display_status(
            "No attack paths discovered."
        )


# ============================================================
# SECURITY FINDINGS PAGE
# ============================================================

elif page == "Security Findings":

    st.header(
        "Security Findings"
    )


    if not security_findings:

        display_status(
            "No security findings available."
        )


    else:

        findings_df = pd.DataFrame(
            security_findings
        )


        # ----------------------------------------------------
        # FILTERS
        # ----------------------------------------------------

        available_severities = sorted(

            findings_df["severity"]
            .dropna()
            .unique()
            .tolist()

            if "severity" in findings_df.columns

            else []

        )


        selected_severities = st.multiselect(

            "Filter by Severity",

            available_severities,

            default=available_severities

        )


        if "severity" in findings_df.columns:

            filtered_df = findings_df[
                findings_df["severity"].isin(
                    selected_severities
                )
            ]

        else:

            filtered_df = findings_df


        st.dataframe(

            filtered_df,

            use_container_width=True,

            hide_index=True

        )


        st.subheader(
            "Finding Details"
        )


        for index, finding in enumerate(
            filtered_df.to_dict(
                orient="records"
            ),
            start=1
        ):


            severity = finding.get(
                "severity",
                "Unknown"
            )


            with st.expander(

                f"{index}. "
                f"{finding.get('title', 'Finding')} "
                f"[{severity}]"

            ):


                st.write(
                    finding.get(
                        "description",
                        "No description available."
                    )
                )


                st.markdown(
                    "**Affected Object**"
                )


                st.write(
                    finding.get(
                        "affected_object",
                        "Unknown"
                    )
                )


                st.markdown(
                    "**Recommendation**"
                )


                st.write(
                    finding.get(
                        "recommendation",
                        "No recommendation available."
                    )
                )


# ============================================================
# ATTACK PATHS PAGE
# ============================================================

elif page == "Attack Paths":

    st.header(
        "Attack Path Analysis"
    )


    st.markdown(
        """
        Identify users who have membership relationships
        leading to privileged Active Directory groups.
        """
    )


    if not prioritized_attack_paths:

        display_status(
            "No prioritized attack paths available."
        )


    else:

        col1, col2, col3, col4 = st.columns(4)


        with col1:

            st.metric(
                "Total Paths",
                attack_path_summary.get(
                    "total_attack_paths",
                    len(prioritized_attack_paths)
                )
            )


        with col2:

            st.metric(
                "Critical",
                attack_path_summary.get(
                    "critical_paths",
                    0
                )
            )


        with col3:

            st.metric(
                "High",
                attack_path_summary.get(
                    "high_risk_paths",
                    0
                )
            )


        with col4:

            st.metric(
                "Medium",
                attack_path_summary.get(
                    "medium_risk_paths",
                    0
                )
            )


        st.divider()


        # ----------------------------------------------------
        # ATTACK PATH TABLE
        # ----------------------------------------------------

        path_table = []


        for path in prioritized_attack_paths:

            path_table.append({

                "Source User":
                    path.get("source_user"),

                "Username":
                    path.get("source_username"),

                "Target Group":
                    path.get("target_group"),

                "Risk Score":
                    path.get("risk_score"),

                "Risk Level":
                    path.get("risk_level"),

                "Path Length":
                    path.get("path_length"),

            })


        st.dataframe(

            pd.DataFrame(path_table),

            use_container_width=True,

            hide_index=True

        )


        st.subheader(
            "Attack Path Details"
        )


        for index, path in enumerate(
            prioritized_attack_paths,
            start=1
        ):


            with st.expander(

                f"Attack Path #{index} | "
                f"{path.get('risk_level')} | "
                f"Score: {path.get('risk_score')}"

            ):


                st.markdown(
                    f"**Source User:** "
                    f"{path.get('source_user')}"
                )


                st.markdown(
                    f"**Username:** "
                    f"{path.get('source_username')}"
                )


                st.markdown(
                    f"**Target Group:** "
                    f"{path.get('target_group')}"
                )


                st.markdown(
                    f"**Risk Score:** "
                    f"{path.get('risk_score')}"
                )


                st.markdown(
                    f"**Risk Level:** "
                    f"{path.get('risk_level')}"
                )


                st.markdown(
                    "**Path Visualization**"
                )


                st.code(
                    " → ".join(
                        path.get(
                            "path",
                            []
                        )
                    )
                )


                st.markdown(
                    "**Risk Breakdown**"
                )


                st.json(
                    path.get(
                        "risk_breakdown",
                        {}
                    )
                )


# ============================================================
# RISK ANALYSIS PAGE
# ============================================================

elif page == "Risk Analysis":

    st.header(
        "Risk Analysis"
    )


    # --------------------------------------------------------
    # OVERALL RISK
    # --------------------------------------------------------

    st.subheader(
        "Overall Domain Risk"
    )


    col1, col2 = st.columns(2)


    with col1:

        st.metric(
            "Total Risk Score",
            risk_report.get(
                "total_score",
                risk_report.get(
                    "risk_score",
                    0
                )
            )
        )


    with col2:

        st.metric(
            "Risk Classification",
            risk_report.get(
                "risk_level",
                risk_report.get(
                    "overall_risk",
                    "Unknown"
                )
            )
        )


    st.divider()


    # --------------------------------------------------------
    # FINDINGS BY SEVERITY
    # --------------------------------------------------------

    st.subheader(
        "Finding Severity Distribution"
    )


    if security_findings:

        severity_counts = {}


        for finding in security_findings:

            severity = finding.get(
                "severity",
                "Unknown"
            )


            severity_counts[severity] = (
                severity_counts.get(
                    severity,
                    0
                ) + 1
            )


        severity_df = pd.DataFrame(

            {

                "Severity":
                    list(severity_counts.keys()),

                "Count":
                    list(severity_counts.values()),

            }

        )


        fig = px.bar(

            severity_df,

            x="Severity",

            y="Count",

            color="Severity",

            title="Security Findings"

        )


        st.plotly_chart(
            fig,
            use_container_width=True
        )


    # --------------------------------------------------------
    # ATTACK PATH RISK
    # --------------------------------------------------------

    st.subheader(
        "Attack Path Prioritization"
    )


    if prioritized_attack_paths:

        risk_df = pd.DataFrame(

            [

                {

                    "Source":
                        path.get("source_user"),

                    "Target":
                        path.get("target_group"),

                    "Score":
                        path.get("risk_score"),

                    "Risk":
                        path.get("risk_level"),

                }

                for path in prioritized_attack_paths

            ]

        )


        st.dataframe(

            risk_df,

            use_container_width=True,

            hide_index=True

        )


    # --------------------------------------------------------
    # RISK REPORT DETAILS
    # --------------------------------------------------------

    st.subheader(
        "Risk Report Details"
    )


    st.json(
        risk_report
    )


# ============================================================
# DIRECTORY EXPLORER
# ============================================================

elif page == "Directory Explorer":

    st.header(
        "Active Directory Explorer"
    )


    tabs = st.tabs(

        [

            "Users",

            "Groups",

            "Computers",

            "Organizational Units",

        ]

    )


    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    with tabs[0]:

        st.subheader(
            "Users"
        )


        if users:

            users_df = pd.DataFrame(
                users
            )


            st.dataframe(

                users_df,

                use_container_width=True,

                hide_index=True

            )

        else:

            display_status(
                "No user data available."
            )


    # --------------------------------------------------------
    # GROUPS
    # --------------------------------------------------------

    with tabs[1]:

        st.subheader(
            "Groups"
        )


        if groups:

            groups_df = pd.DataFrame(
                groups
            )


            st.dataframe(

                groups_df,

                use_container_width=True,

                hide_index=True

            )

        else:

            display_status(
                "No group data available."
            )


    # --------------------------------------------------------
    # COMPUTERS
    # --------------------------------------------------------

    with tabs[2]:

        st.subheader(
            "Computers"
        )


        if computers:

            computers_df = pd.DataFrame(
                computers
            )


            st.dataframe(

                computers_df,

                use_container_width=True,

                hide_index=True

            )

        else:

            display_status(
                "No computer data available."
            )


    # --------------------------------------------------------
    # OUS
    # --------------------------------------------------------

    with tabs[3]:

        st.subheader(
            "Organizational Units"
        )


        if ous:

            ous_df = pd.DataFrame(
                ous
            )


            st.dataframe(

                ous_df,

                use_container_width=True,

                hide_index=True

            )

        else:

            display_status(
                "No organizational unit data available."
            )


# ============================================================
# FOOTER
# ============================================================

st.sidebar.divider()


st.sidebar.caption(
    "ADPathFinder"
)


st.sidebar.caption(
    "Active Directory Security Analysis"
)