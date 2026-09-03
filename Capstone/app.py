"""
Vulnerability Management Data Warehouse: Unified Dashboard & 3D OLAP Cube
"""

import engine
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Vulnerability Warehouse & OLAP Engine",
    page_icon="🛡️",
    layout="wide",
)

engine.init_warehouse()

# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------
with st.sidebar:
    st.header("⚡ Scanner Orchestration")
    target_ip = st.text_input("Target IP Address", value="172.23.29.95")

    if st.button(
        "🚀 Run Real Nmap & Vuln Scan", type="primary", use_container_width=True
    ):
        with st.spinner(f"Executing Live Scan on {target_ip}..."):
            try:
                scan_uuid, scan_key, total_found = engine.execute_pipeline(
                    target_ip
                )
                st.session_state["active_scan_key"] = scan_key
                st.success(
                    f"Scan Completed: {scan_uuid} ({total_found} findings)"
                )
                st.rerun()
            except Exception as e:
                st.error(f"Scan failed: {e}")

    st.divider()
    st.subheader("📁 BI Sync Status")
    st.caption(
        "Files synced in `powerbi_exports/`. Ready for Power BI & Tableau."
    )

# ---------------------------------------------------------
# MAIN DASHBOARD
# ---------------------------------------------------------
st.title("🛡️ Vulnerability Management Data Warehouse")
st.caption(
    "Star Schema DW • Contextual Risk Prioritizer • Integrated 3D OLAP Cube"
)

# Fetch latest scan if available
conn = engine.get_db()
latest_scan = conn.cursor().execute(
    "SELECT MAX(scan_key) FROM fact_vulnerability"
).fetchone()[0]
conn.close()

active_scan_key = st.session_state.get("active_scan_key", latest_scan)

if active_scan_key is None:
    st.info(
        "👋 **Data warehouse ready.** Click **'🚀 Run Real Nmap & Vuln Scan'**"
        " in the sidebar to populate the warehouse."
    )
else:
    query = f"""
    SELECT 
        f.fact_id,
        a.ip_address,
        a.hostname,
        a.criticality_tier,
        v.cve_id,
        v.vuln_name,
        v.cvss_v3_base,
        f.contextual_risk_score,
        f.patch_priority_index,
        f.estimated_remediation_hours
    FROM fact_vulnerability f
    JOIN dim_asset a ON f.asset_key = a.asset_key
    JOIN dim_vulnerability v ON f.vuln_key = v.vuln_key
    WHERE f.scan_key = {active_scan_key}
    ORDER BY f.patch_priority_index DESC;
    """
    conn = engine.get_db()
    df = pd.read_sql(query, conn)
    conn.close()

    if df.empty:
        st.warning("No findings recorded for this scan. Run a new scan from the sidebar.")
    else:
        # TOP KPI CARDS
        total_baseline_risk = df["contextual_risk_score"].sum()
        avg_crs = df["contextual_risk_score"].mean()
        total_hours = df["estimated_remediation_hours"].sum()
        total_findings = len(df)

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Active Findings", total_findings)
        k2.metric("Scan Baseline Risk", f"{total_baseline_risk:.2f}")
        k3.metric("Avg Contextual Risk", f"{avg_crs:.2f}")
        k4.metric("Remediation Effort", f"{total_hours:.1f} hrs")

        st.divider()

        # OPERATIONAL ANALYTICS & WHAT-IF SIMULATOR
        c_left, c_right = st.columns([1.2, 1])
        with c_left:
            st.subheader("📊 Contextual Risk vs. CVSS Divergence")
            fig_scatter = px.scatter(
                df,
                x="cvss_v3_base",
                y="contextual_risk_score",
                color="criticality_tier",
                size="patch_priority_index",
                hover_data=["cve_id", "hostname", "ip_address"],
                labels={
                    "cvss_v3_base": "CVSS v3 Base",
                    "contextual_risk_score": "Contextual Risk Score",
                },
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

        with c_right:
            st.subheader("🧪 Live What-If Patch Simulator")
            all_cves = df["cve_id"].unique().tolist()
            selected_patches = st.multiselect(
                "Select CVEs to Remediate:",
                options=all_cves,
                default=all_cves[:1] if all_cves else [],
            )

            patched_df = df[df["cve_id"].isin(selected_patches)]
            risk_eliminated = patched_df["contextual_risk_score"].sum()
            residual_risk = total_baseline_risk - risk_eliminated
            pct_reduced = (
                (risk_eliminated / total_baseline_risk * 100)
                if total_baseline_risk > 0
                else 0
            )

            s1, s2 = st.columns(2)
            s1.metric(
                "Residual Risk",
                f"{residual_risk:.2f}",
                delta=f"-{pct_reduced:.1f}%",
                delta_color="inverse",
            )
            s2.metric("Risk Eliminated", f"{risk_eliminated:.2f}")

            fig_gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=residual_risk,
                    title={"text": "Residual Enterprise Risk"},
                    gauge={
                        "axis": {
                            "range": [0, max(100.0, total_baseline_risk)]
                        },
                        "bar": {
                            "color": (
                                "#2ecc71" if pct_reduced > 50 else "#e67e22"
                            )
                        },
                    },
                )
            )
            fig_gauge.update_layout(
                height=220, margin=dict(l=20, r=20, t=30, b=20)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        st.divider()

        # INTEGRATED 3D OLAP CUBE
        st.subheader("🧊 Multidimensional 3D OLAP Cube")
        st.caption(
            "Aggregating facts across three dimensions: **Asset Criticality"
            " Tier (X)**, **Vulnerability Severity (Y)**, and **Network Zone"
            " (Z)**."
        )

        df_cube = engine.get_olap_cube_data(active_scan_key)

        if not df_cube.empty:
            col_cube_visual, col_cube_table = st.columns([1.3, 1])

            with col_cube_visual:
                fig_3d = go.Figure()
                fig_3d.add_trace(
                    go.Scatter3d(
                        x=df_cube["Asset_Tier"],
                        y=df_cube["Vuln_Severity"],
                        z=df_cube["Network_Zone"],
                        mode="markers+text",
                        marker=dict(
                            size=df_cube["Sum_Contextual_Risk"] / 4,
                            color=df_cube["Sum_Contextual_Risk"],
                            colorscale="Turbo",
                            showscale=True,
                            colorbar=dict(
                                title=dict(
                                    text="Risk Score",
                                    font=dict(color="#FFFFFF", size=13),
                                ),
                                thickness=15,
                                len=0.7,
                                tickfont=dict(color="#FFFFFF"),
                            ),
                            opacity=0.95,
                            line=dict(width=2, color="#FFFFFF"),
                        ),
                        text=df_cube["Sum_Contextual_Risk"].apply(
                            lambda v: f"Risk: {v}"
                        ),
                        textposition="top center",
                        textfont=dict(color="#00FFAA", size=12),
                        hovertemplate=(
                            "<b>Asset Tier:</b> %{x}<br>"
                            "<b>Severity:</b> %{y}<br>"
                            "<b>Zone:</b> %{z}<br>"
                            "<b>Total Findings:</b> %{customdata[0]}<br>"
                            "<b>Sum Risk Score:</b> %{customdata[1]}<br>"
                            "<b>Avg Risk Score:</b> %{customdata[2]}<br>"
                            "<b>Remediation Backlog:</b> %{customdata[3]} hrs"
                            "<extra></extra>"
                        ),
                        customdata=df_cube[[
                            "Total_Findings",
                            "Sum_Contextual_Risk",
                            "Avg_Contextual_Risk",
                            "Total_Remediation_Hours",
                        ]].values,
                    )
                )

                fig_3d.update_layout(
                    height=480,
                    paper_bgcolor="#0e1117",
                    scene=dict(
                        bgcolor="#161b22",
                        xaxis=dict(
                            title=dict(
                                text="<b>X: Asset Tier</b>",
                                font=dict(color="#00FFAA"),
                            ),
                            tickfont=dict(color="#FFFFFF"),
                            gridcolor="#30363d",
                        ),
                        yaxis=dict(
                            title=dict(
                                text="<b>Y: Vuln Severity</b>",
                                font=dict(color="#FF7B72"),
                            ),
                            tickfont=dict(color="#FFFFFF"),
                            gridcolor="#30363d",
                        ),
                        zaxis=dict(
                            title=dict(
                                text="<b>Z: Network Zone</b>",
                                font=dict(color="#58A6FF"),
                            ),
                            tickfont=dict(color="#FFFFFF"),
                            gridcolor="#30363d",
                        ),
                        camera=dict(eye=dict(x=1.7, y=1.7, z=1.2)),
                    ),
                    margin=dict(l=0, r=0, b=0, t=10),
                )
                st.plotly_chart(fig_3d, use_container_width=True)

            with col_cube_table:
                st.markdown("**OLAP Cell Aggregation Matrix**")
                st.dataframe(
                    df_cube[[
                        "Asset_Tier",
                        "Network_Zone",
                        "Vuln_Severity",
                        "Total_Findings",
                        "Sum_Contextual_Risk",
                        "Total_Remediation_Hours",
                    ]],
                    height=440,
                    use_container_width=True,
                )

        st.divider()

        # RANKED ACTION TABLE
        st.subheader("📋 Ranked Remediation Queue (Patch Priority Index)")
        st.dataframe(df, use_container_width=True)