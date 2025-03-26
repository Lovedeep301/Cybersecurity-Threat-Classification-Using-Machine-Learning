import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime

st.set_page_config(
    page_title="Alerts - Cybersecurity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🚨 Threat Alerts")

# Check if there are any alerts in the session state
if 'alerts' not in st.session_state or not st.session_state.alerts:
    st.warning("No alerts have been generated yet. Run threat detection in the Threat Analysis page.")
    
    # Add a button to go to the Threat Analysis page
    if st.button("Go to Threat Analysis"):
        # Use query parameter to navigate to the Threat Analysis page
        st.switch_page("pages/2_Threat_Analysis.py")
        
    st.stop()

alerts = st.session_state.alerts

# Convert alerts to DataFrame for easier manipulation
alerts_df = pd.DataFrame(alerts)

# Alert dashboard
st.subheader("Alert Dashboard")

# Alert metrics
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total Alerts", len(alerts_df))

with col2:
    if 'severity' in alerts_df.columns:
        high_severity = sum(alerts_df['severity'] == 'High')
        st.metric("High Severity Alerts", high_severity)

with col3:
    if 'threat_type' in alerts_df.columns:
        unique_threats = alerts_df['threat_type'].nunique()
        st.metric("Unique Threat Types", unique_threats)

# Alert filtering
st.subheader("Filter Alerts")

col1, col2 = st.columns(2)

with col1:
    if 'severity' in alerts_df.columns:
        selected_severity = st.multiselect(
            "Filter by Severity",
            options=sorted(alerts_df['severity'].unique()),
            default=sorted(alerts_df['severity'].unique())
        )
    else:
        selected_severity = None

with col2:
    if 'threat_type' in alerts_df.columns:
        selected_threat_types = st.multiselect(
            "Filter by Threat Type",
            options=sorted(alerts_df['threat_type'].unique()),
            default=sorted(alerts_df['threat_type'].unique())
        )
    else:
        selected_threat_types = None

# Apply filters
filtered_alerts = alerts_df
if selected_severity:
    filtered_alerts = filtered_alerts[filtered_alerts['severity'].isin(selected_severity)]
if selected_threat_types:
    filtered_alerts = filtered_alerts[filtered_alerts['threat_type'].isin(selected_threat_types)]

# Display filtered alerts
st.subheader("Current Alerts")

if filtered_alerts.empty:
    st.info("No alerts match the selected filters.")
else:
    # Sort alerts by timestamp (newest first) if available
    if 'timestamp' in filtered_alerts.columns:
        filtered_alerts = filtered_alerts.sort_values('timestamp', ascending=False)
    
    # Display alerts in an expandable format
    for i, alert in filtered_alerts.iterrows():
        with st.expander(f"{alert.get('threat_type', 'Unknown Threat')} - {alert.get('source_ip', 'Unknown Source')} - {alert.get('severity', 'Unknown Severity')}"):
            # Create a multi-column layout for alert details
            detail_col1, detail_col2 = st.columns(2)
            
            with detail_col1:
                st.markdown(f"**Time:** {alert.get('timestamp', 'Unknown')}")
                st.markdown(f"**Source IP:** {alert.get('source_ip', 'Unknown')}")
                st.markdown(f"**Threat Type:** {alert.get('threat_type', 'Unknown')}")
            
            with detail_col2:
                st.markdown(f"**Severity:** {alert.get('severity', 'Unknown')}")
                st.markdown(f"**Details:** {alert.get('details', 'No additional details')}")
            
            # Add action buttons
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("Mark as Resolved", key=f"resolve_{i}"):
                    st.session_state.alerts[i]['status'] = 'Resolved'
                    st.success("Alert marked as resolved!")
                    st.rerun()
            
            with col2:
                if st.button("Ignore", key=f"ignore_{i}"):
                    st.session_state.alerts[i]['status'] = 'Ignored'
                    st.info("Alert will be ignored.")
                    st.rerun()
            
            with col3:
                if st.button("Investigate", key=f"investigate_{i}"):
                    st.session_state.alerts[i]['status'] = 'Under Investigation'
                    st.info("Alert marked for investigation.")
                    st.rerun()

# Visualize alert data
if not filtered_alerts.empty:
    st.subheader("Alert Visualization")
    
    tab1, tab2, tab3 = st.tabs(["By Threat Type", "By Severity", "Timeline"])
    
    with tab1:
        if 'threat_type' in filtered_alerts.columns:
            # Group by threat type
            threat_type_counts = filtered_alerts['threat_type'].value_counts().reset_index()
            threat_type_counts.columns = ['Threat Type', 'Count']
            
            fig = px.pie(
                threat_type_counts,
                values='Count',
                names='Threat Type',
                title='Alerts by Threat Type',
                color_discrete_sequence=px.colors.sequential.Reds_r
            )
            st.plotly_chart(fig)
        else:
            st.info("Threat type data not available.")
    
    with tab2:
        if 'severity' in filtered_alerts.columns:
            # Group by severity
            severity_counts = filtered_alerts['severity'].value_counts().reset_index()
            severity_counts.columns = ['Severity', 'Count']
            
            # Order by severity level
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            if all(sev in severity_order for sev in severity_counts['Severity']):
                severity_counts['Order'] = severity_counts['Severity'].map(severity_order)
                severity_counts = severity_counts.sort_values('Order').drop('Order', axis=1)
            
            fig = px.bar(
                severity_counts,
                x='Severity',
                y='Count',
                title='Alerts by Severity',
                color='Severity',
                color_discrete_map={'Critical': 'darkred', 'High': 'red', 'Medium': 'orange', 'Low': 'yellow'}
            )
            st.plotly_chart(fig)
        else:
            st.info("Severity data not available.")
    
    with tab3:
        if 'timestamp' in filtered_alerts.columns:
            try:
                # Convert timestamp to datetime if not already
                if not pd.api.types.is_datetime64_any_dtype(filtered_alerts['timestamp']):
                    filtered_alerts['timestamp'] = pd.to_datetime(filtered_alerts['timestamp'])
                
                # Group by date
                filtered_alerts['date'] = filtered_alerts['timestamp'].dt.date
                date_counts = filtered_alerts.groupby('date').size().reset_index(name='count')
                
                fig = px.line(
                    date_counts,
                    x='date',
                    y='count',
                    title='Alert Timeline',
                    labels={'count': 'Number of Alerts', 'date': 'Date'}
                )
                st.plotly_chart(fig)
            except Exception as e:
                st.error(f"Error creating timeline: {str(e)}")
        else:
            st.info("Timestamp data not available.")

# Alert settings
st.markdown("---")
st.subheader("Alert Settings")

# Alert threshold setting
threshold = st.slider(
    "Alert Threshold (confidence score)",
    min_value=0.0,
    max_value=1.0,
    value=0.7,
    step=0.05,
    help="Only generate alerts for threats with confidence score above this threshold"
)

# Notification settings
st.markdown("### Notification Settings")
email_notifications = st.checkbox("Email Notifications", value=False)

if email_notifications:
    email_address = st.text_input("Email Address for Notifications")
    
    notification_options = st.multiselect(
        "Notify me about:",
        ["High Severity Alerts", "Medium Severity Alerts", "Low Severity Alerts", "All New Threats", "Daily Summary"],
        default=["High Severity Alerts"]
    )
    
    if st.button("Save Notification Settings"):
        st.success("Notification settings saved!")

# Clear alerts button
if st.button("Clear All Alerts"):
    st.session_state.alerts = []
    st.success("All alerts have been cleared.")
    st.rerun()

# Navigation hints
st.markdown("---")
st.info("💡 Tip: Return to the Threat Analysis page to run detection on new data.")
