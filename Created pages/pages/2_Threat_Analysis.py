import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from utils.model import ThreatDetectionModel
from utils.visualizations import create_threat_heatmap, create_timeline_chart

st.set_page_config(
    page_title="Threat Analysis - Cybersecurity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🔍 Threat Analysis")

# Check if data exists in session state
if st.session_state.data is None:
    st.warning("No data available. Please upload security logs in the Data Upload page.")
    st.stop()

data = st.session_state.data

# Run threat detection if predictions don't exist yet
if st.session_state.predictions is None:
    st.info("Running threat detection on your data...")
    
    with st.spinner("Analyzing threats..."):
        # If model is not trained yet, use default model
        if not st.session_state.trained:
            predictions = st.session_state.model.predict(data)
        else:
            # Use the trained model for predictions
            predictions = st.session_state.model.predict(data)
        
        # Add predictions to the dataframe
        data['is_threat'] = predictions
        
        # Detect threat types based on features
        threat_types = []
        
        for idx, row in data.iterrows():
            if row['is_threat'] == 1:
                # Simple rule-based threat classification
                if 'failed_login_attempts' in data.columns and row['failed_login_attempts'] > 3:
                    threat_type = "Brute Force"
                elif 'port' in data.columns and row['port'] in [22, 23, 3389]:
                    threat_type = "Suspicious Remote Access"
                elif 'bytes' in data.columns and row['bytes'] > data['bytes'].quantile(0.95):
                    threat_type = "Data Exfiltration"
                elif 'ip_reputation_score' in data.columns and row['ip_reputation_score'] < 30:
                    threat_type = "Malicious IP"
                else:
                    threat_type = "Anomalous Activity"
            else:
                threat_type = "None"
            
            threat_types.append(threat_type)
        
        data['threat_type'] = threat_types
        
        # Update session state
        st.session_state.predictions = predictions
        st.session_state.data = data
        
        # Create alerts for significant threats
        new_alerts = []
        threat_data = data[data['is_threat'] == 1]
        
        for idx, row in threat_data.iterrows():
            alert = {
                'timestamp': row.get('timestamp', 'Unknown'),
                'source_ip': row.get('source_ip', 'Unknown'),
                'threat_type': row['threat_type'],
                'severity': 'High' if row['threat_type'] in ['Brute Force', 'Data Exfiltration'] else 'Medium',
                'details': f"Detected {row['threat_type']} from {row.get('source_ip', 'Unknown')}"
            }
            new_alerts.append(alert)
        
        # Add new alerts to existing ones
        st.session_state.alerts.extend(new_alerts)

st.subheader("Threat Detection Results")

# Display metrics
col1, col2, col3 = st.columns(3)

with col1:
    total_threats = data['is_threat'].sum()
    st.metric("Total Threats Detected", f"{total_threats:,}")

with col2:
    threat_percentage = (total_threats / len(data)) * 100
    st.metric("Threat Percentage", f"{threat_percentage:.2f}%")

with col3:
    if 'threat_type' in data.columns:
        most_common_threat = data[data['is_threat'] == 1]['threat_type'].value_counts().idxmax() \
            if total_threats > 0 else "None"
        st.metric("Most Common Threat", most_common_threat)

# Threat type distribution
if total_threats > 0 and 'threat_type' in data.columns:
    st.subheader("Threat Type Distribution")
    
    threat_counts = data[data['is_threat'] == 1]['threat_type'].value_counts().reset_index()
    threat_counts.columns = ['Threat Type', 'Count']
    
    fig = px.pie(
        threat_counts, 
        values='Count', 
        names='Threat Type',
        title='Distribution of Threat Types',
        color_discrete_sequence=px.colors.sequential.Reds_r
    )
    st.plotly_chart(fig)

# Create tabs for different visualizations
tab1, tab2, tab3 = st.tabs(["Timeline Analysis", "Source IP Analysis", "Detailed Threat Data"])

with tab1:
    st.subheader("Threat Timeline Analysis")
    
    if 'timestamp' in data.columns:
        # Create timeline chart
        timeline_chart = create_timeline_chart(data)
        st.plotly_chart(timeline_chart, use_container_width=True)
    else:
        st.warning("Timeline analysis requires timestamp data which is not available.")

with tab2:
    st.subheader("Source IP Analysis")
    
    if 'source_ip' in data.columns:
        # Group by source IP and count threats
        ip_threats = data.groupby('source_ip')['is_threat'].sum().sort_values(ascending=False).reset_index()
        ip_threats.columns = ['Source IP', 'Threat Count']
        ip_threats = ip_threats[ip_threats['Threat Count'] > 0].head(10)
        
        if not ip_threats.empty:
            fig = px.bar(
                ip_threats,
                x='Source IP',
                y='Threat Count',
                title='Top 10 Source IPs by Threat Count',
                color='Threat Count',
                color_continuous_scale='reds'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # IP threat heatmap if geographical data exists
            st.subheader("IP Threat Heatmap")
            st.info("For a geographical heatmap, IP geolocation data would be required. In a real implementation, this would show a world map with threat hotspots.")
        else:
            st.info("No threats detected from any source IP.")
    else:
        st.warning("Source IP analysis requires source_ip data which is not available.")

with tab3:
    st.subheader("Detailed Threat Data")
    
    # Filter to show only threats or all data
    show_only_threats = st.checkbox("Show Only Threats", value=True)
    
    if show_only_threats:
        filtered_data = data[data['is_threat'] == 1]
    else:
        filtered_data = data
    
    if not filtered_data.empty:
        st.dataframe(filtered_data)
        
        # Option to download the data
        csv = filtered_data.to_csv(index=False)
        st.download_button(
            label="Download Threat Data as CSV",
            data=csv,
            file_name="threat_detection_results.csv",
            mime="text/csv",
        )
    else:
        st.info("No threats detected in the current dataset.")

# Navigation hints
st.markdown("---")
st.info("💡 Tip: Go to the Model Training page to train a more accurate threat detection model.")
