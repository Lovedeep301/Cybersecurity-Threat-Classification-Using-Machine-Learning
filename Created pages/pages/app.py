import streamlit as st
import os
import pandas as pd
from utils.data_processor import DataProcessor
from utils.log_parser import LogParser
from utils.model import ThreatDetectionModel

# Set page configuration
st.set_page_config(
    page_title="Cybersecurity Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state variables if they don't exist
if 'data' not in st.session_state:
    st.session_state.data = None
if 'model' not in st.session_state:
    st.session_state.model = ThreatDetectionModel()
if 'predictions' not in st.session_state:
    st.session_state.predictions = None
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'trained' not in st.session_state:
    st.session_state.trained = False

# Main page
st.title("🛡️ Cybersecurity Threat Detection System")

# Introduction to the application
st.markdown("""
This application uses machine learning to detect potential cybersecurity threats from log files.
Use the sidebar to navigate between different sections of the application.

## Features:
- Upload and parse security logs from various formats
- Analyze potential threats with machine learning
- Visualize threat patterns and anomalies
- Train custom detection models
- Set up alerts for detected threats

## Getting Started:
1. Navigate to the **Data Upload** page to upload your security logs
2. Go to the **Threat Analysis** page to visualize and analyze threats
3. Use the **Model Training** page to train or improve detection models
4. Check the **Alerts** page to manage detected threat alerts
""")

# Display data statistics if data exists
if st.session_state.data is not None:
    st.subheader("Current Dataset Overview")
    data = st.session_state.data
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Logs", f"{len(data):,}")
    
    with col2:
        if 'is_threat' in data.columns and st.session_state.predictions is not None:
            threat_count = data[data['is_threat'] == 1].shape[0]
            st.metric("Detected Threats", f"{threat_count:,}")
        else:
            st.metric("Detected Threats", "Not analyzed yet")
    
    with col3:
        if 'timestamp' in data.columns:
            time_range = f"{data['timestamp'].min()} to {data['timestamp'].max()}"
            st.metric("Time Range", time_range)
        else:
            st.metric("Time Range", "N/A")

# Footer
st.markdown("---")
st.markdown("Cybersecurity Threat Detection System | Powered by Streamlit and Scikit-learn")
