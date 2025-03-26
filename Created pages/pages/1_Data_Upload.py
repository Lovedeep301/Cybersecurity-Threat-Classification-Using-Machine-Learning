import streamlit as st
import pandas as pd
import io
import os
from utils.log_parser import LogParser
from utils.data_processor import DataProcessor

st.set_page_config(
    page_title="Data Upload - Cybersecurity Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("📤 Upload Security Logs")

# Description of the page functionality
st.markdown("""
Upload your security log files for analysis. The system supports various common log formats:
- Apache/Nginx access logs
- Windows Event logs
- Firewall logs
- IDS/IPS logs
- Authentication logs

The system will automatically detect the format and extract relevant features for threat detection.
""")

# Create a file uploader
uploaded_file = st.file_uploader("Choose a log file", type=['log', 'txt', 'csv'])

# Sample selector for predefined log formats
log_format = st.selectbox(
    "Select log format (if auto-detection fails)",
    [
        "Auto-detect",
        "Apache/Nginx Access Logs", 
        "Windows Event Logs", 
        "Firewall Logs", 
        "IDS/IPS Logs", 
        "Authentication Logs",
        "Custom"
    ]
)

# If custom format is selected, show additional options
if log_format == "Custom":
    st.info("For custom log formats, provide a regular expression pattern to match your log entries.")
    regex_pattern = st.text_input("Regex pattern for log parsing", 
                                 value=r'(?P<timestamp>\S+) (?P<source_ip>\S+) (?P<event>\S+) (?P<details>.*)')
    st.code(regex_pattern, language="text")
    
    st.markdown("Example custom log format:")
    st.code("2023-06-12T15:43:12 192.168.1.5 LOGIN_ATTEMPT Failed password for user admin", language="text")

# Process the uploaded file
if uploaded_file is not None:
    try:
        # Read the file content
        file_content = uploaded_file.read().decode('utf-8')
        
        with st.spinner('Processing log file...'):
            # Parse logs based on format
            log_parser = LogParser()
            
            if log_format == "Auto-detect":
                df = log_parser.parse_logs(file_content)
            elif log_format == "Custom":
                df = log_parser.parse_custom_logs(file_content, regex_pattern)
            else:
                df = log_parser.parse_logs(file_content, log_format)
            
            # Process data to extract features
            data_processor = DataProcessor()
            processed_df = data_processor.process_logs(df)
            
            # Store processed data in session state
            st.session_state.data = processed_df
            # Reset previous predictions and trained status
            st.session_state.predictions = None
            st.session_state.trained = False
            
            # Display preview of the processed data
            st.subheader("Preview of Processed Data")
            st.dataframe(processed_df.head(10))
            
            # Display statistics about the data
            st.subheader("Data Statistics")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Log Entries", f"{len(processed_df):,}")
            
            with col2:
                if 'source_ip' in processed_df.columns:
                    unique_sources = processed_df['source_ip'].nunique()
                    st.metric("Unique Source IPs", f"{unique_sources:,}")
            
            with col3:
                if 'event_type' in processed_df.columns:
                    unique_events = processed_df['event_type'].nunique()
                    st.metric("Unique Event Types", f"{unique_events:,}")
            
            # Success message
            st.success(f"Successfully processed {len(processed_df):,} log entries!")
            
            # Navigation hint
            st.info("Now proceed to the Threat Analysis page to analyze potential threats.")
    
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        st.session_state.data = None

# Option to use sample data
st.markdown("---")
if st.button("Load Sample Security Logs"):
    with st.spinner('Loading sample data...'):
        # Create sample data
        sample_data = {
            'timestamp': pd.date_range(start='2023-01-01', periods=100, freq='H'),
            'source_ip': ['192.168.1.' + str(i % 20) for i in range(100)],
            'destination_ip': ['10.0.0.' + str(i % 15) for i in range(100)],
            'port': [(i % 5) * 1000 + 22 for i in range(100)],
            'protocol': ['TCP' if i % 3 else 'UDP' for i in range(100)],
            'event_type': ['LOGIN' if i % 5 == 0 else 
                          'ACCESS' if i % 5 == 1 else 
                          'DOWNLOAD' if i % 5 == 2 else 
                          'UPLOAD' if i % 5 == 3 else 'CONFIG' 
                          for i in range(100)],
            'status': ['SUCCESS' if i % 4 != 0 else 'FAILURE' for i in range(100)],
            'bytes': [i * 100 for i in range(100)],
            'duration': [(i % 10) * 2.5 for i in range(100)]
        }
        
        # Create DataFrame from sample data
        df = pd.DataFrame(sample_data)
        
        # Process the data to extract features
        data_processor = DataProcessor()
        processed_df = data_processor.process_logs(df, is_sample=True)
        
        # Store processed data in session state
        st.session_state.data = processed_df
        st.session_state.predictions = None
        st.session_state.trained = False
        
        # Display preview
        st.subheader("Preview of Sample Data")
        st.dataframe(processed_df.head(10))
        
        # Success message
        st.success("Sample data loaded successfully!")
        
        # Navigation hint
        st.info("Now proceed to the Threat Analysis page to analyze potential threats.")
