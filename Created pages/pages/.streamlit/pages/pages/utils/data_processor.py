import pandas as pd
import numpy as np
import re
from datetime import datetime

class DataProcessor:
    """
    Processes security log data to extract relevant features for threat detection.
    """
    
    def __init__(self):
        # Known malicious IPs (in a real system, this would be loaded from a database or API)
        self.malicious_ips = [
            "192.168.1.5", 
            "10.0.0.99", 
            "172.16.0.1"
        ]
        
        # Suspicious ports
        self.suspicious_ports = [22, 23, 25, 3389, 445, 1433, 3306, 5432]
        
        # Suspicious user agents
        self.suspicious_user_agents = [
            "python-requests",
            "zgrab",
            "masscan",
            "nmap",
            "nikto"
        ]
    
    def process_logs(self, df, is_sample=False):
        """
        Process logs and extract features for threat detection.
        
        Args:
            df (pandas.DataFrame): DataFrame containing parsed log data
            is_sample (bool): Whether this is sample data
            
        Returns:
            pandas.DataFrame: DataFrame with extracted features
        """
        # Make a copy to avoid modifying the original
        processed_df = df.copy()
        
        # Extract time-based features if timestamp exists
        if 'timestamp' in processed_df.columns:
            # Convert timestamp to datetime if not already
            if not pd.api.types.is_datetime64_any_dtype(processed_df['timestamp']):
                try:
                    processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'])
                except:
                    # If conversion fails, keep as is
                    pass
            
            # Try to extract time features if conversion succeeded
            if pd.api.types.is_datetime64_any_dtype(processed_df['timestamp']):
                processed_df['hour_of_day'] = processed_df['timestamp'].dt.hour
                processed_df['day_of_week'] = processed_df['timestamp'].dt.dayofweek
                processed_df['is_weekend'] = processed_df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
                processed_df['is_night'] = processed_df['hour_of_day'].apply(lambda x: 1 if x < 6 or x > 22 else 0)
        
        # Process source IP features if available
        if 'source_ip' in processed_df.columns:
            # Check if IP is in known malicious list
            processed_df['is_known_malicious'] = processed_df['source_ip'].apply(
                lambda ip: 1 if ip in self.malicious_ips else 0
            )
            
            # Generate a synthetic reputation score for demonstration
            processed_df['ip_reputation_score'] = processed_df['source_ip'].apply(
                lambda ip: np.random.randint(0, 30) if ip in self.malicious_ips 
                           else np.random.randint(30, 100)
            )
        
        # Process port features if available
        if 'port' in processed_df.columns:
            processed_df['is_suspicious_port'] = processed_df['port'].apply(
                lambda p: 1 if p in self.suspicious_ports else 0
            )
        
        # Process user agent features if available
        if 'user_agent' in processed_df.columns:
            processed_df['is_suspicious_agent'] = processed_df['user_agent'].apply(
                lambda ua: 1 if any(agent in str(ua).lower() for agent in self.suspicious_user_agents) else 0
            )
        
        # Process login attempt features if available
        if 'event_type' in processed_df.columns and 'status' in processed_df.columns:
            # Group by source_ip and count failed login attempts
            if 'source_ip' in processed_df.columns:
                failed_logins = processed_df[
                    (processed_df['event_type'] == 'LOGIN') & 
                    (processed_df['status'] == 'FAILURE')
                ].groupby('source_ip').size().reset_index(name='failed_login_attempts')
                
                # Merge back to the main dataframe
                if not failed_logins.empty:
                    processed_df = pd.merge(
                        processed_df, 
                        failed_logins, 
                        on='source_ip', 
                        how='left'
                    )
                    processed_df['failed_login_attempts'] = processed_df['failed_login_attempts'].fillna(0)
        
        # Calculate data transfer anomalies if bytes field exists
        if 'bytes' in processed_df.columns:
            # Convert to numeric if not already
            if not pd.api.types.is_numeric_dtype(processed_df['bytes']):
                processed_df['bytes'] = pd.to_numeric(processed_df['bytes'], errors='coerce')
            
            # Calculate Z-score for bytes
            mean_bytes = processed_df['bytes'].mean()
            std_bytes = processed_df['bytes'].std()
            if std_bytes > 0:  # Avoid division by zero
                processed_df['bytes_zscore'] = (processed_df['bytes'] - mean_bytes) / std_bytes
                processed_df['is_data_anomaly'] = processed_df['bytes_zscore'].apply(
                    lambda z: 1 if abs(z) > 2.5 else 0
                )
        
        # For sample data, add some threat labels for demonstration
        if is_sample:
            # Label about 10% of the data as threats randomly
            processed_df['is_threat'] = np.random.choice(
                [0, 1], 
                size=len(processed_df), 
                p=[0.9, 0.1]  # 10% chance of being a threat
            )
            
            # Make some threats more likely based on features
            if 'is_suspicious_port' in processed_df.columns:
                mask = processed_df['is_suspicious_port'] == 1
                processed_df.loc[mask, 'is_threat'] = np.random.choice(
                    [0, 1], 
                    size=mask.sum(), 
                    p=[0.6, 0.4]  # 40% chance of being a threat if using suspicious port
                )
            
            if 'is_known_malicious' in processed_df.columns:
                mask = processed_df['is_known_malicious'] == 1
                processed_df.loc[mask, 'is_threat'] = np.random.choice(
                    [0, 1], 
                    size=mask.sum(), 
                    p=[0.2, 0.8]  # 80% chance of being a threat if from known malicious IP
                )
            
            if 'is_data_anomaly' in processed_df.columns:
                mask = processed_df['is_data_anomaly'] == 1
                processed_df.loc[mask, 'is_threat'] = np.random.choice(
                    [0, 1], 
                    size=mask.sum(), 
                    p=[0.3, 0.7]  # 70% chance of being a threat if data anomaly
                )
        else:
            # For real data, initialize with zeros if is_threat doesn't exist
            if 'is_threat' not in processed_df.columns:
                processed_df['is_threat'] = 0
        
        return processed_df
