import pandas as pd
import re
from datetime import datetime
import io

class LogParser:
    """
    Parses various security log formats into structured data for analysis.
    """
    
    def __init__(self):
        # Regular expressions for different log formats
        self.apache_pattern = r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        
        self.windows_event_pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<source>\S+) (?P<event_id>\d+) (?P<message>.*)'
        
        self.firewall_pattern = r'(?P<timestamp>\S+) (?P<action>\S+) (?P<source_ip>\S+):(?P<source_port>\d+) -> (?P<dest_ip>\S+):(?P<dest_port>\d+) (?P<protocol>\S+) (?P<info>.*)'
        
        self.auth_pattern = r'(?P<timestamp>\S+ \d+ \d+:\d+:\d+) (?P<hostname>\S+) (?P<service>\S+): (?P<message>.*)'
        
        self.ids_pattern = r'(?P<timestamp>\S+) \[(?P<rule_id>\d+):(?P<sig_id>\d+):(?P<sig_rev>\d+)\] (?P<message>.*) \[Classification: (?P<classification>[^\]]+)\] \[Priority: (?P<priority>\d+)\] \{(?P<protocol>\S+)\} (?P<source_ip>\S+):(?P<source_port>\d+) -> (?P<dest_ip>\S+):(?P<dest_port>\d+)'
    
    def parse_logs(self, log_content, log_format=None):
        """
        Parse logs into a structured pandas DataFrame.
        
        Args:
            log_content (str): Raw log file content
            log_format (str, optional): Format specification if known
            
        Returns:
            pandas.DataFrame: Structured log data
        """
        # Auto-detect format if not specified
        if log_format is None or log_format == "Auto-detect":
            # Try each format and see which one matches the most lines
            formats = {
                "Apache/Nginx Access Logs": self.apache_pattern,
                "Windows Event Logs": self.windows_event_pattern,
                "Firewall Logs": self.firewall_pattern,
                "Authentication Logs": self.auth_pattern,
                "IDS/IPS Logs": self.ids_pattern
            }
            
            max_matches = 0
            best_format = None
            
            # Take the first 10 lines for detection
            sample_lines = log_content.split('\n')[:10]
            sample_text = '\n'.join(sample_lines)
            
            for fmt_name, pattern in formats.items():
                matches = len(re.findall(pattern, sample_text))
                if matches > max_matches:
                    max_matches = matches
                    best_format = fmt_name
            
            log_format = best_format if best_format else "Apache/Nginx Access Logs"  # Default
        
        # Select the appropriate parsing method based on the format
        if log_format == "Apache/Nginx Access Logs":
            return self._parse_apache_logs(log_content)
        elif log_format == "Windows Event Logs":
            return self._parse_windows_logs(log_content)
        elif log_format == "Firewall Logs":
            return self._parse_firewall_logs(log_content)
        elif log_format == "Authentication Logs":
            return self._parse_auth_logs(log_content)
        elif log_format == "IDS/IPS Logs":
            return self._parse_ids_logs(log_content)
        else:
            # For unknown formats, treat as CSV or try a generic approach
            return self._parse_generic_logs(log_content)
    
    def parse_custom_logs(self, log_content, regex_pattern):
        """
        Parse logs using a custom regex pattern.
        
        Args:
            log_content (str): Raw log file content
            regex_pattern (str): Regular expression with named groups
            
        Returns:
            pandas.DataFrame: Structured log data
        """
        matches = []
        
        for line in log_content.split('\n'):
            if line.strip():
                match = re.search(regex_pattern, line)
                if match:
                    matches.append(match.groupdict())
        
        # Convert to DataFrame
        return pd.DataFrame(matches)
    
    def _parse_apache_logs(self, log_content):
        """Parse Apache/Nginx access logs."""
        matches = []
        
        for line in log_content.split('\n'):
            if line.strip():
                match = re.search(self.apache_pattern, line)
                if match:
                    log_entry = match.groupdict()
                    
                    # Process timestamp
                    try:
                        log_entry['timestamp'] = datetime.strptime(
                            log_entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z'
                        )
                    except:
                        pass
                    
                    # Extract HTTP method, URL and protocol from request
                    request_parts = log_entry['request'].split()
                    if len(request_parts) >= 2:
                        log_entry['method'] = request_parts[0]
                        log_entry['url'] = request_parts[1]
                        if len(request_parts) >= 3:
                            log_entry['protocol'] = request_parts[2]
                    
                    # Convert status code to integer
                    try:
                        log_entry['status'] = int(log_entry['status'])
                    except:
                        pass
                    
                    # Convert size to integer
                    try:
                        log_entry['size'] = int(log_entry['size'])
                    except:
                        pass
                    
                    # Add source_ip for consistency with other formats
                    log_entry['source_ip'] = log_entry['ip']
                    
                    # Add an event_type field
                    log_entry['event_type'] = 'ACCESS'
                    
                    matches.append(log_entry)
        
        return pd.DataFrame(matches)
    
    def _parse_windows_logs(self, log_content):
        """Parse Windows Event logs."""
        matches = []
        
        for line in log_content.split('\n'):
            if line.strip():
                match = re.search(self.windows_event_pattern, line)
                if match:
                    log_entry = match.groupdict()
                    
                    # Process timestamp
                    try:
                        log_entry['timestamp'] = datetime.strptime(
                            log_entry['timestamp'], '%Y-%m-%d %H:%M:%S'
                        )
                    except:
                        pass
                    
                    # Extract additional information from message
                    message = log_entry.get('message', '')
                    
                    # Extract username if present
                    user_match = re.search(r'User: (\S+)', message)
                    if user_match:
                        log_entry['username'] = user_match.group(1)
                    
                    # Determine event type
                    if 'login' in message.lower() or 'logon' in message.lower():
                        log_entry['event_type'] = 'LOGIN'
                    elif 'logout' in message.lower() or 'logoff' in message.lower():
                        log_entry['event_type'] = 'LOGOUT'
                    elif 'failure' in message.lower() or 'failed' in message.lower():
                        log_entry['event_type'] = 'FAILURE'
                    else:
                        log_entry['event_type'] = 'SYSTEM'
                    
                    # Extract status
                    if 'success' in message.lower():
                        log_entry['status'] = 'SUCCESS'
                    elif 'fail' in message.lower():
                        log_entry['status'] = 'FAILURE'
                    else:
                        log_entry['status'] = 'UNKNOWN'
                    
                    # Set source_ip if available
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
                    if ip_match:
                        log_entry['source_ip'] = ip_match.group(0)
                    else:
                        log_entry['source_ip'] = log_entry['source']
                    
                    matches.append(log_entry)
        
        return pd.DataFrame(matches)
    
    def _parse_firewall_logs(self, log_content):
        """Parse Firewall logs."""
        matches = []
        
        for line in log_content.split('\n'):
            if line.strip():
                match = re.search(self.firewall_pattern, line)
                if match:
                    log_entry = match.groupdict()
                    
                    # Process timestamp
                    try:
                        log_entry['timestamp'] = datetime.strptime(
                            log_entry['timestamp'], '%Y-%m-%d %H:%M:%S'
                        )
                    except:
                        pass
                    
                    # Convert ports to integers
                    try:
                        log_entry['source_port'] = int(log_entry['source_port'])
                        log_entry['dest_port'] = int(log_entry['dest_port'])
                    except:
                        pass
                    
                    # Set port for consistency with other formats
                    log_entry['port'] = log_entry['dest_port']
                    
                    # Set event_type based on action
                    action = log_entry.get('action', '').upper()
                    if action == 'BLOCK' or action == 'DENY':
                        log_entry['event_type'] = 'BLOCK'
                        log_entry['status'] = 'FAILURE'
                    elif action == 'ALLOW' or action == 'ACCEPT':
                        log_entry['event_type'] = 'ALLOW'
                        log_entry['status'] = 'SUCCESS'
                    else:
                        log_entry['event_type'] = action
                        log_entry['status'] = 'UNKNOWN'
                    
                    matches.append(log_entry)
        
        return pd.DataFrame(matches)
    
    def _parse_auth_logs(self, log_content):
        """Parse Authentication logs."""
        matches = []
        
        for line in log_content.split('\n'):
            if line.strip():
                match = re.search(self.auth_pattern, line)
                if match:
                    log_entry = match.groupdict()
                    
                    # Process timestamp
                    try:
                        log_entry['timestamp'] = datetime.strptime(
                            log_entry['timestamp'], '%b %d %H:%M:%S'
                        )
                        # Add current year since it's missing
                        current_year = datetime.now().year
                        log_entry['timestamp'] = log_entry['timestamp'].replace(year=current_year)
                    except:
                        pass
                    
                    # Extract username if present
                    message = log_entry.get('message', '')
                    user_match = re.search(r'user (\S+)', message)
                    if user_match:
                        log_entry['username'] = user_match.group(1)
                    
                    # Extract source IP if present
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
                    if ip_match:
                        log_entry['source_ip'] = ip_match.group(0)
                    else:
                        log_entry['source_ip'] = log_entry.get('hostname', 'unknown')
                    
                    # Determine event type and status
                    if 'accepted' in message.lower():
                        log_entry['event_type'] = 'LOGIN'
                        log_entry['status'] = 'SUCCESS'
                    elif 'failed' in message.lower():
                        log_entry['event_type'] = 'LOGIN'
                        log_entry['status'] = 'FAILURE'
                    elif 'session opened' in message.lower():
                        log_entry['event_type'] = 'SESSION'
                        log_entry['status'] = 'SUCCESS'
                    elif 'session closed' in message.lower():
                        log_entry['event_type'] = 'LOGOUT'
                        log_entry['status'] = 'SUCCESS'
                    else:
                        log_entry['event_type'] = 'AUTH'
                        log_entry['status'] = 'UNKNOWN'
                    
                    matches.append(log_entry)
        
        return pd.DataFrame(matches)
    
    def _parse_ids_logs(self, log_content):
        """Parse IDS/IPS logs."""
        matches = []
        
        for line in log_content.split('\n'):
            if line.strip():
                match = re.search(self.ids_pattern, line)
                if match:
                    log_entry = match.groupdict()
                    
                    # Process timestamp
                    try:
                        log_entry['timestamp'] = datetime.strptime(
                            log_entry['timestamp'], '%m/%d/%Y-%H:%M:%S.%f'
                        )
                    except:
                        pass
                    
                    # Convert ports to integers
                    try:
                        log_entry['source_port'] = int(log_entry['source_port'])
                        log_entry['dest_port'] = int(log_entry['dest_port'])
                    except:
                        pass
                    
                    # Set port for consistency with other formats
                    log_entry['port'] = log_entry['dest_port']
                    
                    # Set event_type and status
                    log_entry['event_type'] = 'IDS_ALERT'
                    
                    # Determine severity based on priority
                    priority = log_entry.get('priority', '0')
                    try:
                        priority = int(priority)
                        if priority <= 1:
                            log_entry['severity'] = 'High'
                        elif priority <= 2:
                            log_entry['severity'] = 'Medium'
                        else:
                            log_entry['severity'] = 'Low'
                    except:
                        log_entry['severity'] = 'Unknown'
                    
                    # Extract attack type from message
                    message = log_entry.get('message', '')
                    attack_match = re.search(r'(?:attack|exploit|scan|probe): (.+?)(?:\s*\[|$)', message)
                    if attack_match:
                        log_entry['attack_type'] = attack_match.group(1).strip()
                    
                    matches.append(log_entry)
        
        return pd.DataFrame(matches)
    
    def _parse_generic_logs(self, log_content):
        """Parse logs in an unknown format using a generic approach."""
        # First try to parse as CSV
        try:
            df = pd.read_csv(io.StringIO(log_content))
            return df
        except:
            pass
        
        # Try to parse as TSV
        try:
            df = pd.read_csv(io.StringIO(log_content), sep='\t')
            return df
        except:
            pass
        
        # Try a simple line-by-line approach
        lines = [line for line in log_content.split('\n') if line.strip()]
        
        # Look for common separators
        separators = [',', '\t', '|', ';', ' ']
        
        for sep in separators:
            # Check if all lines have the same number of fields with this separator
            sample_lines = lines[:min(10, len(lines))]
            field_counts = [len(line.split(sep)) for line in sample_lines]
            
            if len(set(field_counts)) == 1 and field_counts[0] > 1:
                # All sampled lines have the same number of fields, use this separator
                header = ["field_" + str(i) for i in range(field_counts[0])]
                data = [line.split(sep) for line in lines]
                
                # Ensure all rows have the right number of columns
                valid_data = [row for row in data if len(row) == len(header)]
                
                return pd.DataFrame(valid_data, columns=header)
        
        # If all else fails, create a simple single-column DataFrame
        return pd.DataFrame(lines, columns=['raw_log'])
