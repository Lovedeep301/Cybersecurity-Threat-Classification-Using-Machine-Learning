import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

def create_threat_heatmap(data):
    """
    Create a heatmap visualization of threats by source IP and time.
    
    Args:
        data (pandas.DataFrame): DataFrame containing threat data
            Must have 'source_ip', 'timestamp', and 'is_threat' columns
    
    Returns:
        plotly.graph_objects.Figure: Heatmap visualization
    """
    if 'source_ip' not in data.columns or 'timestamp' not in data.columns or 'is_threat' not in data.columns:
        # Return empty figure if required columns are missing
        fig = go.Figure()
        fig.update_layout(
            title="Threat Heatmap (Missing required data)",
            xaxis_title="Time",
            yaxis_title="Source IP",
            height=600
        )
        return fig
    
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_any_dtype(data['timestamp']):
        try:
            data = data.copy()
            data['timestamp'] = pd.to_datetime(data['timestamp'])
        except:
            # If conversion fails, return empty figure
            fig = go.Figure()
            fig.update_layout(
                title="Threat Heatmap (Invalid timestamp format)",
                xaxis_title="Time",
                yaxis_title="Source IP",
                height=600
            )
            return fig
    
    # Filter to only include threats
    threat_data = data[data['is_threat'] == 1]
    
    if threat_data.empty:
        # Return empty figure if no threats
        fig = go.Figure()
        fig.update_layout(
            title="Threat Heatmap (No threats detected)",
            xaxis_title="Time",
            yaxis_title="Source IP",
            height=600
        )
        return fig
    
    # Bin timestamp into hours
    threat_data = threat_data.copy()
    threat_data['hour'] = threat_data['timestamp'].dt.floor('H')
    
    # Group by IP and hour, count threats
    heatmap_data = threat_data.groupby(['source_ip', 'hour']).size().reset_index(name='threat_count')
    
    # Select top IPs by threat count for cleaner visualization
    top_ips = threat_data['source_ip'].value_counts().nlargest(15).index.tolist()
    heatmap_data = heatmap_data[heatmap_data['source_ip'].isin(top_ips)]
    
    # Create heatmap
    fig = px.density_heatmap(
        heatmap_data,
        x='hour',
        y='source_ip',
        z='threat_count',
        title="Threat Activity Heatmap by Source IP and Time",
        labels={'hour': 'Time', 'source_ip': 'Source IP', 'threat_count': 'Threat Count'},
        color_continuous_scale='reds'
    )
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Source IP",
        height=600
    )
    
    return fig

def create_timeline_chart(data):
    """
    Create a timeline visualization of threats over time.
    
    Args:
        data (pandas.DataFrame): DataFrame containing threat data
            Must have 'timestamp' and 'is_threat' columns
    
    Returns:
        plotly.graph_objects.Figure: Timeline visualization
    """
    if 'timestamp' not in data.columns or 'is_threat' not in data.columns:
        # Return empty figure if required columns are missing
        fig = go.Figure()
        fig.update_layout(
            title="Threat Timeline (Missing required data)",
            xaxis_title="Time",
            yaxis_title="Count",
            height=500
        )
        return fig
    
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_any_dtype(data['timestamp']):
        try:
            data = data.copy()
            data['timestamp'] = pd.to_datetime(data['timestamp'])
        except:
            # If conversion fails, return empty figure
            fig = go.Figure()
            fig.update_layout(
                title="Threat Timeline (Invalid timestamp format)",
                xaxis_title="Time",
                yaxis_title="Count",
                height=500
            )
            return fig
    
    # Bin timestamp into hours
    data = data.copy()
    data['hour'] = data['timestamp'].dt.floor('H')
    
    # Group by hour and threat status, count events
    timeline_data = data.groupby(['hour', 'is_threat']).size().reset_index(name='count')
    
    # Get threats and non-threats
    threats = timeline_data[timeline_data['is_threat'] == 1]
    non_threats = timeline_data[timeline_data['is_threat'] == 0]
    
    # Create figure
    fig = go.Figure()
    
    # Add threat line
    fig.add_trace(go.Scatter(
        x=threats['hour'],
        y=threats['count'],
        mode='lines+markers',
        name='Threats',
        line=dict(color='red', width=3),
        marker=dict(size=8, color='red'),
        hovertemplate='%{x}<br>Threats: %{y}<extra></extra>'
    ))
    
    # Add non-threat line
    fig.add_trace(go.Scatter(
        x=non_threats['hour'],
        y=non_threats['count'],
        mode='lines+markers',
        name='Normal Activity',
        line=dict(color='blue', width=2),
        marker=dict(size=6, color='blue'),
        hovertemplate='%{x}<br>Normal Events: %{y}<extra></extra>'
    ))
    
    # Layout
    fig.update_layout(
        title="Threat Activity Timeline",
        xaxis_title="Time",
        yaxis_title="Event Count",
        height=500,
        legend=dict(
            yanchor="top",
            y=0.99,
            xanchor="left",
            x=0.01
        ),
        hovermode="x unified"
    )
    
    return fig

def create_threat_type_breakdown(data):
    """
    Create a pie chart of threat types.
    
    Args:
        data (pandas.DataFrame): DataFrame containing threat data
            Must have 'threat_type' column
    
    Returns:
        plotly.graph_objects.Figure: Pie chart visualization
    """
    if 'threat_type' not in data.columns or 'is_threat' not in data.columns:
        # Return empty figure if required columns are missing
        fig = go.Figure()
        fig.update_layout(
            title="Threat Type Breakdown (Missing required data)",
            height=400
        )
        return fig
    
    # Filter to only include threats
    threat_data = data[data['is_threat'] == 1]
    
    if threat_data.empty:
        # Return empty figure if no threats
        fig = go.Figure()
        fig.update_layout(
            title="Threat Type Breakdown (No threats detected)",
            height=400
        )
        return fig
    
    # Count threat types
    threat_counts = threat_data['threat_type'].value_counts().reset_index()
    threat_counts.columns = ['Threat Type', 'Count']
    
    # Create pie chart
    fig = px.pie(
        threat_counts,
        values='Count',
        names='Threat Type',
        title="Threat Type Breakdown",
        color_discrete_sequence=px.colors.sequential.Reds_r
    )
    
    fig.update_layout(
        height=400
    )
    
    return fig

def create_ip_threat_map(data):
    """
    Create a map visualization of threats by geographic location.
    
    This is a placeholder that would require IP geolocation data in a real implementation.
    
    Args:
        data (pandas.DataFrame): DataFrame containing threat data
            Should have 'source_ip', 'is_threat', and geolocation columns
    
    Returns:
        plotly.graph_objects.Figure: Map visualization
    """
    # In a real implementation, this would use IP geolocation data
    # For this example, we'll create a placeholder figure
    
    fig = go.Figure()
    
    fig.add_annotation(
        text="IP Geolocation Map (Requires geolocation data)",
        xref="paper", yref="paper",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=20)
    )
    
    fig.update_layout(
        title="Geographic Distribution of Threats",
        height=500
    )
    
    return fig
