"""
dashboard.py
Professional interactive dashboard for Cybersecurity Threat Intelligence.
"""

from flask import Flask, render_template_string, request, jsonify
from pymongo import MongoClient
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump, load
import os
import re
from tqdm import tqdm
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from url_analyzer import train_model_from_dataset, analyze_url
import threading
import time

app = Flask(__name__)

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"

# New Dark Theme Color Palette for Complete Design Change
COLORS = {
    'primary': '#1A1A2E',  # Dark Navy Blue
    'secondary': '#E03E3E',  # Red
    'accent': '#00C8FF',  # Cyan
    'success': '#2ECC40',  # Green
    'warning': '#FF851B',  # Orange
    'background': '#16213E'  # Dark Blue
}
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

def get_threat_summary():
    """Get summary statistics of threats."""
    try:
        import pandas as pd
        
        # Try to get data from database first, fallback to CSV
        try:
            # Get data from MongoDB
            total_urls = db['urls'].count_documents({})
            if total_urls == 0:
                raise Exception("No data in database")
            
            malicious = db['urls'].count_documents({"type": {"$ne": "benign"}})
            threat_scores = list(db['threat_scores'].find())
            avg_threat = np.mean([score['avg_threat_score'] for score in threat_scores]) if threat_scores else 0
            
        except:
            # Fallback to CSV file
            print("Using CSV data for threat summary")
            df = pd.read_csv('/Users/joeltharakan/Documents/Big Data Project/malicious_phish.csv')
            total_urls = len(df)
            malicious = len(df[df['type'] != 'benign'])
            avg_threat = 5.0  # Default average threat score
        
        threat_percentage = round((malicious / total_urls * 100), 2) if total_urls > 0 else 0
        
        return {
            'total_urls': total_urls,
            'malicious_urls': malicious,
            'benign_urls': total_urls - malicious,
            'threat_percentage': threat_percentage,
            'avg_threat_score': round(avg_threat, 2),
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        print(f"Error getting threat summary: {e}")
        # Return default values if everything fails
        return {
            'total_urls': 651208,
            'malicious_urls': 325604,
            'benign_urls': 325604,
            'threat_percentage': 50.0,
            'avg_threat_score': 5.0,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

def create_threat_intelligence_charts():
    """Create comprehensive visualizations for threat intelligence data with optimized performance"""
    try:
        import pandas as pd
        from urllib.parse import urlparse
        import numpy as np
        
        # Try to get data from database first, fallback to CSV
        data = []
        try:
            # Get data from MongoDB with smaller sample for performance
            cursor = db['urls'].aggregate([
                {'$sample': {'size': 10000}},  # Reduced from 50k to 10k for better performance
                {'$project': {'url': 1, 'type': 1, '_id': 0}}
            ])
            data = list(cursor)
            if not data:
                raise Exception("No data in database")
        except:
            # Fallback to CSV file - use smaller sample for performance
            print("Using CSV data for charts (optimized sampling)")
            df = pd.read_csv('/Users/joeltharakan/Documents/Big Data Project/malicious_phish.csv')
            # Sample smaller dataset for better performance
            df_sample = df.sample(n=min(10000, len(df)), random_state=42)
            data = df_sample.to_dict('records')
        
        if not data:
            print("No data available for charts")
            return None, None, None, None, None, None
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(data)
        
        # Pre-compute aggregations to avoid repeated processing
        threat_counts = df['type'].value_counts()
        malicious_df = df[df['type'] != 'benign']
        malicious_domains = malicious_df['url'].apply(lambda x: urlparse(str(x)).netloc).value_counts().head(10)
        
        charts = {}
        
        # 1. Threat Type Distribution Pie Chart
        if not threat_counts.empty:
            colors = ['#28a745', '#dc3545', '#ffc107', '#6c757d', '#007bff']
            
            # Calculate percentages for threat types
            total = threat_counts.sum()
            percentages = (threat_counts / total * 100).round(1)
            
            # Create horizontal bar chart
            fig_threats = go.Figure()
            
            fig_threats.add_trace(go.Bar(
                x=threat_counts.values,
                y=threat_counts.index,
                orientation='h',
                marker_color=colors[:len(threat_counts)],
                text=[f'{val} ({pct}%)' for val, pct in zip(threat_counts.values, percentages)],
                textposition='outside',
                textfont=dict(size=12),
                hovertemplate='<b>%{y}</b><br>Count: %{x}<br>Percentage: %{text}<extra></extra>'
            ))
            
            fig_threats.update_layout(
                title={
                    'text': 'Threat Type Distribution',
                    'y': 0.95,
                    'x': 0.5,
                    'xanchor': 'center',
                    'yanchor': 'top',
                    'font': {'size': 20}
                },
                xaxis_title='Number of URLs',
                yaxis_title='Threat Type',
                yaxis={'categoryorder': 'total ascending'},  # Sort bars by value
                height=500,
                margin=dict(t=80, b=60, l=140, r=40),  # Adjusted margins
                paper_bgcolor='white',
                plot_bgcolor='white',
                bargap=0.3,  # Add space between bars
                showlegend=False,
                autosize=True
            )
            charts['threat_dist'] = fig_threats.to_html(full_html=False)
        
        # 2. URL Length Distribution Histogram (simplified)
        if not df.empty:
            url_lengths = df['url'].str.len()
            fig_url_len = go.Figure()
            
            # Add box plots for each threat type
            for threat_type, color in zip(threat_counts.index, colors):
                lengths = df[df['type'] == threat_type]['url'].str.len()
                fig_url_len.add_trace(go.Box(
                    y=lengths,
                    name=threat_type,
                    marker_color=color,
                    boxpoints='outliers',  # show outliers
                    jitter=0.3,  # add some randomness to point positions
                    pointpos=-1.8,  # offset points
                    marker=dict(
                        size=4,
                        opacity=0.5
                    ),
                    boxmean=True,  # show mean line
                    line=dict(width=2)  # box line width
                ))
            
            # Update layout
            fig_url_len.update_layout(
                title=dict(
                    text='URL Length Distribution by Threat Type',
                    x=0.5,
                    y=0.95
                ),
                yaxis_title='URL Length (characters)',
                height=500,
                template='plotly_white',
                boxmode='group',
                margin=dict(l=50, r=50, t=80, b=50),
                paper_bgcolor='white',
                plot_bgcolor='white',
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5
                )
            )
            charts['url_length'] = fig_url_len.to_html(full_html=False)
        
        # 3. Top Malicious Domains
        if not malicious_domains.empty:
            fig_domains = go.Figure(data=[go.Bar(
                x=malicious_domains.values,
                y=malicious_domains.index,
                orientation='h',
                marker_color='#dc3545',
                text=malicious_domains.values,
                textposition='auto',
                hovertemplate='<b>%{y}</b><br>%{x} malicious URLs<extra></extra>'
            )])
            fig_domains.update_layout(
                title='Top 10 Malicious Domains',
                xaxis_title='Number of URLs',
                yaxis_title='Domain',
                height=400
            )
            charts['malicious_domains'] = fig_domains.to_html(full_html=False)
        
        # 4. TLD Distribution (simplified)
        tld_counts = df['url'].apply(lambda x: urlparse(str(x)).netloc.split('.')[-1] if '.' in urlparse(str(x)).netloc else 'unknown').value_counts().head(10)
        if not tld_counts.empty:
            fig_tld = go.Figure(data=[go.Bar(
                x=tld_counts.index,
                y=tld_counts.values,
                marker_color='#6c757d',
                text=tld_counts.values,
                textposition='auto',
                hovertemplate='<b>%{x}</b><br>%{y} URLs<extra></extra>'
            )])
            fig_tld.update_layout(
                title='Top 10 TLD Distribution',
                xaxis_title='TLD',
                yaxis_title='Number of URLs',
                height=400
            )
            charts['tld_dist'] = fig_tld.to_html(full_html=False)
        
        # 5. Domain Length vs Threat Type (simplified)
        if not df.empty:
            domain_lengths = df['url'].apply(lambda x: len(urlparse(str(x)).netloc))
            fig_domain_len = go.Figure()
            for threat_type in df['type'].unique():
                type_data = domain_lengths[df['type'] == threat_type]
                fig_domain_len.add_trace(go.Box(
                    y=type_data,
                    name=threat_type,
                    boxpoints=False,  # Remove outliers for performance
                    marker_color=colors[df['type'].unique().tolist().index(threat_type) % len(colors)]
                ))
            fig_domain_len.update_layout(
                title='Domain Length Distribution by Threat Type',
                yaxis_title='Domain Length (characters)',
                height=400
            )
            charts['domain_length'] = fig_domain_len.to_html(full_html=False)
        
        # 6. Simplified Risk Score Distribution
        def calculate_simple_risk_score(url):
            score = 0
            url_str = str(url).lower()
            
            # Simple scoring for performance
            if len(url_str) > 75:
                score += 1
            if any(word in url_str for word in ['login', 'bank', 'secure', 'password']):
                score += 1
            if any(tld in url_str for tld in ['ru', 'cn', 'tk']):
                score += 2
            
            return min(score, 5)  # Cap at 5
        
        df['risk_score'] = df['url'].apply(calculate_simple_risk_score)
        
        risk_by_type = df.groupby('type')['risk_score'].mean()
        if not risk_by_type.empty:
            fig_risk = go.Figure(data=[go.Bar(
                x=risk_by_type.index,
                y=risk_by_type.values,
                marker_color=['#28a745' if x == 'benign' else '#dc3545' for x in risk_by_type.index],
                text=risk_by_type.round(2),
                textposition='auto'
            )])
            fig_risk.update_layout(
                title='Average Risk Score by Threat Type',
                xaxis_title='Threat Type',
                yaxis_title='Average Risk Score',
                height=400
            )
            charts['risk_scores'] = fig_risk.to_html(full_html=False)
        
        return (
            charts.get('threat_dist'),
            charts.get('url_length'), 
            charts.get('malicious_domains'),
            charts.get('tld_dist'),
            charts.get('domain_length'),
            charts.get('risk_scores')
        )
        
    except Exception as e:
        print(f"Error creating threat intelligence charts: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None, None, None

# Global cache for charts and data
chart_cache = {
    'charts': None,
    'threat_summary': None,
    'last_updated': None,
    'cache_duration': 300  # 5 minutes cache
}

def get_cached_data():
    """Get cached data if still valid, otherwise return None"""
    if chart_cache['charts'] is not None and chart_cache['last_updated'] is not None:
        if time.time() - chart_cache['last_updated'] < chart_cache['cache_duration']:
            return chart_cache
    return None

def update_cache():
    """Update the cache with fresh data"""
    try:
        threat_summary = get_threat_summary()
        charts = create_threat_intelligence_charts()
        chart_cache['charts'] = charts
        chart_cache['threat_summary'] = threat_summary
        chart_cache['last_updated'] = time.time()
        print("Cache updated successfully")
    except Exception as e:
        print(f"Error updating cache: {e}")

# Start background cache update thread
def cache_updater():
    """Background thread to update cache periodically"""
    while True:
        update_cache()
        time.sleep(chart_cache['cache_duration'])

# Start the cache updater thread
cache_thread = threading.Thread(target=cache_updater, daemon=True)
cache_thread.start()

# Initialize cache on startup
update_cache()

def calculate_entropy(text):
    """Calculate entropy of text string"""
    if not text:
        return 0
    probs = [text.count(c)/len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in probs)

def extract_features(url):
    """Extract features from a single URL"""
    features = {}
    
    # Basic parsing
    url_str = str(url)
    domain = url_str.split('/')[2] if '//' in url_str else url_str.split('/')[0]
    
    features['url_length'] = len(url_str)
    features['domain_length'] = len(domain)
    features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9]', url_str))
    features['digit_count'] = len(re.findall(r'[0-9]', url_str))
    features['digit_ratio'] = features['digit_count'] / features['url_length'] if features['url_length'] > 0 else 0
    features['is_ip_address'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0
    
    # Security patterns
    suspicious_pattern = r'login|bank|paypal|secure|account|update|verify|signin|password'
    features['has_suspicious_words'] = 1 if re.search(suspicious_pattern, url_str, re.IGNORECASE) else 0
    features['security_risk_score'] = len(re.findall(r'[<>\'";\(\)]|://.*://', url_str))
    
    # Additional features
    features['path_length'] = len(url_str) - len(domain)
    features['dir_count'] = url_str.count('/')
    features['has_www'] = 1 if domain.startswith('www.') else 0
    features['has_params'] = 1 if '?' in url_str else 0
    features['has_https'] = 1 if url_str.startswith('https://') else 0
    
    return features

def create_threat_intelligence_charts():
    """Create comprehensive visualizations for threat intelligence data with optimized performance"""
    try:
        import pandas as pd
        from urllib.parse import urlparse
        import numpy as np
        
        # Try to get data from database first, fallback to CSV
        data = []
        try:
            # Get data from MongoDB with smaller sample for performance
            cursor = db['urls'].aggregate([
                {'$sample': {'size': 10000}},  # Reduced from 50k to 10k for better performance
                {'$project': {'url': 1, 'type': 1, '_id': 0}}
            ])
            data = list(cursor)
            if not data:
                raise Exception("No data in database")
        except:
            # Fallback to CSV file - use smaller sample for performance
            print("Using CSV data for charts (optimized sampling)")
            df = pd.read_csv('/Users/joeltharakan/Documents/Big Data Project/malicious_phish.csv')
            # Sample smaller dataset for better performance
            df_sample = df.sample(n=min(10000, len(df)), random_state=42)
            data = df_sample.to_dict('records')
        
        if not data:
            print("No data available for charts")
            return None, None, None, None, None, None
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(data)
        
        # Pre-compute aggregations to avoid repeated processing
        threat_counts = df['type'].value_counts()
        malicious_df = df[df['type'] != 'benign']
        malicious_domains = malicious_df['url'].apply(lambda x: urlparse(str(x)).netloc).value_counts().head(10)
        
        charts = {}
        
        # 1. Threat Type Distribution Pie Chart
        if not threat_counts.empty:
            colors = ['#28a745', '#dc3545', '#ffc107', '#6c757d', '#007bff']
            
            # Calculate percentages for threat types
            total = threat_counts.sum()
            percentages = (threat_counts / total * 100).round(1)
            
            # Create horizontal bar chart
            fig_threats = go.Figure()
            
            fig_threats.add_trace(go.Bar(
                x=threat_counts.values,
                y=threat_counts.index,
                orientation='h',
                marker_color=colors[:len(threat_counts)],
                text=[f'{val} ({pct}%)' for val, pct in zip(threat_counts.values, percentages)],
                textposition='outside',
                textfont=dict(size=12),
                hovertemplate='<b>%{y}</b><br>Count: %{x}<br>Percentage: %{text}<extra></extra>'
            ))
            
            fig_threats.update_layout(
                title={
                    'text': 'Threat Type Distribution',
                    'y': 0.95,
                    'x': 0.5,
                    'xanchor': 'center',
                    'yanchor': 'top',
                    'font': {'size': 20}
                },
                xaxis_title='Number of URLs',
                yaxis_title='Threat Type',
                yaxis={'categoryorder': 'total ascending'},  # Sort bars by value
                height=500,
                margin=dict(t=80, b=60, l=140, r=40),  # Adjusted margins
                paper_bgcolor='white',
                plot_bgcolor='white',
                bargap=0.3,  # Add space between bars
                showlegend=False,
                autosize=True
            )
            charts['threat_dist'] = fig_threats.to_html(full_html=False)
        
        # 2. URL Length Distribution Histogram (simplified)
        if not df.empty:
            url_lengths = df['url'].str.len()
            fig_url_len = go.Figure()
            
            # Add box plots for each threat type
            for threat_type, color in zip(threat_counts.index, colors):
                lengths = df[df['type'] == threat_type]['url'].str.len()
                fig_url_len.add_trace(go.Box(
                    y=lengths,
                    name=threat_type,
                    marker_color=color,
                    boxpoints='outliers',  # show outliers
                    jitter=0.3,  # add some randomness to point positions
                    pointpos=-1.8,  # offset points
                    marker=dict(
                        size=4,
                        opacity=0.5
                    ),
                    boxmean=True,  # show mean line
                    line=dict(width=2)  # box line width
                ))
            
            # Update layout
            fig_url_len.update_layout(
                title=dict(
                    text='URL Length Distribution by Threat Type',
                    x=0.5,
                    y=0.95
                ),
                yaxis_title='URL Length (characters)',
                height=500,
                template='plotly_white',
                boxmode='group',
                margin=dict(l=50, r=50, t=80, b=50),
                paper_bgcolor='white',
                plot_bgcolor='white',
                showlegend=True,
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5
                )
            )
            charts['url_length'] = fig_url_len.to_html(full_html=False)
        
        # 3. Top Malicious Domains
        if not malicious_domains.empty:
            fig_domains = go.Figure(data=[go.Bar(
                x=malicious_domains.values,
                y=malicious_domains.index,
                orientation='h',
                marker_color='#dc3545',
                text=malicious_domains.values,
                textposition='auto',
                hovertemplate='<b>%{y}</b><br>%{x} malicious URLs<extra></extra>'
            )])
            fig_domains.update_layout(
                title='Top 10 Malicious Domains',
                xaxis_title='Number of URLs',
                yaxis_title='Domain',
                height=400
            )
            charts['malicious_domains'] = fig_domains.to_html(full_html=False)
        
        # 4. TLD Distribution (simplified)
        tld_counts = df['url'].apply(lambda x: urlparse(str(x)).netloc.split('.')[-1] if '.' in urlparse(str(x)).netloc else 'unknown').value_counts().head(10)
        if not tld_counts.empty:
            fig_tld = go.Figure(data=[go.Bar(
                x=tld_counts.index,
                y=tld_counts.values,
                marker_color='#6c757d',
                text=tld_counts.values,
                textposition='auto',
                hovertemplate='<b>%{x}</b><br>%{y} URLs<extra></extra>'
            )])
            fig_tld.update_layout(
                title='Top 10 TLD Distribution',
                xaxis_title='TLD',
                yaxis_title='Number of URLs',
                height=400
            )
            charts['tld_dist'] = fig_tld.to_html(full_html=False)
        
        # 5. Domain Length vs Threat Type (simplified)
        if not df.empty:
            domain_lengths = df['url'].apply(lambda x: len(urlparse(str(x)).netloc))
            fig_domain_len = go.Figure()
            for threat_type in df['type'].unique():
                type_data = domain_lengths[df['type'] == threat_type]
                fig_domain_len.add_trace(go.Box(
                    y=type_data,
                    name=threat_type,
                    boxpoints=False,  # Remove outliers for performance
                    marker_color=colors[df['type'].unique().tolist().index(threat_type) % len(colors)]
                ))
            fig_domain_len.update_layout(
                title='Domain Length Distribution by Threat Type',
                yaxis_title='Domain Length (characters)',
                height=400
            )
            charts['domain_length'] = fig_domain_len.to_html(full_html=False)
        
        # 6. Simplified Risk Score Distribution
        def calculate_simple_risk_score(url):
            score = 0
            url_str = str(url).lower()
            
            # Simple scoring for performance
            if len(url_str) > 75:
                score += 1
            if any(word in url_str for word in ['login', 'bank', 'secure', 'password']):
                score += 1
            if any(tld in url_str for tld in ['ru', 'cn', 'tk']):
                score += 2
            
            return min(score, 5)  # Cap at 5
        
        df['risk_score'] = df['url'].apply(calculate_simple_risk_score)
        
        risk_by_type = df.groupby('type')['risk_score'].mean()
        if not risk_by_type.empty:
            fig_risk = go.Figure(data=[go.Bar(
                x=risk_by_type.index,
                y=risk_by_type.values,
                marker_color=['#28a745' if x == 'benign' else '#dc3545' for x in risk_by_type.index],
                text=risk_by_type.round(2),
                textposition='auto'
            )])
            fig_risk.update_layout(
                title='Average Risk Score by Threat Type',
                xaxis_title='Threat Type',
                yaxis_title='Average Risk Score',
                height=400
            )
            charts['risk_scores'] = fig_risk.to_html(full_html=False)
        
        return (
            charts.get('threat_dist'),
            charts.get('url_length'), 
            charts.get('malicious_domains'),
            charts.get('tld_dist'),
            charts.get('domain_length'),
            charts.get('risk_scores')
        )
        
    except Exception as e:
        print(f"Error creating threat intelligence charts: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None, None, None

@app.route('/')
def dashboard():
    """Main dashboard page"""
    try:
        # Get cached data
        cached_data = get_cached_data()
        
        if cached_data is None:
            # Cache miss - update cache synchronously for first load
            update_cache()
            cached_data = get_cached_data()
        
        if cached_data:
            threat_summary = cached_data['threat_summary']
            (threat_dist_html, url_length_html, malicious_domains_html, 
             tld_dist_html, domain_length_html, risk_scores_html) = cached_data['charts']
        else:
            # Fallback if caching fails
            threat_summary = get_threat_summary()
            (threat_dist_html, url_length_html, malicious_domains_html, 
             tld_dist_html, domain_length_html, risk_scores_html) = create_threat_intelligence_charts()
        
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Cybersecurity Threat Intelligence Dashboard</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
            <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
            <style>
                :root {
                    --primary: """ + COLORS['primary'] + """;
                    --secondary: """ + COLORS['secondary'] + """;
                    --accent: """ + COLORS['accent'] + """;
                    --background: """ + COLORS['background'] + """;
                }
                body {
                    font-family: 'Inter', sans-serif;
                    background-color: var(--background);
                    margin: 0;
                    padding: 0;
                    color: var(--primary);
                }
                .navbar {
                    background: var(--primary);
                    padding: 15px 30px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    position: sticky;
                    top: 0;
                    z-index: 1000;
                }
                .navbar .container {
                    max-width: 1400px;
                    margin: auto;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .navbar h1 {
                    margin: 0;
                    color: white;
                    font-size: 1.5em;
                    font-weight: 600;
                }
                .navbar nav {
                    display: flex;
                    gap: 20px;
                }
                .navbar a {
                    color: white;
                    text-decoration: none;
                    padding: 8px 16px;
                    border-radius: 6px;
                    transition: background 0.2s;
                    font-weight: 500;
                }
                .navbar a:hover, .navbar a.active {
                    background: rgba(255,255,255,0.1);
                }
                .main-content {
                    max-width: 1400px;
                    margin: auto;
                    padding: 20px;
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding: 20px;
                    background: linear-gradient(135deg, var(--primary), var(--secondary));
                    border-radius: 12px;
                    color: white;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                .header h1 {
                    margin: 0;
                    font-size: 2.5em;
                    font-weight: 700;
                }
                .subtitle {
                    margin: 10px 0 0 0;
                    font-size: 1.2em;
                    opacity: 0.9;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .stat-card {
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                    border-left: 4px solid var(--accent);
                    transition: transform 0.2s;
                }
                .stat-card:hover {
                    transform: translateY(-2px);
                }
                .stat-card h3 {
                    margin: 0 0 10px 0;
                    color: var(--primary);
                    font-size: 1.1em;
                    font-weight: 600;
                }
                .stat-value {
                    font-size: 2.5em;
                    font-weight: 700;
                    color: var(--secondary);
                    margin: 0;
                }
                .charts-section {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
                    gap: 30px;
                    margin-bottom: 30px;
                }
                .chart-card {
                    background: white;
                    padding: 30px;
                    border-radius: 16px;
                    box-shadow: 0 6px 20px rgba(0,0,0,0.08);
                    border: 2px solid #f1f5f9;
                    transition: all 0.3s ease;
                    position: relative;
                    overflow: visible;  /* Changed from hidden to visible */
                    min-height: 550px;  /* Minimum height for charts */
                }
                .chart-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 12px 40px rgba(0,0,0,0.12);
                    border-color: var(--accent);
                }
                .chart-card::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 4px;
                    background: linear-gradient(90deg, var(--accent), var(--secondary));
                }
                .chart-card h3 {
                    margin: 0 0 20px 0;
                    color: var(--primary);
                    font-size: 1.4em;
                    font-weight: 600;
                    text-align: center;
                    border-bottom: 2px solid #f1f5f9;
                    padding-bottom: 10px;
                }
                /* Plotly chart specific styles */
                .chart-card .js-plotly-plot {
                    width: 100% !important;
                    height: 100% !important;
                    min-height: 450px !important;
                }
                .chart-card .plotly {
                    width: 100% !important;
                    height: 100% !important;
                }
                .chart-card .main-svg {
                    width: 100% !important;
                    height: 100% !important;
                }
                .actions-section {
                    background: white;
                    padding: 30px;
                    border-radius: 16px;
                    box-shadow: 0 6px 20px rgba(0,0,0,0.08);
                    text-align: center;
                    margin-bottom: 30px;
                }
                .actions-section h3 {
                    margin: 0 0 20px 0;
                    color: var(--primary);
                    font-size: 1.6em;
                    font-weight: 600;
                }
                .action-btn {
                    display: inline-block;
                    padding: 15px 30px;
                    background: linear-gradient(135deg, var(--accent), var(--secondary));
                    color: white;
                    text-decoration: none;
                    border-radius: 12px;
                    font-weight: 600;
                    font-size: 1.1em;
                    margin: 10px;
                    transition: all 0.3s;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                }
                .action-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(0,0,0,0.2);
                }
                .loading-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.8);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    z-index: 9999;
                    color: white;
                    font-size: 1.2em;
                }
                @media (max-width: 768px) {
                    .main-content {
                        padding: 10px;
                    }
                    .header h1 {
                        font-size: 2em;
                    }
                    .stats-grid {
                        grid-template-columns: 1fr;
                    }
                    .charts-section {
                        grid-template-columns: 1fr;
                    }
                }
            </style>
        </head>
        <body>
            <div id="loading-overlay" class="loading-overlay" style="display: none;">
                <div>Loading dashboard...</div>
            </div>
            
            <div class="navbar">
                <div class="container">
                    <h1>CTIA</h1>
                    <nav>
                        <a href="/" class="active">Dashboard</a>
                        <a href="/analyze">Analyze URL</a>
                    </nav>
                </div>
            </div>
            
            <div class="main-content">
                <div class="header">
                    <h1>Cybersecurity Threat Intelligence Dashboard</h1>
                    <p class="subtitle">Real-time threat analysis and URL classification using AI-powered detection</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total URLs Analyzed</h3>
                        <p class="stat-value">{{ threat_summary.total_urls | default(0) }}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Malicious URLs</h3>
                        <p class="stat-value">{{ threat_summary.malicious_urls | default(0) }}</p>
                    </div>
                    <div class="stat-card">
                        <h3>Threat Percentage</h3>
                        <p class="stat-value">{{ threat_summary.threat_percentage | default(0) }}%</p>
                    </div>
                    <div class="stat-card">
                        <h3>Average Threat Score</h3>
                        <p class="stat-value">{{ threat_summary.avg_threat_score | default(0) }}</p>
                    </div>
                </div>
                
                <div class="charts-section">
                    {% if threat_dist_html %}
                    <div class="chart-card">
                        <h3>Threat Type Distribution</h3>
                        {{ threat_dist_html | safe }}
                    </div>
                    {% endif %}
                    
                    {% if url_length_html %}
                    <div class="chart-card">
                        <h3>URL Length Distribution</h3>
                        {{ url_length_html | safe }}
                    </div>
                    {% endif %}
                    
                    {% if malicious_domains_html %}
                    <div class="chart-card">
                        <h3>Top Malicious Domains</h3>
                        {{ malicious_domains_html | safe }}
                    </div>
                    {% endif %}
                    
                    {% if tld_dist_html %}
                    <div class="chart-card">
                        <h3>TLD Distribution</h3>
                        {{ tld_dist_html | safe }}
                    </div>
                    {% endif %}
                    
                    {% if domain_length_html %}
                    <div class="chart-card">
                        <h3>Domain Length Analysis</h3>
                        {{ domain_length_html | safe }}
                    </div>
                    {% endif %}
                    
                    {% if risk_scores_html %}
                    <div class="chart-card">
                        <h3>Risk Score Analysis</h3>
                        {{ risk_scores_html | safe }}
                    </div>
                    {% endif %}
                </div>
                
                <div class="actions-section">
                    <h3>Threat Analysis Tools</h3>
                    <a href="/analyze" class="action-btn">Analyze Custom URL</a>
                    <p style="margin-top: 20px; color: #666; font-size: 0.9em;">
                        Last updated: {{ threat_summary.last_updated | default('Never') }}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """, threat_summary=threat_summary, threat_dist_html=threat_dist_html, 
           url_length_html=url_length_html, malicious_domains_html=malicious_domains_html,
           tld_dist_html=tld_dist_html, domain_length_html=domain_length_html, 
           risk_scores_html=risk_scores_html)
    
    except Exception as e:
        return f"Error loading dashboard: {str(e)}"

@app.route('/get_random_url')
def get_random_url():
    """Get a random URL from the dataset for automatic analysis"""
    try:
        # Get a random URL from the database
        random_url_doc = list(db['urls'].aggregate([
            {'$sample': {'size': 1}}
        ]))
        
        if random_url_doc:
            url = random_url_doc[0]['url']
            url_type = random_url_doc[0]['type']
            return jsonify({
                'url': url,
                'type': url_type
            })
        else:
            return jsonify({'error': 'No URLs found in dataset'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/analyze', methods=['GET', 'POST'])
def analyze_page():
    if request.method == 'POST':
        # Handle URL analysis with training
        url = request.form.get('url')
        if not url:
            return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>URL Analysis - Error</title>
            </head>
            <body>
                <h1>Error: No URL provided</h1>
                <a href="/analyze">Go back</a>
            </body>
            </html>
            """)
        
        try:
            # Analyze the URL directly (model is already trained)
            print(f"Analyzing URL: {url}")
            result = analyze_url(url)
            
            if 'error' in result:
                return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>URL Analysis - Error</title>
                </head>
                <body>
                    <h1>Analysis Error</h1>
                    <p>{{ error }}</p>
                    <a href="/analyze">Try again</a>
                </body>
                </html>
                """, error=result['error'])
            
            # Return detailed analysis page
            return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>URL Analysis Results</title>
                <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
                <style>
                    body { 
                        font-family: 'Inter', sans-serif; 
                        background-color: """ + COLORS['background'] + """; 
                        margin: 0; 
                        padding: 20px; 
                        color: """ + COLORS['primary'] + """;
                    }
                    .navbar {
                        background: """ + COLORS['primary'] + """;
                        padding: 15px 30px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        position: sticky;
                        top: 0;
                        z-index: 1000;
                        border-radius: 8px;
                        margin-bottom: 20px;
                    }
                    .navbar .container {
                        max-width: 1400px;
                        margin: auto;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                    }
                    .navbar h1 {
                        margin: 0;
                        color: white;
                        font-size: 1.5em;
                        font-weight: 600;
                    }
                    .navbar nav {
                        display: flex;
                        gap: 20px;
                    }
                    .navbar a {
                        color: white;
                        text-decoration: none;
                        padding: 8px 16px;
                        border-radius: 6px;
                        transition: background 0.2s;
                        font-weight: 500;
                    }
                    .navbar a:hover, .navbar a.active {
                        background: rgba(255,255,255,0.1);
                    }
                    .result-card {
                        background: white;
                        padding: 30px;
                        border-radius: 12px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                        margin: 20px auto;
                        max-width: 800px;
                        border-left: 4px solid {{ 'red' if result.is_malicious else 'green' }};
                    }
                    .result-header {
                        display: flex;
                        align-items: center;
                        margin-bottom: 20px;
                    }
                    .result-icon {
                        font-size: 2em;
                        margin-right: 15px;
                    }
                    .result-title {
                        margin: 0;
                        font-size: 1.8em;
                        font-weight: 600;
                        color: """ + COLORS['primary'] + """;
                    }
                    .result-meta {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 15px;
                        margin: 20px 0;
                    }
                    .meta-item {
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 8px;
                        text-align: center;
                    }
                    .meta-label {
                        font-size: 0.9em;
                        color: #666;
                        margin-bottom: 5px;
                    }
                    .meta-value {
                        font-size: 1.4em;
                        font-weight: 600;
                        color: """ + COLORS['secondary'] + """;
                    }
                    .reasons-section {
                        margin: 20px 0;
                        padding: 20px;
                        background: #fff3cd;
                        border-radius: 8px;
                        border-left: 4px solid #ffc107;
                    }
                    .reasons-title {
                        font-weight: 600;
                        margin-bottom: 10px;
                        color: #856404;
                    }
                    .reasons-list {
                        list-style: none;
                        padding: 0;
                    }
                    .reasons-list li {
                        padding: 5px 0;
                        color: #856404;
                    }
                    .charts-section {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                        gap: 20px;
                        margin: 30px 0;
                    }
                    .chart-card {
                        background: white;
                        padding: 20px;
                        border-radius: 12px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                    }
                    .chart-title {
                        font-size: 1.2em;
                        font-weight: 600;
                        margin-bottom: 15px;
                        color: """ + COLORS['primary'] + """;
                        text-align: center;
                    }
                    .actions {
                        text-align: center;
                        margin: 30px 0;
                    }
                    .action-btn {
                        display: inline-block;
                        padding: 12px 24px;
                        background: linear-gradient(135deg, """ + COLORS['accent'] + """, """ + COLORS['secondary'] + """);
                        color: white;
                        text-decoration: none;
                        border-radius: 8px;
                        font-weight: 600;
                        transition: all 0.3s;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    }
                    .action-btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 6px 20px rgba(0,0,0,0.2);
                    }
                </style>
            </head>
            <body>
                <div class="navbar">
                    <div class="container">
                        <h1>CTIA</h1>
                        <nav>
                            <a href="/">Dashboard</a>
                            <a href="/analyze" class="active">Analyze URL</a>
                        </nav>
                    </div>
                </div>
                
                <div class="result-card">
                    <div class="result-header">
                        <div class="result-icon">{{ "Alert" if result.is_malicious else "Safe" }}</div>
                        <div>
                            <h1 class="result-title">URL Analysis Results</h1>
                            <p style="margin: 5px 0; color: #666;">{{ url }}</p>
                        </div>
                    </div>
                    
                    <div class="result-meta">
                        <div class="meta-item">
                            <div class="meta-label">Prediction</div>
                            <div class="meta-value">{{ result.prediction.upper() }}</div>
                        </div>
                        <div class="meta-item">
                            <div class="meta-label">Confidence</div>
                            <div class="meta-value">{{ "%.1f"|format(result.confidence * 100) }}%</div>
                        </div>
                        <div class="meta-item">
                            <div class="meta-label">Status</div>
                            <div class="meta-value" style="color: {{ 'red' if result.is_malicious else 'green' }};">
                                {{ "MALICIOUS" if result.is_malicious else "SAFE" }}
                            </div>
                        </div>
                        {% if result.rule_score is defined %}
                        <div class="meta-item">
                            <div class="meta-label">Risk Score</div>
                            <div class="meta-value">{{ result.rule_score }}</div>
                        </div>
                        {% endif %}
                    </div>
                    
                    {% if result.reasons %}
                    <div class="reasons-section">
                        <div class="reasons-title">Analysis Details:</div>
                        <ul class="reasons-list">
                            {% for reason in result.reasons %}
                            <li>• {{ reason }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                </div>
                
                <div class="charts-section">
                    <div class="chart-card">
                        <div class="chart-title">Feature Analysis</div>
                        <div id="feature-chart"></div>
                    </div>
                    
                    {% if result.probabilities %}
                    <div class="chart-card">
                        <div class="chart-title">Threat Probabilities</div>
                        <div id="prob-chart"></div>
                    </div>
                    {% endif %}
                </div>
                
                <div class="actions">
                    <a href="/analyze" class="action-btn">Analyze Another URL</a>
                </div>
                
                <script>
                    // Feature chart
                    const features = {{ result.features | tojson }};
                    const featureData = Object.entries(features)
                        .filter(([key, value]) => typeof value === 'number' && value > 0)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 10); // Top 10 features
                    
                    Plotly.newPlot('feature-chart', [{
                        type: 'bar',
                        x: featureData.map(d => d[1]),
                        y: featureData.map(d => d[0]),
                        orientation: 'h',
                        marker: { color: '""" + COLORS['accent'] + """' }
                    }], { 
                        margin: { l: 150 },
                        height: 300
                    });
                    
                    {% if result.probabilities %}
                    // Probability chart
                    const probData = {{ result.probabilities | tojson }};
                    Plotly.newPlot('prob-chart', [{
                        type: 'bar',
                        x: Object.keys(probData),
                        y: Object.values(probData).map(x => x * 100),
                        marker: { 
                            color: Object.values(probData).map((p, i) => {
                                const colors = ['#28a745', '#dc3545', '#6c757d', '#007bff'];
                                return colors[i];
                            })
                        }
                    }], { 
                        title: 'Threat Probabilities (%)',
                        height: 300
                    });
                    {% endif %}
                </script>
            </body>
            </html>
            """, url=url, result=result)
        
        except Exception as e:
            return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>URL Analysis - Error</title>
            </head>
            <body>
                <h1>Analysis Error</h1>
                <p>{{ error }}</p>
                <a href="/analyze">Try again</a>
            </body>
            </html>
            """, error=str(e))
    
    # GET request - show the input form
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>URL Analysis - Cybersecurity Threat Intelligence</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary: """ + COLORS['primary'] + """;
                --secondary: """ + COLORS['secondary'] + """;
                --accent: """ + COLORS['accent'] + """;
                --background: """ + COLORS['background'] + """;
            }
            body {
                font-family: 'Inter', sans-serif;
                background-color: var(--background);
                margin: 0;
                padding: 0;
                color: var(--primary);
            }
            .navbar {
                background: var(--primary);
                padding: 15px 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                position: sticky;
                top: 0;
                z-index: 1000;
            }
            .navbar .container {
                max-width: 1400px;
                margin: auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .navbar h1 {
                margin: 0;
                color: white;
                font-size: 1.5em;
                font-weight: 600;
            }
            .navbar nav {
                display: flex;
                gap: 20px;
            }
            .navbar a {
                color: white;
                text-decoration: none;
                padding: 8px 16px;
                border-radius: 6px;
                transition: background 0.2s;
                font-weight: 500;
            }
            .navbar a:hover, .navbar a.active {
                background: rgba(255,255,255,0.1);
            }
            .main-content {
                max-width: 800px;
                margin: auto;
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                margin-top: 50px;
            }
            .header {
                text-align: center;
                margin-bottom: 40px;
                padding-bottom: 20px;
                border-bottom: 2px solid var(--background);
            }
            .header h1 {
                margin: 0;
                color: var(--primary);
                font-size: 2.2em;
                font-weight: 600;
            }
            .subtitle {
                color: var(--secondary);
                font-size: 1.1em;
                margin-top: 10px;
            }
            .analyze-form {
                text-align: center;
            }
            .url-input {
                width: 100%;
                max-width: 500px;
                padding: 15px;
                font-size: 1.1em;
                border: 2px solid var(--accent);
                border-radius: 8px;
                margin: 20px 0;
                outline: none;
            }
            .url-input:focus {
                border-color: var(--secondary);
                box-shadow: 0 0 0 3px rgba(224, 62, 62, 0.1);
            }
            .analyze-btn {
                padding: 15px 30px;
                background: linear-gradient(135deg, var(--accent), var(--secondary));
                color: white;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                font-size: 1.1em;
                transition: all 0.3s;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            }
            .analyze-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(0,0,0,0.2);
            }
            .analyze-btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
            }
            .loading {
                display: none;
                text-align: center;
                color: var(--secondary);
                font-size: 1.2em;
                margin: 20px 0;
                font-weight: 500;
            }
            .info-box {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 8px;
                border-left: 4px solid var(--accent);
                margin: 30px 0;
            }
            .info-box h3 {
                margin: 0 0 10px 0;
                color: var(--primary);
                font-size: 1.2em;
            }
            .info-box p {
                margin: 8px 0;
                color: var(--primary);
                line-height: 1.6;
            }
        </style>
    </head>
    <body>
        <div class="navbar">
            <div class="container">
                <h1>CTIA</h1>
                <nav>
                    <a href="/">Dashboard</a>
                    <a href="/analyze" class="active">Analyze URL</a>
                </nav>
            </div>
        </div>
        
        <div class="main-content">
            <div class="header">
                <h1>URL Analysis Tool</h1>
                <p class="subtitle">Enter a URL to analyze for potential threats using AI-powered detection</p>
            </div>
            
            <form method="POST" class="analyze-form" onsubmit="showLoading()">
                <input type="url" name="url" class="url-input" placeholder="https://example.com" required>
                <br>
                <button type="submit" class="analyze-btn" id="analyze-btn">
                    Analyze URL
                </button>
                <div class="loading" id="loading">
                    Analyzing URL... This will only take a few seconds...
                </div>
            </form>
            
            <div class="info-box">
                <h3>How it works:</h3>
                <p>• Enter any URL you want to analyze for potential threats</p>
                <p>• Our AI-powered system will instantly analyze the URL using advanced ML algorithms</p>
                <p>• Get detailed threat intelligence including confidence scores, risk factors, and feature analysis</p>
                <p>• Results help you make informed security decisions</p>
            </div>
        </div>
        
        <script>
            function showLoading() {
                document.getElementById('analyze-btn').disabled = true;
                document.getElementById('analyze-btn').textContent = 'Processing...';
                document.getElementById('loading').style.display = 'block';
            }
        </script>
    </body>
    </html>
    """)

def find_free_port(start_port=5001):
    """Find a free port starting from start_port."""
    import socket
    from contextlib import closing
    
    def is_port_free(port):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                sock.bind(('0.0.0.0', port))
                return True
            except OSError:
                return False
    
    port = start_port
    while port < start_port + 100:  # Try up to 100 ports
        if is_port_free(port):
            return port
        port += 1
    raise OSError("No free ports found")

if __name__ == '__main__':
    try:
        # First, try to kill any existing process on port 5001
        import os
        os.system("lsof -ti:5001 | xargs kill -9 2>/dev/null")
        
        # Find a free port
        port = find_free_port()
        print(f"Starting dashboard on port {port}")
        app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)
    except Exception as e:
        print(f"Error starting server: {e}")
