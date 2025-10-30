"""
MongoDB data viewer for the Cybersecurity Threat Intelligence Analyzer.
"""
from flask import Flask, render_template_string, request
from pymongo import MongoClient, ASCENDING, DESCENDING
from flask_paginate import Pagination, get_page_parameter
import time
import threading

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/', maxPoolSize=50)
db = client['cyber_intel']

# Performance optimized constants
ITEMS_PER_PAGE = 25  # Increased for better performance
MAX_CACHE_AGE = 300  # 5 minutes cache duration

# Create indexes for better query performance
def ensure_indexes():
    """Ensure all necessary indexes exist"""
    try:
        db.urls.create_index([("type", ASCENDING)])
        db.urls.create_index([("timestamp", DESCENDING)])
        print("Database indexes created/verified")
    except Exception as e:
        print(f"Error creating indexes: {e}")

# Initialize indexes
ensure_indexes()
MAX_CACHE_AGE = 300  # 5 minutes cache duration for better performance

# Cache for MongoDB data with extended structure
data_cache = {
    'stats': None,
    'url_types': None,
    'threat_scores': None,
    'top_domains': {},  # Cache by page
    'recent_urls': {},  # Cache by page
    'last_updated': None,
    'cache_duration': MAX_CACHE_AGE
}

def get_cached_stats():
    """Get cached collection stats if still valid"""
    if data_cache['stats'] is not None and data_cache['last_updated'] is not None:
        if time.time() - data_cache['last_updated'] < data_cache['cache_duration']:
            return data_cache['stats']
    return None

def update_stats_cache():
    """Update the stats cache"""
    try:
        stats = {
            'urls': db['urls'].count_documents({}),
            'mal_domains': db['mal_domains'].count_documents({}),
            'threat_scores': db['threat_scores'].count_documents({}),
            'types': db['counts_by_type'].count_documents({})
        }
        data_cache['stats'] = stats
        # Cache the full collections since they're small
        data_cache['url_types'] = list(db['counts_by_type'].find({}, {'_id': 1, 'value': 1}))
        data_cache['threat_scores'] = list(db['threat_scores'].find({}, {'_id': 1, 'avg_threat_score': 1, 'max_threat_score': 1}))
        data_cache['last_updated'] = time.time()
        print("Stats cache updated")
    except Exception as e:
        print(f"Error updating stats cache: {e}")

# Start background cache updater
def cache_updater():
    """Background thread to update cache periodically"""
    while True:
        update_stats_cache()
        time.sleep(data_cache['cache_duration'])

cache_thread = threading.Thread(target=cache_updater, daemon=True)
cache_thread.start()

# Initialize cache
update_stats_cache()

def get_cached_data(key, page=None):
    """Get cached data with page support"""
    if page is not None:
        cache_key = f"{key}_{page}"
        return data_cache.get(key, {}).get(page)
    return data_cache.get(key)

def cache_data(key, data, page=None):
    """Cache data with page support"""
    if page is not None:
        if key not in data_cache:
            data_cache[key] = {}
        data_cache[key][page] = data
    else:
        data_cache[key] = data

def get_mongo_data():
    """Retrieve and format MongoDB data for display with optimized performance and better formatting"""
    try:
        # Get current page from request args
        page = request.args.get(get_page_parameter(), type=int, default=1)
        
        # Calculate skip value for pagination
        skip = (page - 1) * ITEMS_PER_PAGE
        
        # Check if cache is valid
        cache_age = time.time() - (data_cache['last_updated'] or 0)
        cache_valid = cache_age < MAX_CACHE_AGE
        
        # Get cached stats
        collection_stats = get_cached_stats() if cache_valid else None
        if collection_stats is None:
            # Fallback to direct query if cache miss
            update_stats_cache()
            collection_stats = get_cached_stats() or {
                'urls': 0, 'mal_domains': 0, 'threat_scores': 0, 'types': 0
            }
        
        # Get paginated data with optimized queries and better formatting
        data = {
            # Use cached data for small collections
            'url_types': data_cache.get('url_types', []),
            'threat_scores': data_cache.get('threat_scores', []),
            
            # Get cached domains for current page - use mal_domains collection for better performance
            'top_domains': (
                get_cached_data('top_domains', page) or 
                list(db['mal_domains'].find({}, {'_id': 1, 'value': 1})
                     .sort('value', -1)
                     .skip(skip)
                     .limit(ITEMS_PER_PAGE))
            ),
            
            # Recent URLs with enhanced fields - use a simpler approach
            'recent_urls': (
                get_cached_data('recent_urls', page) or 
                list(db['urls'].find(
                    {},  # Include all URLs (benign and malicious)
                    {'url': 1, 'type': 1, '_id': 0}
                ).sort([('_id', -1)]).skip(skip).limit(ITEMS_PER_PAGE))
            ),
            
            'collection_stats': collection_stats,
            'pagination': {
                'mal_domains': Pagination(
                    page=page,
                    total=collection_stats['mal_domains'],
                    per_page=ITEMS_PER_PAGE,
                    css_framework='bootstrap4',
                    alignment='center'
                ),
                'urls': Pagination(
                    page=page,
                    total=collection_stats['urls'],
                    per_page=ITEMS_PER_PAGE,
                    css_framework='bootstrap4',
                    alignment='center'
                )
            }
        }
        
        print(f"DEBUG: top_domains count: {len(data['top_domains'])}")
        print(f"DEBUG: recent_urls count: {len(data['recent_urls'])}")
        print(f"DEBUG: url_types count: {len(data['url_types'])}")
        print(f"DEBUG: threat_scores count: {len(data['threat_scores'])}")
        
        # Cache the page data
        if page not in data_cache.get('top_domains', {}):
            data_cache.setdefault('top_domains', {})[page] = data['top_domains']
        if page not in data_cache.get('recent_urls', {}):
            data_cache.setdefault('recent_urls', {})[page] = data['recent_urls']
        
        # Post-process the data for better display
        for domain in data['top_domains']:
            if 'value' in domain:
                # Format large numbers with commas
                try:
                    domain['value'] = f"{int(domain['value']):,}"
                except (ValueError, TypeError):
                    pass
            # Rename _id to name for consistency
            if '_id' in domain:
                domain['name'] = domain.pop('_id')
        
        return data
        
    except Exception as e:
        print(f"Error getting MongoDB data: {e}")
        import traceback
        traceback.print_exc()
        # Return empty data structure with error handling
        return {
            'url_types': [],
            'threat_scores': [],
            'top_domains': [],
            'recent_urls': [],
            'collection_stats': {
                'urls': 0, 'mal_domains': 0, 'threat_scores': 0, 'types': 0
            },
            'pagination': {
                'mal_domains': Pagination(page=1, total=0, per_page=ITEMS_PER_PAGE, css_framework='bootstrap4'),
                'urls': Pagination(page=1, total=0, per_page=ITEMS_PER_PAGE, css_framework='bootstrap4')
            }
        }

@app.route('/')
def index():
    return show_mongodb_data()

@app.route('/mongodb-data')
def show_mongodb_data():
    data = get_mongo_data()
    
    # Convert to HTML tables without pandas for better performance
    def list_to_html_table(data_list, columns=None):
        """Convert list of dicts to HTML table with improved formatting"""
        if not data_list:
            return '<div class="alert alert-info">No data available</div>'
        
        if columns is None:
            columns = list(data_list[0].keys()) if data_list else []
        
        html = '<div class="table-responsive">'  # Add responsive wrapper
        html += '<table class="data-table table table-hover">'
        
        # Header
        html += '<thead><tr>'
        headers = {
            'name': 'Domain',
            'value': 'Occurrences',
            'url': 'URL',
            'type': 'Type',
            'timestamp': 'Timestamp',
            '_id': 'Type',
            'avg_threat_score': 'Avg Threat Score',
            'max_threat_score': 'Max Threat Score'
        }
        for col in columns:
            # Use custom headers if available, otherwise format the column name
            header = headers.get(col, col.replace('_', ' ').title())
            html += f'<th scope="col">{header}</th>'
        html += '</tr></thead>'
        
        # Body
        html += '<tbody>'
        for item in data_list:
            html += '<tr>'
            for col in columns:
                value = item.get(col, '')
                
                # Special formatting for different column types
                if col == 'url':
                    # Truncate long URLs and add tooltip
                    full_url = str(value)
                    display_url = full_url[:60] + '...' if len(full_url) > 60 else full_url
                    html += f'<td title="{full_url}">{display_url}</td>'
                    
                elif col == 'type':
                    # Add color-coding for different types
                    color_class = {
                        'benign': 'text-success',
                        'malicious': 'text-danger',
                        'phishing': 'text-warning',
                        'malware': 'text-danger',
                        'defacement': 'text-warning'
                    }.get(str(value).lower(), '')
                    html += f'<td><span class="{color_class}">{value}</span></td>'
                    
                elif col == 'value':
                    # Format numeric values with proper type checking
                    try:
                        num_value = int(value) if isinstance(value, str) else value
                        formatted_value = f"{num_value:,}"
                        html += f'<td class="text-right font-weight-bold">{formatted_value}</td>'
                    except (ValueError, TypeError):
                        html += f'<td class="text-right">{value}</td>'
                    
                elif col == 'name':
                    # Format domain names with copy button
                    html += f'''<td>
                        <div class="d-flex align-items-center">
                            <code class="mr-2">{value}</code>
                            <button class="btn btn-sm btn-light" onclick="navigator.clipboard.writeText('{value}')" title="Copy domain">
                                Copy
                            </button>
                        </div>
                    </td>'''
                    
                else:
                    html += f'<td>{value}</td>'
            html += '</tr>'
        html += '</tbody></table></div>'
        return html
    
    # Format tables
    tables_html = {
        'url_types': list_to_html_table(data['url_types'], ['_id', 'value']),
        'threat_scores': list_to_html_table(data['threat_scores'], ['_id', 'avg_threat_score', 'max_threat_score']),
        'top_domains': list_to_html_table(data['top_domains'], ['name', 'value']),
        'recent_urls': list_to_html_table(data['recent_urls'], ['url', 'type'])
    }
    
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cybersecurity Threat Intelligence Dashboard</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                :root {
                    --primary-color: #2563eb;
                    --secondary-color: #1e40af;
                    --background-color: #f1f5f9;
                    --card-background: #ffffff;
                    --text-primary: #1e293b;
                    --text-secondary: #64748b;
                    --border-color: #e2e8f0;
                }
                
                body {
                    font-family: 'Inter', sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: var(--background-color);
                    color: var(--text-primary);
                }
                
                .header {
                    background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
                    color: white;
                    padding: 2rem;
                    text-align: center;
                    margin-bottom: 2rem;
                }
                
                .header h1 {
                    margin: 0;
                    font-size: 2rem;
                    font-weight: 600;
                }
                
                .stats-container {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 1rem;
                    padding: 0 2rem;
                    margin-bottom: 2rem;
                }
                
                .stat-card {
                    background: var(--card-background);
                    border-radius: 0.5rem;
                    padding: 1.5rem;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    text-align: center;
                }
                
                .stat-card h3 {
                    color: var(--text-secondary);
                    margin: 0 0 0.5rem 0;
                    font-size: 0.875rem;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }
                
                .stat-card .value {
                    font-size: 2rem;
                    font-weight: 600;
                    color: var(--primary-color);
                }
                
                .container {
                    max-width: 1600px;
                    margin: 0 auto;
                    padding: 0 2rem 2rem;
                }
                
                .section {
                    background: var(--card-background);
                    border-radius: 0.5rem;
                    padding: 1.5rem;
                    margin-bottom: 2rem;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }
                
                .section h2 {
                    color: var(--text-primary);
                    margin: 0 0 1.5rem 0;
                    padding-bottom: 0.75rem;
                    border-bottom: 2px solid var(--border-color);
                    font-size: 1.25rem;
                }
                
                .data-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 1rem;
                    font-size: 0.875rem;
                    background-color: white;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }
                
                .data-table th {
                    background-color: var(--primary-color);
                    color: white;
                    padding: 1rem;
                    text-align: left;
                    font-weight: 500;
                    position: sticky;
                    top: 0;
                    z-index: 10;
                }
                
                .data-table td {
                    padding: 1rem;
                    border-bottom: 1px solid var(--border-color);
                    vertical-align: middle;
                }
                
                .data-table tbody tr:hover {
                    background-color: #f8fafc;
                    transition: background-color 0.2s ease;
                }
                
                .data-table code {
                    background: #f1f5f9;
                    padding: 0.2rem 0.4rem;
                    border-radius: 4px;
                    font-family: 'Monaco', 'Consolas', monospace;
                    font-size: 0.8rem;
                }
                
                .text-success { color: #10b981; }
                .text-danger { color: #ef4444; }
                .text-warning { color: #f59e0b; }
                
                .table-responsive {
                    overflow-x: auto;
                    max-width: 100%;
                    margin-bottom: 1rem;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                
                /* Custom scrollbar for better UX */
                .table-responsive::-webkit-scrollbar {
                    height: 8px;
                }
                
                .table-responsive::-webkit-scrollbar-track {
                    background: #f1f5f9;
                    border-radius: 4px;
                }
                
                .table-responsive::-webkit-scrollbar-thumb {
                    background: var(--primary-color);
                    border-radius: 4px;
                }
                
                .data-table td[title] {
                    cursor: help;
                    text-decoration: underline dotted #cbd5e1;
                }
                
                .refresh-button {
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    padding: 0.75rem 1.5rem;
                    background-color: var(--primary-color);
                    color: white;
                    border: none;
                    border-radius: 0.375rem;
                    font-weight: 500;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }
                
                .refresh-button:hover {
                    background-color: var(--secondary-color);
                }
                
                .buttons-container {
                    text-align: center;
                    margin: 2rem 0;
                }
                
                .auto-refresh-text {
                    display: block;
                    text-align: center;
                    color: var(--text-secondary);
                    font-size: 0.875rem;
                    margin-top: 0.5rem;
                }

                .pagination-container {
                    margin-top: 1.5rem;
                    display: flex;
                    justify-content: center;
                }

                .pagination {
                    display: flex;
                    list-style: none;
                    padding: 0;
                    margin: 0;
                }

                .pagination li {
                    margin: 0 0.25rem;
                }

                .pagination li a,
                .pagination li span {
                    display: inline-block;
                    padding: 0.5rem 1rem;
                    text-decoration: none;
                    border: 1px solid var(--border-color);
                    color: var(--primary-color);
                    border-radius: 0.375rem;
                }

                .pagination li.active span {
                    background-color: var(--primary-color);
                    color: white;
                    border-color: var(--primary-color);
                }

                .pagination li a:hover {
                    background-color: var(--background-color);
                }
                
                @media (max-width: 768px) {
                    .stats-container {
                        grid-template-columns: 1fr;
                    }
                    
                    .container {
                        padding: 0 1rem 1rem;
                    }
                }

                /* Badge styles */
                .badge {
                    display: inline-block;
                    padding: 0.25em 0.6em;
                    font-size: 0.75rem;
                    font-weight: 600;
                    line-height: 1;
                    text-align: center;
                    white-space: nowrap;
                    vertical-align: baseline;
                    border-radius: 0.25rem;
                    margin-right: 0.25rem;
                }
                
                .badge-success { background-color: #10b981; color: white; }
                .badge-danger { background-color: #ef4444; color: white; }
                .badge-warning { background-color: #f59e0b; color: white; }
                .badge-secondary { background-color: #6b7280; color: white; }
                
                /* Table styles */
                .table-responsive {
                    margin: 1rem 0;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                }
                
                .data-table {
                    margin-bottom: 0 !important;
                }
                
                .data-table thead th {
                    border-bottom: 2px solid var(--primary-color);
                    white-space: nowrap;
                }
                
                .data-table td {
                    vertical-align: middle !important;
                }
                
                .data-table code {
                    background: #f1f5f9;
                    padding: 0.2rem 0.4rem;
                    border-radius: 4px;
                    font-family: 'Monaco', 'Consolas', monospace;
                    font-size: 0.85rem;
                    color: var(--primary-color);
                }
                
                /* Button styles */
                .btn-light {
                    background: #f1f5f9;
                    border: 1px solid #e2e8f0;
                    padding: 0.25rem 0.5rem;
                    font-size: 0.875rem;
                    line-height: 1.5;
                    border-radius: 0.2rem;
                    margin-left: 0.5rem;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                
                .btn-light:hover {
                    background: #e2e8f0;
                }
                
                /* Flex utilities */
                .d-flex { display: flex !important; }
                .align-items-center { align-items: center !important; }
                .mr-1 { margin-right: 0.25rem !important; }
                .mr-2 { margin-right: 0.5rem !important; }
                
                /* Font utilities */
                .font-weight-bold { font-weight: 600 !important; }
                
                /* Performance optimizations */
                .data-table {
                    contain: content;
                }
                
                .section {
                    contain: content;
                }
                
                @media (prefers-reduced-motion: reduce) {
                    * {
                        animation: none !important;
                        transition: none !important;
                    }
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>MongoDB Data Viewer</h1>
                <p>Real-time view of cybersecurity threat intelligence data</p>
            </div>
            
            <div class="stats-container">
                <div class="stat-card">
                    <h3>Total URLs Analyzed</h3>
                    <div class="value">{{ data.collection_stats.urls }}</div>
                </div>
                <div class="stat-card">
                    <h3>Malicious Domains</h3>
                    <div class="value">{{ data.collection_stats.mal_domains }}</div>
                </div>
                <div class="stat-card">
                    <h3>Threat Categories</h3>
                    <div class="value">{{ data.collection_stats.types }}</div>
                </div>
                <div class="stat-card">
                    <h3>Threat Assessments</h3>
                    <div class="value">{{ data.collection_stats.threat_scores }}</div>
                </div>
            </div>
            
            <div class="container">
                <div class="section">
                    <h2>URL Types Distribution</h2>
                    {{ tables.url_types | safe }}
                </div>
                
                <div class="section">
                    <h2>Threat Scores by Type</h2>
                    {{ tables.threat_scores | safe }}
                </div>
                
                <div class="section">
                    <h2>Malicious Domains</h2>
                    {{ tables.top_domains | safe }}
                    <div class="pagination-container">
                        {{ data.pagination.mal_domains.links | safe }}
                    </div>
                </div>
                
                <div class="section">
                    <h2>Recent Analyzed URLs</h2>
                    {{ tables.recent_urls | safe }}
                    <div class="pagination-container">
                        {{ data.pagination.urls.links | safe }}
                    </div>
                </div>
                
                <div class="buttons-container">
                    <button class="refresh-button" onclick="location.reload()">
                        Refresh Dashboard
                    </button>
                    <span class="auto-refresh-text">Data cached for 1 minute • Click refresh for latest data</span>
                </div>
            </div>
            
            <script>
                // Reduced auto-refresh frequency for better performance
                setTimeout(function() {
                    location.reload();
                }, 60000); // 1 minute instead of 30 seconds
            </script>
        </body>
        </html>
    """, tables=tables_html, data=data)

def find_free_port(start_port=5002):
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

def start_mongodb_viewer(port=None):
    """Start the MongoDB data viewer on a different port"""
    try:
        # Check for port argument
        import sys
        if port is None:
            port = 5002  # default port
            if len(sys.argv) > 1:
                try:
                    port = int(sys.argv[1])
                except ValueError:
                    print(f"Invalid port number: {sys.argv[1]}. Using default port 5002.")
        
        # Kill any existing process on the target port
        import os
        os.system(f"lsof -ti:{port} | xargs kill -9 2>/dev/null")
        
        print(f"\n=== MongoDB Data Viewer ===")
        print(f"Access the MongoDB viewer at: http://localhost:{port}")
        print("Press Ctrl+C to stop the server")
        print("="*30 + "\n")
        
        app.run(host='0.0.0.0', port=port, debug=False)
    except Exception as e:
        print(f"Error starting MongoDB viewer: {e}")
        print("Please try accessing the main dashboard at http://localhost:5001")

if __name__ == '__main__':
    start_mongodb_viewer()