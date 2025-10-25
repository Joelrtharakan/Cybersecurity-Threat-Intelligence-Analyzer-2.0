"""
visualize.py
Pulls MapReduce result collections and produces PNGs for your report/ppt.
Saves charts to report/images/
"""

import os
from pymongo import MongoClient
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'report', 'images')
os.makedirs(OUT_DIR, exist_ok=True)

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

def plot_top_types(n=10):
    cur = db['counts_by_type'].find().sort('value', -1).limit(n)
    rows = [(d['_id'], d['value']) for d in cur]
    if not rows:
        print("No data in counts_by_type. Run mapreduce_queries.py first.")
        return
    df = pd.DataFrame(rows, columns=['type','count'])
    df.set_index('type', inplace=True)
    ax = df.plot(kind='bar', legend=False, figsize=(10,6))
    ax.set_title('Top URL Types')
    ax.set_ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    out = os.path.join(OUT_DIR, 'top_types.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_top_mal_domains(n=15):
    cur = db['mal_domains'].find().sort('value', -1).limit(n)
    rows = [(d['_id'], d['value']) for d in cur]
    if not rows:
        print("No data in mal_domains. Run mapreduce_queries.py first.")
        return
    df = pd.DataFrame(rows, columns=['domain','count'])
    df.set_index('domain', inplace=True)
    ax = df.plot(kind='bar', legend=False, figsize=(12,6))
    ax.set_title('Top Malicious Domains')
    ax.set_ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    out = os.path.join(OUT_DIR, 'top_malicious_domains.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_tld_distribution(n=20):
    cur = db['malicious_tld_counts'].find().sort('value', -1).limit(n)
    rows = [(d['_id'], d['value']) for d in cur]
    if not rows:
        print("No data in malicious_tld_counts. Run mapreduce_queries.py first.")
        return
    df = pd.DataFrame(rows, columns=['tld','count']).set_index('tld')
    ax = df.plot(kind='pie', y='count', figsize=(8,8), legend=False, autopct='%1.1f%%')
    ax.set_ylabel('')
    ax.set_title('Top TLDs for Malicious URLs')
    out = os.path.join(OUT_DIR, 'malicious_tld_pie.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_threat_scores():
    cur = db['threat_scores'].find()
    rows = [(d['_id'], d['avg_threat_score']) for d in cur]
    if not rows:
        print("No data in threat_scores.")
        return
    df = pd.DataFrame(rows, columns=['type','avg_score'])
    df.set_index('type', inplace=True)
    ax = df.plot(kind='bar', legend=False, figsize=(10,6))
    ax.set_title('Average Threat Scores by Type')
    ax.set_ylabel('Score')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    out = os.path.join(OUT_DIR, 'threat_scores.png')
    plt.savefig(out)
    plt.close()
    print("Saved:", out)

def plot_country_map():
    # Get country data
    cur = db['country_counts'].find()
    rows = [(d['_id'], d.get('count', 0), d.get('country_name', '')) for d in cur]
    if not rows:
        print("No data in country_counts.")
        return
    
    # Create DataFrame and filter out the "OTHER" category
    df = pd.DataFrame(rows, columns=['country', 'count', 'country_name'])
    df = df[df['country'] != 'OTHER']
    
    if df.empty:
        print("No valid country data available.")
        return
    
    # Normalize the counts for better visualization
    df['count_normalized'] = np.log1p(df['count'])  # log transformation for better color distribution
    
    # Create a more detailed choropleth map
    fig = px.choropleth(
        df,
        locations='country',
        locationmode='ISO-3',
        color='count',
        hover_name='country_name',
        color_continuous_scale=[
            [0, '#edf8fb'],      # Lightest shade
            [0.2, '#b2e2e2'],
            [0.4, '#66c2a4'],
            [0.6, '#2ca25f'],
            [0.8, '#006d2c'],    # Darkest shade
        ],
        range_color=[df['count'].min(), df['count'].max()],
        title='Global Distribution of Malicious URLs',
        labels={'count': 'Number of Malicious URLs'},
    )
    
    # Enhance the map layout
    fig.update_layout(
        title={
            'text': 'Global Distribution of Malicious URLs',
            'y':0.95,
            'x':0.5,
            'xanchor': 'center',
            'yanchor': 'top',
            'font': {'size': 24, 'color': '#2C3E50'}
        },
        paper_bgcolor='rgba(255,255,255,0.8)',
        plot_bgcolor='rgba(255,255,255,0.8)',
        geo=dict(
            showframe=True,
            showcoastlines=True,
            projection_type='equirectangular',
            coastlinecolor='#95a5a6',
            showocean=True,
            oceancolor='#edf8fb',
            showland=True,
            landcolor='#ffffff',
            showcountries=True,
            countrycolor='#bdc3c7',
            countrywidth=0.5,
            lonaxis=dict(
                showgrid=True,
                gridwidth=0.5,
                gridcolor='#ecf0f1'
            ),
            lataxis=dict(
                showgrid=True,
                gridwidth=0.5,
                gridcolor='#ecf0f1'
            )
        ),
        width=1200,
        height=800,
        margin={"r":60,"t":80,"l":60,"b":40},
        coloraxis_colorbar=dict(
            title='Number of<br>Malicious URLs',
            thicknessmode="pixels",
            thickness=20,
            lenmode="pixels",
            len=300,
            yanchor="middle",
            y=0.5,
            xanchor="right",
            x=0.98,
            bgcolor='rgba(255,255,255,0.8)',
            bordercolor='#2C3E50',
            borderwidth=1,
            titlefont=dict(size=14, color='#2C3E50'),
            tickfont=dict(size=12, color='#2C3E50')
        )
    )
    
    # Add hover template with more details
    fig.update_traces(
        hovertemplate=(
            '<b>%{customdata[0]}</b><br>' +
            'Malicious URLs: %{z:,.0f}<br>' +
            '<extra></extra>'
        ),
        customdata=df[['country_name']].values
    )
    
    out = os.path.join(OUT_DIR, 'country_map.html')
    fig.write_html(out, include_plotlyjs=True, full_html=True)
    print("Saved:", out)

def main():
    plot_top_types()
    plot_top_mal_domains()
    plot_tld_distribution()
    plot_threat_scores()
    plot_country_map()

if __name__ == '__main__':
    main()