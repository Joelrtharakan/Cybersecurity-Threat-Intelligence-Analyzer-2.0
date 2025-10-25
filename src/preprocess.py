"""
preprocess.py
Reads raw URL,label file and outputs processed_urls.json (JSON lines).

Input expected: data/raw_urls.csv or data/raw_urls.txt
Format: two columns (url and label), separator auto-detected.
"""

import os
import pandas as pd
from urllib.parse import urlparse
import tldextract
from tqdm import tqdm
import json
import argparse
import requests

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
RAW_PATHS = [
    os.path.join(DATA_DIR, 'raw_urls.csv'),
    os.path.join(DATA_DIR, 'raw_urls.txt'),
    os.path.join(DATA_DIR, 'raw_urls.tsv'),
    os.path.join(DATA_DIR, 'raw_urls'),
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'malicious_phish.csv')  # Added this file
]
OUTPATH = os.path.join(DATA_DIR, 'processed_urls.json')  # JSON lines

def detect_file():
    for p in RAW_PATHS:
        if os.path.exists(p):
            return p
    raise FileNotFoundError("No raw file found. Place raw file as data/raw_urls.csv or .txt")

def read_data(path):
    # Try common delimiters
    for sep in [',', '\t', ';', '|']:
        try:
            df = pd.read_csv(path, sep=sep, header=None, names=['url','type'], dtype=str, engine='python', keep_default_na=False)
            if df.shape[1] >= 2:
                # Check if first row looks like header
                if df.shape[0] > 0 and df.iloc[0]['url'].strip().lower() == 'url' and df.iloc[0]['type'].strip().lower() == 'type':
                    df = df.iloc[1:].copy()
                # If second column has many non-empty values, assume correct
                if df['type'].notna().sum() > 0:
                    return df
        except Exception:
            continue
    # fallback: read whole file and split first whitespace
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        rows = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            # try split by whitespace into two
            if '\t' in line:
                parts = line.split('\t', 1)
            else:
                parts = line.split(None, 1)
            if len(parts) == 2:
                rows.append(parts)
        return pd.DataFrame(rows, columns=['url','type'])

def normalize_url(u):
    if not u:
        return None
    u = u.strip()
    # If it starts with something like 'www.' or domain only, add http scheme for parser
    if not u.startswith(('http://', 'https://')):
        # Avoid double adding for data like 'http://example' already ok
        u = 'http://' + u
    return u

def get_country(domain):
    # For speed, skip API calls; return 'Unknown'
    return 'Unknown'

def parse_row(u, label):
    try:
        u_norm = normalize_url(u)
        if not u_norm:
            return None
        p = urlparse(u_norm)
        td = tldextract.extract(u_norm)
        domain = '.'.join([s for s in [td.domain, td.suffix] if s]) or p.netloc
        subdomain = td.subdomain or ''
        tld = td.suffix or ''
        path = p.path or ''
        query = p.query or ''
        scheme = p.scheme or ''
        url_length = len(u_norm)
        num_subdomains = 0 if not subdomain else len(subdomain.split('.'))
        has_https = scheme == 'https'
        country = get_country(domain)
        threat_score = (url_length / 100) + (num_subdomains * 2) + (1 if tld in ['tk', 'xyz', 'info', 'top'] else 0)
        # normalize label
        label = (label or '').strip().lower()
        if label == '':
            label = 'unknown'
        return {
            'url': u_norm,
            'type': label,
            'domain': domain,
            'subdomain': subdomain,
            'tld': tld,
            'path': path,
            'query': query,
            'scheme': scheme,
            'has_https': has_https,
            'url_length': url_length,
            'num_subdomains': num_subdomains,
            'country': country,
            'threat_score': threat_score
        }
    except Exception:
        return None

def main():
    path = detect_file()
    print("Reading:", path)
    df = read_data(path)
    print("Rows read:", len(df))
    # Basic cleaning
    df['url'] = df['url'].astype(str).str.strip()
    df['type'] = df['type'].astype(str).str.strip().str.lower()
    # Drop blank URLs
    df = df[df['url'].str.len() > 0].copy()
    print("After dropping empty URLs:", len(df))

    # Parse and convert
    out_file = OUTPATH
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, 'w', encoding='utf-8') as fout:
        for _, row in tqdm(df.iterrows(), total=len(df), desc='Parsing URLs'):
            rec = parse_row(row['url'], row['type'])
            if rec:
                fout.write(json.dumps(rec, ensure_ascii=False) + '\n')
    print("Processed data saved to:", out_file)

if __name__ == '__main__':
    main()