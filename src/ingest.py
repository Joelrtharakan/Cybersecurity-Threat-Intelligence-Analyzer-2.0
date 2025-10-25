"""
ingest.py
Bulk inserts data/processed_urls.json (JSON lines) into MongoDB collection cyber_intel.urls
"""

import os
import json
from pymongo import MongoClient, InsertOne
from tqdm import tqdm

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
INPATH = os.path.join(DATA_DIR, 'processed_urls.json')

MONGO_URI = "mongodb://localhost:27017/"  # change if needed
DB_NAME = "cyber_intel"
COLL_NAME = "urls"
BATCH_SIZE = 2000

def main():
    if not os.path.exists(INPATH):
        raise FileNotFoundError(f"{INPATH} not found. Run preprocess.py first.")
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLL_NAME]
    # Optional: create indexes after inserting
    total = 0
    batch = []
    with open(INPATH, 'r', encoding='utf-8') as fin:
        for line in tqdm(fin, desc='Reading JSON lines'):
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            batch.append(InsertOne(doc))
            if len(batch) >= BATCH_SIZE:
                res = col.bulk_write(batch)
                total += len(batch)
                batch = []
        if batch:
            res = col.bulk_write(batch)
            total += len(batch)
    print(f"Inserted (approx): {total} documents into {DB_NAME}.{COLL_NAME}")

    print("Creating indexes on domain, type, tld")
    col.create_index("domain")
    col.create_index("type")
    col.create_index("tld")
    col.create_index("url_length")
    print("Done.")

if __name__ == '__main__':
    main()