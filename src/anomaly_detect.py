"""
anomaly_detect.py
Detects anomalies in URL counts using z-score.
"""

from pymongo import MongoClient
import numpy as np
from scipy import stats

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

def detect_anomalies(collection, field):
    cursor = db[collection].find({}, {field: 1})
    values = [doc[field] for doc in cursor if field in doc]
    if not values:
        return []
    z_scores = np.abs(stats.zscore(values))
    anomalies = [i for i, z in enumerate(z_scores) if z > 3]
    return anomalies

def main():
    print("Detecting anomalies in counts_by_type...")
    anomalies = detect_anomalies('counts_by_type', 'value')
    print(f"Anomalous indices: {anomalies}")

    print("Detecting anomalies in threat_scores...")
    anomalies = detect_anomalies('threat_scores', 'avg_threat_score')
    print(f"Anomalous indices: {anomalies}")

if __name__ == '__main__':
    main()