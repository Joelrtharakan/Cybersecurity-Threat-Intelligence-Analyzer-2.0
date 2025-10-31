"""
ml_predict.py
Excellent for classification tasks
Handles mixed data types well
Less prone to overfitting than other models
Good performance on tabular data
Trains an optimized ML model with reduced training time and improved accuracy.
"""

from pymongo import MongoClient
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
from joblib import Parallel, delayed, dump
import warnings
import re
from sklearn.exceptions import ConvergenceWarning

# Suppress warnings
warnings.filterwarnings('ignore', category=ConvergenceWarning)
warnings.filterwarnings('ignore', category=UserWarning)

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "cyber_intel"
COLL_NAME = "urls"

# Initialize MongoDB connection
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
col = db[COLL_NAME]

def calculate_entropy(text):
    """Calculate entropy of text string"""
    if not text:
        return 0
    probs = [text.count(c)/len(text) for c in set(text)]
    return -sum(p * np.log2(p) for p in probs)

def process_chunk(urls):
    """Process a chunk of URLs in parallel"""
    features = pd.DataFrame(index=urls.index)
    
    # Prepare strings
    url_strings = urls['url'].fillna('')
    domain_strings = urls['domain'].fillna('')
    
    # Basic features
    features['domain_length'] = domain_strings.str.len()
    features['special_char_count'] = url_strings.str.count(r'[^a-zA-Z0-9]')
    features['digit_count'] = url_strings.str.count(r'[0-9]')
    features['digit_ratio'] = features['digit_count'] / urls['url_length']
    features['is_ip_address'] = domain_strings.str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').astype(int)
    
    # Security patterns
    suspicious_pattern = r'login|bank|paypal|secure|account|update|verify|signin|password'
    features['has_suspicious_words'] = url_strings.str.contains(suspicious_pattern, case=False, regex=True).astype(int)
    features['security_risk_score'] = url_strings.str.count(r'[<>\'";\(\)]|://.*://')
    
    return features

def add_features(df):
    """Add features to the dataframe"""
    # Process in chunks
    chunk_size = min(5000, len(df))
    n_chunks = (len(df) + chunk_size - 1) // chunk_size
    chunks = np.array_split(df, n_chunks)
    
    # Parallel processing
    results = Parallel(n_jobs=-1, prefer="threads")(
        delayed(process_chunk)(chunk) for chunk in chunks
    )
    features = pd.concat(results)
    
    # Combine features
    df = pd.concat([df, features], axis=1)
    
    # Additional features
    df['path_length'] = df['url'].str.len() - df['domain'].str.len()
    df['dir_count'] = df['url'].str.count('/')
    df['has_www'] = df['domain'].str.startswith('www.').astype(int)
    df['has_params'] = df['url'].str.contains(r'\?').astype(int)
    
    return df

def main():
    print("Loading data...")
    # Use smaller sample for faster processing
    sample_size = 20000
    
    # MongoDB aggregation pipeline
    pipeline = [
        {"$sample": {"size": sample_size}},
        {"$project": {
            "url_length": 1,
            "num_subdomains": 1,
            "has_https": 1,
            "domain": 1,
            "url": 1,
            "type": 1
        }}
    ]
    
    # Load and prepare data
    data = list(col.aggregate(pipeline))
    df = pd.DataFrame(data)
    
    print("Processing features...")
    df['has_https'] = df['has_https'].astype('int8')
    df['url_length'] = df['url_length'].astype('int16')
    df = df.dropna(subset=['url', 'type'])
    
    # Add features
    df = add_features(df)
    
    # Select features
    feature_columns = [
        'url_length', 'domain_length', 'has_suspicious_words',
        'special_char_count', 'digit_ratio', 'is_ip_address',
        'security_risk_score', 'has_www', 'has_params',
        'path_length', 'dir_count', 'has_https'
    ]
    
    # Prepare data for training
    X = df[feature_columns]
    y = df['type']
    
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print("Training model...")
    model = GradientBoostingClassifier(
        n_estimators=100,
        max_depth=8,
        learning_rate=0.1,
        min_samples_split=20,
        min_samples_leaf=10,
        subsample=0.8,
        random_state=42,
        n_iter_no_change=3,
        validation_fraction=0.1
    )
    
    model.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = model.predict(X_test)
    accuracy = (y_pred == y_test).mean()
    print(f"\nAccuracy: {accuracy:.3f}")
    
    clf_report = classification_report(y_test, y_pred)
    print("\nClassification Report:")
    print(clf_report)
    
    conf_matrix = confusion_matrix(y_test, y_pred)
    feature_importance = list(zip(feature_columns, model.feature_importances_))
    
    # Store metrics
    metrics = {
        'accuracy': float(accuracy),
        'classification_report': clf_report,
        'confusion_matrix': conf_matrix.tolist(),
        'feature_importance': [{'feature': f, 'importance': float(i)} for f, i in feature_importance]
    }
    
    print("Updating metrics in database...")
    db['ml_metrics'].replace_one({}, metrics, upsert=True)
    
    print("Saving model...")
    dump(model, 'threat_detector.joblib')
    print("Done!")

if __name__ == '__main__':
    main()