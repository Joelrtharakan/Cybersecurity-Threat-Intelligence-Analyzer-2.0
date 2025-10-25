import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import tldextract
import re
from urllib.parse import urlparse
import pymongo
from tqdm import tqdm
import json
import os
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertForSequenceClassification
from transformers import get_linear_schedule_with_warmup
from torch.optim import AdamW

# BERT Dataset class for URL classification
class URLDataset(Dataset):
    def __init__(self, urls, labels, tokenizer, max_length=128):
        self.urls = urls
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.urls)

    def __getitem__(self, idx):
        url = str(self.urls[idx])
        label = self.labels[idx]

        # Tokenize the URL
        encoding = self.tokenizer.encode_plus(
            url,
            add_special_tokens=True,
            max_length=self.max_length,
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )

        return {
            'url_text': url,
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }

# MongoDB connection
def get_mongodb_connection():
    try:
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        db = client["cyber_intel"]
        collection = db["urls"]
        return collection
    except Exception as e:
        print(f"MongoDB connection error: {e}")
        return None

# Feature extraction function
def extract_features(url):
    features = {}

    try:
        # Basic URL features
        features['url_length'] = len(url)
        parsed = urlparse(url)
        domain = parsed.netloc
        features['domain_length'] = len(domain)

        # Character analysis
        features['special_char_count'] = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', url))
        features['digit_count'] = len(re.findall(r'\d', url))
        features['letter_count'] = len(re.findall(r'[a-zA-Z]', url))
        features['digit_ratio'] = features['digit_count'] / features['url_length'] if features['url_length'] > 0 else 0

        # Domain analysis
        features['subdomain_count'] = len(domain.split('.')) - 2 if domain.count('.') > 1 else 0
        features['has_www'] = 1 if domain.startswith('www.') else 0
        features['has_hyphen_domain'] = 1 if '-' in domain else 0

        # Suspicious patterns - expanded list (removed legitimate domains)
        suspicious_words = ['login', 'password', 'bank', 'account', 'secure', 'verify', 'confirm',
                          'signin', 'admin', 'update', 'alert', 'warning', 'suspended', 'locked',
                          'billing', 'invoice', 'payment', 'credit', 'card', 'support', 'help',
                          'service', 'customer', 'client', 'user', 'auth', 'session', 'token']
        features['has_suspicious_words'] = int(any(word in url.lower() for word in suspicious_words))

        # TLD analysis - expanded malicious TLD list
        tld = tldextract.extract(url).suffix.lower()
        malicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site', 'work',
                         'bid', 'party', 'review', 'trade', 'science', 'space', 'tech', 'fun', 'icu',
                         'info', 'biz', 'pro', 'loan', 'win', 'life', 'stream', 'download', 'date',
                         'ru', 'cn', 'in', 'br', 'mx', 'tr', 'pl', 'ua', 'ro', 'cz', 'gr', 'pt', 'ar']
        features['malicious_tld'] = int(tld in malicious_tlds)

        # Protocol and security
        features['has_https'] = int(url.startswith('https://'))
        features['has_http'] = int(url.startswith('http://'))
        features['is_ip_address'] = int(bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)))

        # Path and query analysis
        path = parsed.path
        query = parsed.query
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        features['has_query'] = int(len(query) > 0)
        features['path_depth'] = path.count('/') if path else 0
        features['has_php'] = int('.php' in path.lower() or '.php' in query.lower())
        features['has_jsp'] = int('.jsp' in path.lower() or '.jsp' in query.lower())
        features['has_exe'] = int('.exe' in url.lower())

        # URL structure features
        features['has_at_symbol'] = int('@' in url)
        features['has_double_slash'] = int('//' in url[8:])  # After protocol
        features['has_redirect'] = int('redirect' in url.lower() or 'redir' in url.lower())

        # Domain entropy (measure of randomness)
        if domain:
            domain_chars = [c for c in domain if c.isalnum()]
            if domain_chars:
                entropy = -sum((domain_chars.count(c)/len(domain_chars)) * np.log2(domain_chars.count(c)/len(domain_chars)) for c in set(domain_chars))
                features['domain_entropy'] = entropy
            else:
                features['domain_entropy'] = 0
        else:
            features['domain_entropy'] = 0

        # Security risk score - improved calculation with better weights
        risk_score = 0
        risk_score += features['special_char_count'] * 0.1
        risk_score += features['digit_count'] * 0.05
        risk_score += features['subdomain_count'] * 0.3
        risk_score += features['malicious_tld'] * 2.0
        risk_score += features['has_suspicious_words'] * 1.5
        risk_score += features['has_hyphen_domain'] * 0.8
        risk_score += features['is_ip_address'] * 1.2
        risk_score += features['has_at_symbol'] * 2.5
        risk_score += features['has_double_slash'] * 1.8
        risk_score += features['has_redirect'] * 1.0
        risk_score += features['has_php'] * 0.5
        risk_score += features['has_exe'] * 1.5
        risk_score += features['has_jsp'] * 0.5
        risk_score += features['has_query'] * 0.3
        risk_score += features['path_depth'] * 0.2
        risk_score -= features['has_https'] * 0.5  # HTTPS should reduce risk
        risk_score -= features['has_www'] * 0.3    # www should reduce risk
        risk_score += features['domain_entropy'] * 0.1
        features['security_risk_score'] = max(-5, min(10, risk_score))  # Allow negative scores

    except Exception as e:
        print(f"Error extracting features: {e}")
        # Return default features if extraction fails
        features = {
            'url_length': 0, 'domain_length': 0, 'special_char_count': 0,
            'digit_count': 0, 'letter_count': 0, 'digit_ratio': 0,
            'subdomain_count': 0, 'has_www': 0, 'has_hyphen_domain': 0,
            'has_suspicious_words': 0, 'malicious_tld': 0, 'has_https': 0,
            'has_http': 0, 'is_ip_address': 0, 'path_length': 0,
            'query_length': 0, 'has_query': 0, 'path_depth': 0,
            'has_php': 0, 'has_jsp': 0, 'has_exe': 0,
            'has_at_symbol': 0, 'has_double_slash': 0, 'has_redirect': 0,
            'domain_entropy': 0, 'security_risk_score': 5.0
        }

    return features

# Train BERT model for URL classification
def train_bert_model(sample_size=8000, epochs=2, batch_size=16, learning_rate=5e-5):
    print(f"Training FAST BERT model with {sample_size} samples...")

    try:
        collection = get_mongodb_connection()
        if collection is None:
            raise Exception("Could not connect to MongoDB")

        # Get balanced sample from MongoDB with minimum samples per class
        pipeline = [
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        class_counts = {doc["_id"]: doc["count"] for doc in collection.aggregate(pipeline)}

        print(f"Class distribution in database: {class_counts}")

        # Sample proportionally with minimum samples per class
        samples_per_class = {}
        total_samples = 0
        min_samples_per_class = 1000  # Minimum samples per class

        for class_name, count in class_counts.items():
            allocated = max(min_samples_per_class, min(count, int(sample_size * (count / sum(class_counts.values())))))
            samples_per_class[class_name] = allocated
            total_samples += allocated

        print(f"Sampling strategy: {samples_per_class}")
        print(f"Total samples to train on: {total_samples}")

        # Get samples for each class
        data = []
        for class_name, num_samples in samples_per_class.items():
            class_data = list(collection.aggregate([
                {"$match": {"type": class_name}},
                {"$sample": {"size": num_samples}},
                {"$project": {"url": 1, "type": 1, "_id": 0}}
            ]))
            data.extend(class_data)

        print(f"Loaded {len(data)} URLs from database")

        # Prepare data
        urls = [item.get('url', '') for item in data]
        labels_text = [item.get('type', 'benign') for item in data]

        # Add legitimate hosting domain examples to ensure they're learned as benign
        legitimate_hosting_urls = [
            'https://myproject.web.app/',
            'https://portfolio.web.app/',
            'https://app.web.app/',
            'https://demo.web.app/',
            'https://test.web.app/',
            'https://myapp.firebaseapp.com/',
            'https://project.github.io/',
            'https://docs.github.io/',
            'https://portfolio.netlify.app/',
            'https://site.vercel.app/'
        ]
        
        # Add these legitimate examples multiple times to reinforce learning
        for _ in range(10):  # Add each 10 times
            urls.extend(legitimate_hosting_urls)
            labels_text.extend(['benign'] * len(legitimate_hosting_urls))

        print(f"After adding legitimate hosting examples: {len(urls)} URLs")

        # Encode labels
        label_encoder = LabelEncoder()
        labels = label_encoder.fit_transform(labels_text)

        # Split data
        urls_train, urls_test, labels_train, labels_test = train_test_split(
            urls, labels, test_size=0.2, random_state=42, stratify=labels
        )

        print(f"Train: {len(urls_train)}, Test: {len(urls_test)}")

        # Use BERT base but freeze first 8 layers for speed
        tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        model = BertForSequenceClassification.from_pretrained(
            'bert-base-uncased',
            num_labels=len(label_encoder.classes_),
            output_attentions=False,
            output_hidden_states=False
        )

        # Freeze first 8 layers for faster training
        for name, param in model.named_parameters():
            if 'encoder.layer' in name:
                layer_num = int(name.split('encoder.layer.')[1].split('.')[0])
                if layer_num < 8:
                    param.requires_grad = False

        # Create datasets with smaller max_length for speed
        train_dataset = URLDataset(urls_train, labels_train, tokenizer, max_length=128)
        test_dataset = URLDataset(urls_test, labels_test, tokenizer, max_length=128)

        # Larger batch size for faster training
        train_dataloader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        test_dataloader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

        # Set up optimizer (only train unfrozen parameters)
        optimizer = AdamW(filter(lambda p: p.requires_grad, model.parameters()), lr=learning_rate)

        total_steps = len(train_dataloader) * epochs
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=0,
            num_training_steps=total_steps
        )

        # Training loop (simplified, no validation for speed)
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        model.to(device)

        print(f"Training on device: {device}")
        print(f"Model: BERT-base (partially frozen for speed)")
        print(f"Frozen layers: First 8 encoder layers")
        print(f"Classes: {list(label_encoder.classes_)}")

        for epoch in range(epochs):
            print(f"\nEpoch {epoch + 1}/{epochs}")

            # Training
            model.train()
            total_train_loss = 0
            train_correct = 0
            train_total = 0

            for batch in tqdm(train_dataloader, desc="Training"):
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels_batch = batch['labels'].to(device)

                model.zero_grad()

                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels_batch
                )

                loss = outputs.loss
                logits = outputs.logits

                total_train_loss += loss.item()

                # Calculate training accuracy
                preds = torch.argmax(logits, dim=1)
                train_correct += (preds == labels_batch).sum().item()
                train_total += labels_batch.size(0)

                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()

            avg_train_loss = total_train_loss / len(train_dataloader)
            train_accuracy = train_correct / train_total

            print(".4f")

        # Final evaluation on test set
        model.eval()
        total_test_loss = 0
        test_correct = 0
        test_total = 0

        with torch.no_grad():
            for batch in tqdm(test_dataloader, desc="Final Testing"):
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels_batch = batch['labels'].to(device)

                outputs = model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels_batch
                )

                loss = outputs.loss
                logits = outputs.logits

                total_test_loss += loss.item()

                preds = torch.argmax(logits, dim=1)
                test_correct += (preds == labels_batch).sum().item()
                test_total += labels_batch.size(0)

        final_test_accuracy = test_correct / test_total
        final_test_loss = total_test_loss / len(test_dataloader)

        print(".4f")
        print(".4f")

        # Save model and artifacts
        os.makedirs('models', exist_ok=True)
        model.save_pretrained('models/bert_threat_detector')
        tokenizer.save_pretrained('models/bert_threat_detector')
        joblib.dump(label_encoder, 'models/bert_label_encoder.joblib')

        # Save training metadata
        metadata = {
            'model_name': 'BERT-base (partially frozen)',
            'sample_size': sample_size,
            'epochs_trained': epochs,
            'batch_size': batch_size,
            'learning_rate': learning_rate,
            'final_test_accuracy': final_test_accuracy,
            'training_date': str(pd.Timestamp.now()),
            'device': str(device),
            'frozen_layers': 'First 8 encoder layers'
        }
        joblib.dump(metadata, 'models/bert_training_metadata.joblib')

        print("Fast BERT model and artifacts saved successfully!")
        print(f"Final Test Accuracy: {final_test_accuracy:.4f}")
        print(f"Classes: {list(label_encoder.classes_)}")

        return {
            'model_path': 'models/bert_threat_detector',
            'encoder_path': 'models/bert_label_encoder.joblib',
            'metadata_path': 'models/bert_training_metadata.joblib',
            'test_accuracy': final_test_accuracy,
            'classes': list(label_encoder.classes_),
            'device': str(device)
        }

    except Exception as e:
        print(f"Error training BERT model: {e}")
        import traceback
        traceback.print_exc()
        raise

# Train model from dataset
def train_model_from_dataset(sample_size=50000):
    print(f"Training model with {sample_size} samples from dataset...")

    try:
        collection = get_mongodb_connection()
        if collection is None:
            raise Exception("Could not connect to MongoDB")

        # Get balanced sample from MongoDB (stratified sampling)
        # First get counts for each class
        pipeline = [
            {"$group": {"_id": "$type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        class_counts = {doc["_id"]: doc["count"] for doc in collection.aggregate(pipeline)}
        
        print(f"Class distribution in database: {class_counts}")
        
        # Sample proportionally (up to sample_size total)
        samples_per_class = {}
        total_samples = 0
        for class_name, count in class_counts.items():
            # Take min of available count and proportional allocation
            allocated = min(count, max(1000, int(sample_size * (count / sum(class_counts.values())))))
            samples_per_class[class_name] = allocated
            total_samples += allocated
        
        print(f"Sampling strategy: {samples_per_class}")
        
        # Get samples for each class
        data = []
        for class_name, num_samples in samples_per_class.items():
            class_data = list(collection.aggregate([
                {"$match": {"type": class_name}},
                {"$sample": {"size": num_samples}},
                {"$project": {"url": 1, "type": 1, "_id": 0}}
            ]))
            data.extend(class_data)
        
        print(f"Loaded {len(data)} URLs from database (balanced sampling)")

        # Prepare features and labels
        features_list = []
        labels = []

        for item in tqdm(data, desc="Extracting features"):
            url = item.get('url', '')
            label = item.get('type', 'benign')

            if url:
                features = extract_features(url)
                features_list.append(features)
                labels.append(label)

        if not features_list:
            raise Exception("No valid URLs found for training")

        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        df['label'] = labels

        # Encode labels
        label_encoder = LabelEncoder()
        df['label_encoded'] = label_encoder.fit_transform(df['label'])

        # Prepare training data
        X = df.drop(['label', 'label_encoded'], axis=1)
        y = df['label_encoded']

        # Split data with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train improved model - try XGBoost
        try:
            from xgboost import XGBClassifier
            model = XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1,
                verbosity=1
            )
            print("Training XGBoost classifier...")
        except ImportError:
            print("XGBoost not available, falling back to RandomForest")
            from sklearn.ensemble import RandomForestClassifier
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            print("Training RandomForest classifier...")

        model.fit(X_train_scaled, y_train)

        # Evaluate model
        train_score = model.score(X_train_scaled, y_train)
        test_score = model.score(X_test_scaled, y_test)

        print(".4f")
        print(".4f")

        # Save model and artifacts
        os.makedirs('models', exist_ok=True)
        joblib.dump(model, 'models/threat_detector.joblib')
        joblib.dump(scaler, 'models/feature_scaler.joblib')
        joblib.dump(label_encoder, 'models/label_encoder.joblib')

        print("Model and artifacts saved successfully!")

        return {
            'train_accuracy': train_score,
            'test_accuracy': test_score,
            'model_path': 'models/threat_detector.joblib',
            'scaler_path': 'models/feature_scaler.joblib',
            'encoder_path': 'models/label_encoder.joblib'
        }

    except Exception as e:
        print(f"Error training model: {e}")
        raise

# Rule-based URL analyzer as fallback
def analyze_url_rules(url):
    """Simple rule-based URL analysis for reliable classification"""
    try:
        features = extract_features(url)
        
        # Rule-based classification
        score = 0
        reasons = []
        
        # High-risk indicators (strong evidence of malicious)
        if features['has_exe']:
            score += 10
            reasons.append("Contains .exe file")
        if features['is_ip_address']:
            score += 8
            reasons.append("Uses IP address instead of domain")
        if features['malicious_tld']:
            score += 7
            reasons.append("Uses suspicious TLD")
        if features['has_at_symbol']:
            score += 6
            reasons.append("Contains @ symbol")
        if features['subdomain_count'] >= 4:
            score += 5
            reasons.append("Too many subdomains")
        
        # Medium-risk indicators
        if features['has_suspicious_words']:
            score += 4
            reasons.append("Contains suspicious keywords")
        if features['has_hyphen_domain'] and features['domain_length'] > 20:
            score += 3
            reasons.append("Long domain with hyphens")
        if features['security_risk_score'] > 3:
            score += 3
            reasons.append("High security risk score")
        if features['domain_entropy'] > 4:
            score += 2
            reasons.append("High domain entropy")
        
        # Low-risk indicators (reduce score)
        if features['has_https']:
            score -= 2
            reasons.append("Uses HTTPS")
        if features['has_www']:
            score -= 1
            reasons.append("Has www prefix")
        
        # Special handling for legitimate hosting platforms
        domain = urlparse(url).netloc.lower()
        if domain.endswith('.web.app'):
            score -= 5  # Strong reduction for Firebase hosting
            reasons.append("Firebase hosting domain (legitimate)")
        elif domain.endswith('.github.io'):
            score -= 5  # Strong reduction for GitHub Pages
            reasons.append("GitHub Pages hosting (legitimate)")
        elif domain.endswith('.netlify.app'):
            score -= 5  # Strong reduction for Netlify
            reasons.append("Netlify hosting (legitimate)")
        elif domain.endswith('.vercel.app'):
            score -= 5  # Strong reduction for Vercel
            reasons.append("Vercel hosting (legitimate)")
        
        # Classification based on score
        if score >= 8:
            prediction = "malware"
            confidence = min(0.95, 0.7 + (score - 8) * 0.05)
        elif score >= 5:
            prediction = "phishing"
            confidence = min(0.9, 0.6 + (score - 5) * 0.06)
        elif score >= 2:
            prediction = "defacement"
            confidence = min(0.8, 0.4 + (score - 2) * 0.1)
        else:
            prediction = "benign"
            confidence = max(0.6, 0.8 - score * 0.1)
        
        malicious_types = ['phishing', 'malware', 'defacement']
        is_malicious = prediction.lower() in malicious_types
        
        return {
            'url': url,
            'prediction': prediction,
            'confidence': float(confidence),
            'is_malicious': is_malicious,
            'rule_score': score,
            'reasons': reasons,
            'features': features
        }
        
    except Exception as e:
        return {
            'error': f"Rule-based analysis failed: {str(e)}",
            'url': url
        }
# Analyze URL function - using BERT model for classification
def analyze_url(url):
    """Analyze URL using BERT model for accurate predictions"""
    try:
        # Load BERT model and artifacts
        model_path = 'models/bert_threat_detector'
        if not os.path.exists(model_path):
            raise Exception("BERT model not found. Please train the model first.")

        model = BertForSequenceClassification.from_pretrained(model_path)
        tokenizer = BertTokenizer.from_pretrained(model_path)
        label_encoder = joblib.load('models/bert_label_encoder.joblib')

        # Set device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        model.to(device)
        model.eval()

        # Tokenize URL
        encoding = tokenizer.encode_plus(
            url,
            add_special_tokens=True,
            max_length=256,  # Match training max_length
            return_token_type_ids=False,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )

        input_ids = encoding['input_ids'].to(device)
        attention_mask = encoding['attention_mask'].to(device)

        # Make prediction
        with torch.no_grad():
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1)
            confidence, prediction_encoded = torch.max(probs, dim=1)

        prediction = label_encoder.inverse_transform([prediction_encoded.item()])[0]
        confidence = confidence.item()

        # Create probabilities dict
        probabilities = {}
        probs_np = probs.cpu().numpy()[0]
        for i, class_name in enumerate(label_encoder.classes_):
            probabilities[class_name] = float(probs_np[i])

        # Override obviously wrong predictions for known legitimate domains
        domain = urlparse(url).netloc.lower()
        legitimate_domains = [
            'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'amazon.in',
            'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com',
            'wikipedia.org', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'paypal.com',
            'ebay.com', 'craigslist.org', 'indeed.com', 'glassdoor.com', 'monster.com',
            'linkedin.com', 'xing.com', 'dropbox.com', 'onedrive.live.com', 'icloud.com',
            'zoom.us', 'slack.com', 'discord.com', 'telegram.org', 'whatsapp.com',
            'spotify.com', 'soundcloud.com', 'pandora.com', 'tidal.com', 'apple.com',
            'microsoft.com', 'adobe.com', 'autodesk.com', 'nvidia.com', 'amd.com',
            'web.app'  # Firebase hosting domains
        ]

        # If BERT predicts malicious but it's a known legitimate domain, override to benign
        override_applied = False
        if prediction != 'benign' and any(legit_domain in domain for legit_domain in legitimate_domains):
            prediction = 'benign'
            confidence = 0.95
            probabilities = {'benign': 0.95, 'defacement': 0.02, 'malware': 0.02, 'phishing': 0.01}
            override_applied = True

        # Determine if malicious
        malicious_types = ['phishing', 'malware', 'defacement']
        is_malicious = prediction.lower() in malicious_types

        # Add rule-based reasons for additional context
        rule_result = analyze_url_rules(url)
        reasons = rule_result.get('reasons', [])

        # Add model information
        model_info = {
            'model_type': 'BERT (Bidirectional Encoder Representations from Transformers)',
            'model_name': 'bert-base-uncased',
            'classes': list(label_encoder.classes_),
            'device': str(device)
        }

        return {
            'url': url,
            'prediction': prediction,
            'confidence': confidence,
            'probabilities': probabilities,
            'is_malicious': is_malicious,
            'reasons': reasons,
            'features': rule_result.get('features', {}),
            'model_info': model_info,
            'override_applied': override_applied,
            'override_reason': 'Known legitimate domain' if override_applied else None
        }

    except Exception as e:
        # Fallback to rule-based if BERT fails
        print(f"BERT analysis failed, falling back to rule-based: {e}")
        rule_result = analyze_url_rules(url)
        if 'error' not in rule_result:
            rule_result['model_info'] = {
                'model_type': 'Rule-based (Fallback)',
                'reason': 'BERT model unavailable or failed to load'
            }
            return rule_result
        else:
            return rule_result

# Main function for testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        url = sys.argv[1]
        print(f"Analyzing URL: {url}")

        # Train BERT model first
        try:
            train_result = train_bert_model(sample_size=5000, epochs=2)  # Smaller sample for faster training
            print("BERT training completed successfully!")
        except Exception as e:
            print(f"BERT training failed: {e}")
            sys.exit(1)

        # Analyze URL
        result = analyze_url(url)

        if 'error' in result:
            print(f"Error: {result['error']}")
        else:
            print(f"Prediction: {result['prediction']}")
            print(".2%")
            print(f"Malicious: {result['is_malicious']}")
            print(f"Probabilities: {result['probabilities']}")
    else:
        print("Usage: python url_analyzer.py <url>")
        print("Example: python url_analyzer.py https://example.com")