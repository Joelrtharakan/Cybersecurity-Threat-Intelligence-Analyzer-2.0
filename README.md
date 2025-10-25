# Cybersecurity Threat Intelligence Analyzer 🛡️

A comprehensive big data analytics platform for analyzing and detecting malicious URLs using MongoDB, Machine Learning, and interactive visualizations. This system processes large-scale cybersecurity threat data to identify phishing, malware, defacement attacks, and other malicious activities.

![Platform](https://img.shields.io/badge/Platform-Python%20%7C%20MongoDB-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 📋 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#️-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Dataset](#-dataset)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Components](#-components)
- [Machine Learning Model](#-machine-learning-model)
- [Visualizations](#-visualizations)
- [Web Dashboard](#-web-dashboard)
- [API Endpoints](#-api-endpoints)
- [Configuration](#️-configuration)
- [Performance](#-performance)
- [Contributing](#-contributing)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

## 🎯 Overview

The Cybersecurity Threat Intelligence Analyzer is an end-to-end solution for processing, analyzing, and visualizing large-scale cybersecurity threat data. It combines:

- **Big Data Processing**: MongoDB for efficient storage and retrieval of millions of URLs
- **Machine Learning**: BERT (Bidirectional Encoder Representations from Transformers) model for threat detection with 90.8% accuracy
- **Real-time Analytics**: MapReduce aggregations for threat pattern analysis
- **Interactive Dashboards**: Flask-based web interfaces with Plotly visualizations
- **Anomaly Detection**: Statistical analysis using z-scores for outlier identification
- **Geospatial Analysis**: Global threat distribution mapping

## ✨ Features

### Core Capabilities
- **Multi-threaded Data Processing**: Efficiently processes large CSV datasets with progress tracking
- **URL Feature Extraction**:
  - Domain parsing and TLD extraction
  - Subdomain analysis
  - HTTPS detection
  - Special character counting
  - Path and query parameter analysis
  - Suspicious keyword detection
- **Threat Classification**: Categorizes URLs into:
  - Benign
  - Phishing
  - Malware
  - Defacement
- **Advanced Analytics**:
  - Threat score calculation
  - Domain reputation analysis
  - TLD distribution analysis
  - URL length pattern detection
- **Machine Learning Predictions**: Trained model for real-time threat detection
- **Real-time Monitoring**: Change stream monitoring for new threats
- **Interactive Visualizations**:
  - Horizontal bar charts for better data representation
  - Box plots for distribution analysis
  - Geospatial heat maps
  - Confusion matrices
  - Feature importance graphs

### Technical Highlights
- **Scalable Architecture**: Handles millions of records efficiently
- **Batch Processing**: 2000-record batch inserts for optimal performance
- **Parallel Processing**: Multi-core feature extraction
- **Optimized ML Training**: Reduced training time with early stopping
- **Responsive Web UI**: Professional dark-themed dashboard with improved chart layouts
- **RESTful API**: Easy integration with external systems
- **Enhanced Caching**: Implemented chart data caching for improved performance

## 🏗️ Architecture

```
┌─────────────────┐
│  Raw CSV Data   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Preprocess    │ ◄── Feature Extraction, URL Parsing
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   MongoDB       │ ◄── Bulk Insert, Indexing
│  (cyber_intel)  │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌─────────┐ ┌──────────────┐
│MapReduce│ │  ML Training │
└────┬────┘ └──────┬───────┘
     │             │
     │     ┌───────┴──────┐
     │     │              │
     ▼     ▼              ▼
┌─────────────┐    ┌──────────────┐
│Visualization│    │  Dashboard   │
└─────────────┘    └──────────────┘
```

## 🤖 Machine Learning Model

The system employs a BERT (Bidirectional Encoder Representations from Transformers) model for URL threat analysis:

- **Model Architecture**: bert-base-uncased fine-tuned for URL classification
- **Accuracy**: 90.8% test accuracy on malicious/benign URL classification
- **Framework**: PyTorch with Hugging Face Transformers library
- **Training Data**: 650,000+ URLs from Kaggle malicious URLs dataset
- **Features**: Contextual understanding of URL patterns and suspicious keywords
- **Fallback System**: Rule-based analysis for domains like Firebase to prevent false positives
- **Optimization**: Early stopping and hyperparameter tuning for efficient training

## 🔧 Prerequisites

### Required Software
- Python: 3.8 or higher
- MongoDB: 5.0 or higher (running on localhost:27017)
- pip: Python package installer

### System Requirements
- RAM: 4GB minimum (8GB recommended for large datasets)
- Storage: 5GB free space for data and models
- OS: Windows, Linux, or macOS

## � Installation

1. **Clone the Repository**
```bash
git clone https://github.com/Joelrtharakan/Cybersecurity-Threat-Intelligence-Analyzer.git
cd Cybersecurity-Threat-Intelligence-Analyzer
```

2. **Create Virtual Environment**
On Windows (PowerShell):
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```
On Linux/Mac:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Start MongoDB**
On Windows:
```bash
net start MongoDB
```
On Linux/Mac:
```bash
sudo systemctl start mongod
# or
brew services start mongodb-community
```

5. **Verify MongoDB Connection**
```bash
mongosh mongodb://localhost:27017/
```

## 📊 Dataset

### Source
The project uses the Malicious and Benign URLs dataset from Kaggle:

- Dataset Name: malicious_phish.csv
- Source: Kaggle - Malicious URLs Dataset
- Size: ~650,000 URLs
- Format: CSV with two columns: url and type

### Download Instructions
1. Visit Kaggle and download the dataset
2. Place `malicious_phish.csv` in the project root directory:
```
Cybersecurity-Threat-Intelligence-Analyzer/
├── malicious_phish.csv  ← Place here
├── src/
├── requirements.txt
└── ...
```

### Data Format
```csv
url,type
http://example.com,benign
http://phishing-site.com,phishing
http://malware-domain.tk,malware
http://defaced-site.org,defacement
```

## 📈 Visualizations

### Recent Dashboard Improvements
- **Threat Type Distribution**: Changed from pie chart to horizontal bar chart for better visibility
- **URL Length Distribution**: Implemented box plot for clearer pattern visualization
- **Chart Layout Optimization**: Added proper margins and improved overall chart visibility
- **Caching Mechanism**: Added background chart generation and caching for faster load times

### Main Dashboard Charts
- **URL Threat Classification**
  - Type: Horizontal Bar Chart (Updated)
  - Shows distribution across benign/phishing/malware/defacement
  - Enhanced visibility with optimized layout
  
- **URL Length Analysis**
  - Type: Box Plot (New)
  - Shows length distribution patterns by URL type
  - Improved statistical visualization
  
- **Top Malicious Domains**
  - Type: Horizontal Bar Chart
  - Displays top 10 domains by threat count
  - Interactive tooltips and filtering

- **Geographic Distribution**
  - Type: Interactive Choropleth Map
  - Global threat distribution visualization
  - Country-wise threat analysis

## � Project Structure

```
Cybersecurity-Threat-Intelligence-Analyzer/
│
├── src/                              # Source code
│   ├── main.py                       # Automated pipeline orchestrator
│   ├── preprocess.py                 # Data preprocessing & feature extraction
│   ├── ingest.py                     # MongoDB bulk insertion
│   ├── mapreduce_queries.py          # Aggregation queries
│   ├── visualize.py                  # Chart generation (static)
│   ├── ml_predict.py                 # Machine learning model training
│   ├── anomaly_detect.py             # Statistical anomaly detection
│   ├── dashboard.py                  # Interactive web dashboard (Flask)
│   ├── mongodb_viewer.py             # MongoDB data viewer (Flask)
│   └── realtime.py                   # Change stream monitoring
│
├── data/                             # Processed data (auto-generated)
│   └── processed_urls.json           # Preprocessed URL features
│
├── report/                           # Output visualizations
│   └── images/                       # Generated charts
│       ├── top_types.png
│       ├── top_malicious_domains.png
│       ├── malicious_tld_pie.png
│       ├── threat_scores.png
│       └── country_map.html
│
├── malicious_phish.csv               # Raw dataset (download from Kaggle)
├── threat_detector.joblib            # Trained ML model (auto-generated)
├── optimized_threat_detector.joblib  # Optimized model (optional)
├── requirements.txt                  # Python dependencies
└── README.md                         # This file

## 🚀 Performance

### Recent Optimizations
- **Chart Caching**: Implemented background chart generation and caching
- **Reduced Data Processing**: Optimized data loading on page load
- **MongoDB Query Optimization**: Improved query performance with proper indexing
- **Dashboard Response Time**: Enhanced chart rendering and layout updates

### Benchmarks
| Operation | Time (650K URLs) | Memory Usage |
|-----------|-----------------|--------------|
| Preprocessing | ~4-6 minutes | 2-3 GB |
| MongoDB Ingestion | ~2-3 minutes | 1 GB |
| Aggregations | ~20-30 seconds | 500 MB |
| ML Training | ~3-5 minutes | 2 GB |
| Dashboard Load | <1 second | 100 MB |

### Optimization Tips
- **Increase Batch Size**: For faster ingestion (more memory required)
- **MongoDB Indexing**: Ensure indexes are created
- **Parallel Processing**: Utilize all CPU cores
- **Sample Size**: Reduce ML training sample for faster training
- **SSD Storage**: Use SSD for MongoDB data directory

## � Usage

### Option 1: Automated Pipeline (Recommended)
Run the entire pipeline with one command:
```bash
python src/main.py
```

This will automatically:
- Preprocess the raw data
- Ingest into MongoDB
- Run aggregations
- Generate visualizations
- Train ML model
- Detect anomalies
- Start web dashboards

Access the dashboards:
- Main Dashboard: http://localhost:5001
- MongoDB Viewer: http://localhost:5002

### Option 2: Step-by-Step Execution

1. **Preprocess Data**
```bash
python src/preprocess.py
```
- Reads malicious_phish.csv
- Extracts URL features
- Outputs to data/processed_urls.json

2. **Ingest into MongoDB**
```bash
python src/ingest.py
```
- Bulk inserts processed data
- Creates indexes on key fields
- Target collection: cyber_intel.urls

3. **Run Aggregations**
```bash
python src/mapreduce_queries.py
```
- Generates key analytics collections
- Performs threat analysis
- Creates statistical summaries

4. **Generate Visualizations**
```bash
python src/visualize.py
```
- Creates all charts and maps
- Stores in report/images/
- Updates cached data

5. **Train ML Model**
```bash
python src/ml_predict.py
```
- Trains BERT (Bidirectional Encoder Representations from Transformers) model
- Fine-tunes bert-base-uncased for URL classification
- Generates confusion matrix
- Saves optimized model

6. **Start Dashboards**
```bash
python src/dashboard.py  # Main Dashboard
python src/mongodb_viewer.py  # MongoDB Viewer
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
```bash
git checkout -b feature/your-feature-name
```
3. **Commit changes**
```bash
git commit -m "Add: your feature description"
```
4. **Push to branch**
```bash
git push origin feature/your-feature-name
```
5. **Open a Pull Request**

### Code Style
- Follow PEP 8 guidelines
- Add docstrings to functions
- Include comments for complex logic
- Test before submitting

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Connection Error**
```
Error: pymongo.errors.ServerSelectionTimeoutError
```
Solution:
```bash
# Check if MongoDB is running
mongosh mongodb://localhost:27017/

# Start MongoDB
# Windows:
net start MongoDB

# Linux/Mac:
sudo systemctl start mongod
```

2. **Low Memory During Training**
```
Error: MemoryError
```
Solution:
- Reduce sample_size in ml_predict.py
- Close other applications
- Use smaller batch sizes

3. **Slow Dashboard Performance**
Solution:
- Ensure caching is enabled
- Verify MongoDB indexes
- Check system resources
- Use optimized model version

### Debug Mode
Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Getting Help
- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Email: Contact the maintainer

## � License

This project is licensed under the MIT License - see the LICENSE file for details.

## � Acknowledgments

- **Dataset**: Kaggle community for the malicious URLs dataset
- **Libraries**:
  - MongoDB for scalable data storage
  - PyTorch and Hugging Face Transformers for BERT model implementation
  - scikit-learn for machine learning capabilities
  - Flask for web framework
  - Plotly for interactive visualizations
  - Pandas for data manipulation

## � Statistics

- Lines of Code: ~2,000+
- Languages: Python 100%
- Collections Generated: 7
- Visualizations: 6+
- ML Features: 12
- Supported Threat Types: 4

## � Future Enhancements

- [ ] REST API for external integrations
- [ ] Real-time threat feed integration
- [ ] Deep learning models (LSTM, CNN)
- [ ] URL screenshot capture
- [ ] WHOIS lookup integration
- [ ] Email alert system
- [ ] Docker containerization
- [ ] CI/CD pipeline
- [ ] User authentication
- [ ] Export reports to PDF
- [ ] Scheduled threat scanning
- [ ] Integration with VirusTotal API

## 📞 Contact

Project Maintainer: Joel R Tharakan
Repository: GitHub - Cybersecurity-Threat-Intelligence-Analyzer

⭐ If you find this project useful, please consider giving it a star!