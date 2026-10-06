# Intelligent Phishing Detection and Prevention System

An Applied Cryptography and Network Security (CNS) Design Challenge project that utilizes Machine Learning lexical feature analysis to inspect URLs and detect phishing threats before users interact with them.

---

## Overview

Phishing remains one of the primary entry points for credential harvesting, identity theft, and corporate security breaches. Traditional defense mechanisms rely heavily on static blacklists and rule-based signatures, which fail against zero-day phishing domains and dynamically generated obfuscated URLs.

This project implements a web-based **Intelligent Phishing Detection System** using a **Random Forest Classifier** trained on the benchmark **PhiUSIIL Phishing URL Dataset**. The system extracts 17 key lexical security attributes from any target URL in real time, computes a probabilistic risk score, and presents an interpretable security verdict with detailed feature explanations through a modern cybersecurity dashboard.

---

## Problem Statement

- Phishing attacks deceive users into submitting sensitive credentials or downloading malicious payloads.
- Adversaries continually modify domain names, utilize URL obfuscation techniques, subdomains, and legitimate top-level domains to evade static blocklists.
- Static blacklists have significant detection latency (often hours to days), leaving users vulnerable during that critical window.

---

## Proposed Solution

A machine learning-based proactive URL analyzer that:
1. Validates and normalizes user-submitted URLs.
2. Extracts 17 distinct lexical and syntactic characteristics (length, subdomain count, obfuscation, digit/letter ratios, protocol security).
3. Evaluates feature vectors using an ensemble Random Forest model.
4. Outputs an actionable classification (**Legitimate** vs. **Potential Phishing**) along with a **Risk Score (0–100%)** and granular security breakdown.

---

## Features

- **Real-Time URL Scanning**: Instantly inspects any web address for phishing patterns.
- **17 Lexical Feature Extractor**: Analyzes syntactic structure, obfuscation symbols, special characters, and domain depth.
- **Probabilistic Risk Scoring**: Calculates transparent risk probabilities derived directly from ensemble decision trees.
- **Interpretability & Feature Inspection**: Highlights flagged indicators (e.g., missing HTTPS, excessive subdomains, URL obfuscation).
- **Dynamic Model Performance Dashboard**: Displays actual empirical evaluation metrics (Accuracy, Precision, Recall, F1 Score, Confusion Matrix) saved from model training.
- **Quick-Test Demo Profiles**: Built-in sample URLs for demonstration and viva presentation.
- **Resilient Dual-Engine Backend**: Seamlessly runs with native `scikit-learn` or standard-library pure-Python execution without operating system dependency blocks.

---

## System Architecture

```text
User enters Target URL
        │
        ▼
[ URL Validation & Normalization ]
        │
        ▼
[ Lexical Feature Extraction (17 Features) ]
  • Length metrics (URL, Domain)
  • Structural (Subdomains, IP usage, HTTPS)
  • Obfuscation (@, %, //, ratios)
  • Character distributions (digits, letters, symbols)
        │
        ▼
[ Random Forest Classifier ]
  • Ensemble voting across decision trees
        │
        ▼
[ Probabilistic Risk Score (0-100%) ]
        │
        ▼
[ Actionable Result & UI Presentation ]
  • Legitimate (Low Risk) vs Potential Phishing (High Risk)
  • Feature explanation breakdown
```

---

## Technology Stack

- **Backend**: Python 3.12, Flask, Joblib / Pickle
- **Machine Learning**: Random Forest Classifier, Scikit-learn
- **Feature Extraction**: Python standard library (`urllib.parse`, `re`, `ipaddress`)
- **Frontend**: Vanilla HTML5, Modern CSS3 (Cybersecurity Dark UI, responsive layout), Vanilla JavaScript (`fetch` API)
- **Dataset**: PhiUSIIL Phishing URL Dataset (UCI Machine Learning Repository)

---

## Dataset

- **Dataset**: **PhiUSIIL Phishing URL Dataset** (235,795 rows × 56 columns)
- **Source**: UCI Machine Learning Repository / Elsevier Computers & Security (2024)
- **Label Semantics**:
  - `1`: **Legitimate URL** (134,850 samples / 57.19%)
  - `0`: **Phishing URL** (100,945 samples / 42.81%)
- **Data Quality**: Verified 0 missing values, 0 duplicate records.

---

## Machine Learning Model

- **Model Type**: Random Forest Classifier
- **Ensemble Configuration**:
  - `n_estimators`: 100
  - `random_state`: 42
  - `n_jobs`: -1
- **Train/Test Split**: 80% Training, 20% Testing (Stratified by class distribution)

---

## Feature Extraction

The system extracts the following **17 lexical features** from a target URL in exact alignment with the training feature schema:

| # | Feature Name | Description |
|---|---|---|
| 1 | `URLLength` | Total character length of URL |
| 2 | `DomainLength` | Character length of the host domain |
| 3 | `IsDomainIP` | Binary flag if host is a raw IPv4/IPv6 address |
| 4 | `NoOfSubDomain` | Number of subdomains beyond base domain |
| 5 | `HasObfuscation` | Presence of obfuscation characters (`@`, `%`, `//`) |
| 6 | `NoOfObfuscatedChar` | Total count of obfuscated symbols |
| 7 | `ObfuscationRatio` | Ratio of obfuscation symbols to URL length |
| 8 | `NoOfLettersInURL` | Count of alphabetic characters |
| 9 | `LetterRatioInURL` | Ratio of letters to total URL length |
| 10 | `NoOfDegitsInURL` | Count of numeric digits |
| 11 | `DegitRatioInURL` | Ratio of numeric digits to URL length |
| 12 | `NoOfEqualsInURL` | Count of `=` query delimiters |
| 13 | `NoOfQMarkInURL` | Count of `?` query parameter markers |
| 14 | `NoOfAmpersandInURL`| Count of `&` query argument markers |
| 15 | `NoOfOtherSpecialCharsInURL` | Special characters excluding `=`, `?`, `&` |
| 16 | `SpacialCharRatioInURL` | Ratio of special characters to URL length |
| 17 | `IsHTTPS` | Binary flag indicating secure HTTPS protocol |

---

## Evaluation Metrics

Empirical evaluation on stratified test partition:

- **Accuracy**: ~99.3%
- **Precision**: ~99.0%
- **Recall**: ~99.8%
- **F1 Score**: ~99.4%
- **Confusion Matrix**: Saved in `backend/model_metrics.json` and rendered dynamically on the dashboard.

---

## Project Structure

```text
intelligent-phishing-detection/
│
├── backend/
│   ├── app.py                  # Flask server & REST API (/predict, /api/metrics, /health)
│   ├── check_dataset.py        # Dataset structure & statistics inspection
│   ├── check_labels.py         # Label verification script
│   ├── feature_extraction.py   # 17-feature lexical URL parser
│   ├── rf_engine.py            # Random Forest engine
│   ├── train_model.py          # Model training, evaluation & artifact exporter
│   ├── model.pkl               # Serialized trained model
│   └── model_metrics.json      # Saved evaluation metrics
│
├── data/
│   └── phishing_dataset.csv    # Benchmark PhiUSIIL dataset
│
├── frontend/
│   ├── index.html              # Modern single-page cybersecurity dashboard
│   ├── style.css               # Cybersecurity dark theme
│   └── script.js               # Frontend fetch controller & UI renderer
│
├── screenshots/                # Demonstration and presentation visuals
├── .gitignore                  # Git ignore rules
├── README.md                   # Comprehensive project documentation
└── requirements.txt            # Python dependencies
```

---

## Installation & Setup

### Prerequisites
- Python 3.12 (Recommended)
- PowerShell (Windows) or Bash (macOS/Linux)

### 1. Clone or Open the Repository
```powershell
cd c:\Users\diyas\OneDrive\Desktop\intelligent-phishing-detection
```

### 2. Activate Virtual Environment
Using the configured Python 3.12 environment:
```powershell
.\venv312\Scripts\Activate.ps1
```

*(Or create a new environment with `py -3.12 -m venv venv` and install `pip install -r requirements.txt`)*

---

## Running the Project

### One-Command Quick Launch (Recommended)
You can run both the backend API and frontend dashboard together with a single command:

```powershell
python run.py
```
*(Or simply double-click **`start.bat`** in Windows File Explorer)*

This automatically:
1. Detects and uses the configured Python environment.
2. Checks that `model.pkl` is loaded (or trains it if missing).
3. Serves the Flask backend API and modern frontend dashboard.
4. Automatically opens **http://127.0.0.1:5000** in your default web browser!

---

### Manual Launch (Alternative)
```powershell
.\venv312\Scripts\Activate.ps1
cd backend
python app.py
```
Then visit **http://127.0.0.1:5000** in your browser.

---

## Demonstration Workflow (For Viva / Presentation)

1. **Verify Backend Status**: Look at the top right navbar badge (`ML Engine Active`).
2. **Review Metrics**: Scroll down to the **Model Performance Metrics** section to display empirical Accuracy, Precision, Recall, and Confusion Matrix.
3. **Scan Legitimate URL**:
   - Click the **"Academic Site"** quick button (`https://www.uni-mainz.de`).
   - Click **CHECK URL**.
   - Notice the green verdict banner: **URL LOOKS LEGITIMATE** with low risk score and safe feature attributes.
4. **Scan Phishing URL**:
   - Click the **"Phishing Sample"** quick button (`http://secure-login.paypal.account-verify.com/login?id=999&auth=fail`).
   - Click **CHECK URL**.
   - Notice the red alert: **POTENTIAL PHISHING DETECTED** with high risk score, missing HTTPS, excessive subdomains, and obfuscated characteristics.

---

## Future Scope

- **Browser Extension Integration**: Real-time passive background URL scanning before tab navigation.
- **Live Threat Intelligence Feeds**: Integration with VirusTotal and Google Safe Browsing APIs.
- **Webpage Content & DOM Analysis**: Inspecting HTML forms, hidden password fields, and external resource redirection.
- **Domain Age & SSL Certificate Validation**: Querying WHOIS records for recently registered domains.

---

## Academic Notice
This system is an academic demonstration for the Applied Cryptography and Network Security course. Machine learning predictions are probabilistic indicators and should be combined with multi-layered defense-in-depth security strategies.