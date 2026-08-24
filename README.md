# ThreatLens 🔍
### Real-Time AI/ML-Based Phishing Detection and Prevention System
**SIH 2026 — Problem Statement #100**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-threatlens--shield.netlify.app-teal?style=flat-square)](https://threatlens-shield.netlify.app)
[![Backend API](https://img.shields.io/badge/API-sih--l2l2.onrender.com-purple?style=flat-square)](https://sih-l2l2.onrender.com/api/health)
[![Tests](https://img.shields.io/badge/Tests-135%20passed-green?style=flat-square)](#testing)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

---

## 🎯 Problem

Phishing is the #1 cyber threat vector. Traditional solutions tell users **"This site is dangerous"** — but never explain *why*. Users either blindly trust the warning or ignore it because they don't understand it.

Most existing tools:
- Use blacklist-based detection (misses new domains)
- Provide no explanation for the verdict
- Cannot detect brand impersonation in real-time
- Require cloud lookups that add latency

---

## 💡 Solution — ThreatLens

ThreatLens is an **explainable AI phishing detection system** that:

1. **Analyzes** every URL using 34 lexical/structural features
2. **Scores** it 0–100 using a trained Random Forest classifier
3. **Explains** *why* it's risky in plain language
4. **Prevents** the user from proceeding on high-risk sites
5. **Works** both as a web scanner and a Chrome extension

> Traditional tools say: *"Dangerous website."*  
> ThreatLens says: *"Dangerous — because the hostname contains a brand keyword in an unofficial domain, no HTTPS is active, and the URL contains multiple credential-related keywords."*

---

## 🏗️ Architecture

```
User Input (URL)
       │
       ▼
┌─────────────────┐
│  Frontend       │  threatlens-shield.netlify.app
│  index.html     │  Plain HTML/CSS/JS — no framework
└────────┬────────┘
         │  POST /api/scan
         ▼
┌─────────────────┐
│  Flask Backend  │  sih-l2l2.onrender.com
│  app.py         │  Gunicorn + CORS
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Feature Engine  │  backend/ml/feature_extractor.py
│ 34 URL features │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ RandomForest    │  backend/model/phishing_model.joblib
│ Classifier      │  200 trees, class_weight=balanced
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Risk Engine     │  backend/ml/explain.py
│ + Explainability│  Score 0-100, Verdict, Reasons
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ JSON Response   │  risk_score, verdict, reasons,
│                 │  confidence, features, explanations
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Chrome Extension│  extension/ — Manifest V3
│ Prevention      │  In-page overlay for HIGH RISK / DANGEROUS
└─────────────────┘
```

---

## ✅ Key Features (Implemented)

| Feature | Status |
|---|---|
| 34-feature URL analysis | ✅ Implemented |
| Random Forest ML classifier | ✅ Implemented |
| 0–100 risk scoring | ✅ Implemented |
| 4 risk levels (SAFE / SUSPICIOUS / HIGH RISK / DANGEROUS) | ✅ Implemented |
| Plain-language explanations | ✅ Implemented |
| Brand impersonation detection | ✅ Implemented |
| HTTPS / IP hostname detection | ✅ Implemented |
| Punycode / homograph detection | ✅ Implemented |
| Chrome Extension (Manifest V3) | ✅ Implemented |
| In-browser prevention overlay | ✅ Implemented |
| Flask REST API | ✅ Implemented |
| Live Netlify frontend | ✅ Deployed |
| Render backend deployment | ✅ Deployed |
| 135 automated tests | ✅ All passing |

---

## 🗺️ Roadmap (Not Yet Implemented)

| Feature | Phase |
|---|---|
| QR code inspection | Roadmap |
| Download file protection | Roadmap |
| Gmail / Outlook link scanning | Roadmap |
| Domain age (WHOIS) features | Roadmap |
| Live threat intelligence feeds | Roadmap |
| SHAP explainability | Roadmap |
| User feedback loop / retraining | Roadmap |

---

## 🧠 ML Approach

### Algorithm
**Random Forest Classifier**
- 200 decision trees
- `class_weight="balanced"` — handles class imbalance
- `random_state=42` — fully reproducible
- `max_features="sqrt"` — prevents overfitting

### Dataset
- **Source:** Faizan Ahmad's phishing URL dataset (~420,000 URLs)
- **Training sample:** 60,000 URLs (30,000 legitimate + 30,000 phishing), stratified
- **Split:** 80% train / 20% test, stratified

### Model Evaluation (Real, from held-out test set)

| Metric | Score |
|---|---|
| Accuracy | **89.03%** |
| Precision | **89.06%** |
| Recall | **89.00%** |
| F1-Score | **89.03%** |
| Test set size | 12,000 URLs |

### Top Feature Importances (Real values from trained model)

| Rank | Feature | Importance |
|---|---|---|
| 1 | `url_entropy` | 0.1284 |
| 2 | `path_length` | 0.1193 |
| 3 | `hostname_entropy` | 0.1058 |
| 4 | `num_digits` | 0.0986 |
| 5 | `url_length` | 0.0924 |
| 6 | `url_depth` | 0.0776 |
| 7 | `hostname_length` | 0.0756 |
| 8 | `num_hyphens` | 0.0693 |
| 9 | `num_dots` | 0.0570 |
| 10 | `suspicious_keyword_count` | 0.0322 |

---

## 🔬 Feature Extraction (34 features)

All features are extracted **locally from the URL string** — no external API calls.

```
URL Structure:       url_length, hostname_length, path_length, url_depth, 
                     num_dots, num_hyphens, num_digits, num_special_chars,
                     num_query_params, url_parameter_count

Hostname Analysis:   num_subdomains, hostname_token_count, hostname_entropy,
                     abnormal_hostname_length, ip_hostname, punycode_detected

Scheme & Security:   https_enabled, http_enabled

Obfuscation:         has_at_symbol, has_double_slash_in_path,
                     encoded_char_count, percent_encoded_count, url_entropy

Suspicious Keywords: suspicious_keyword_count, login_keyword_count,
                     verify_keyword_count, account_keyword_count,
                     secure_keyword_count, password_keyword_count,
                     update_keyword_count, payment_keyword_count

Brand Signals:       brand_impersonation_indicator, brand_keyword_count

TLD Analysis:        suspicious_tld
```

---

## ⚡ Risk Scoring

| Score | Verdict | Behavior |
|---|---|---|
| 0–29 | 🟢 SAFE | Allow normally |
| 30–59 | 🟡 SUSPICIOUS | Allow, show in popup |
| 60–79 | 🟠 HIGH RISK | Extension overlay — warn + allow |
| 80–100 | 🔴 DANGEROUS | Extension overlay — warn + Go Back |

---

## 🌐 API Endpoints

**Base URL:** `https://sih-l2l2.onrender.com`

### `GET /api/health`
```json
{ "status": "ok", "service": "ThreatLens API" }
```

### `POST /api/scan`
**Request:**
```json
{ "url": "http://paypal-secure-login.example.com" }
```

**Response:**
```json
{
  "success": true,
  "url": "http://paypal-secure-login.example.com",
  "risk_score": 91,
  "verdict": "DANGEROUS",
  "confidence": 0.905,
  "reasons": [
    "HTTPS is not enabled (insecure connection).",
    "The hostname is abnormally long, often used to hide the real domain.",
    "The URL contains multiple credential-related keywords.",
    "Potential brand impersonation pattern detected."
  ],
  "features": { "url_length": 38.0, "num_hyphens": 2.0, "...": "..." },
  "explanations": [
    { "feature": "url_entropy", "value": 4.21, "importance": 0.1284 },
    { "feature": "hostname_entropy", "value": 3.91, "importance": 0.1058 }
  ]
}
```

---

## 🧩 Technology Stack

| Layer | Technology |
|---|---|
| Frontend | Vanilla HTML5 / CSS3 / JavaScript |
| Backend | Python 3.13 + Flask 3.0 + Gunicorn |
| ML | scikit-learn 1.6 (RandomForestClassifier) |
| Data | pandas, numpy, joblib |
| Testing | pytest (135 tests) |
| Extension | Chrome Extension Manifest V3 |
| Frontend Hosting | Netlify |
| Backend Hosting | Render (free tier) |
| CORS | flask-cors with environment-variable origin control |

---

## 🚀 Local Setup

### Prerequisites
- Python 3.10+
- Git

### 1. Clone
```bash
git clone https://github.com/Shivansh1146/SIH.git
cd SIH/phishing_3
```

### 2. Backend Setup
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Train the Model
```bash
cd backend
python ml/train_model.py
# Downloads dataset, trains RandomForest, saves model to backend/model/
```

### 4. Start the API
```bash
cd backend
python app.py
# → http://127.0.0.1:5000
```

### 5. Open the Frontend
Simply open `index.html` in your browser (or serve with Live Server).

### 6. Test the API
```bash
# Health
curl http://127.0.0.1:5000/api/health

# Scan
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.example.com"}'
```

### 7. Run Tests
```bash
cd backend
pytest tests/ -v
# → 135 passed
```

---

## 🔌 Chrome Extension Installation

1. Open Chrome → `chrome://extensions`
2. Toggle **Developer mode** ON (top-right)
3. Click **Load unpacked**
4. Select the `extension/` folder from this repo
5. Ensure the Flask backend is running locally
6. Browse any website — ThreatLens will automatically scan it

> **Note:** The extension currently points to `http://127.0.0.1:5000` (local). For production use, update `API_URL` in `extension/background.js` to `https://sih-l2l2.onrender.com/api/scan`.

---

## ☁️ Deployment

### Frontend — Netlify
- **URL:** https://threatlens-shield.netlify.app
- Auto-deploys from the `main` branch on push
- Config: `netlify.toml`

### Backend — Render
- **URL:** https://sih-l2l2.onrender.com
- Deployed from the `backend/` root directory
- Config: `render.yaml`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
- Env vars: `FRONTEND_ORIGIN=https://threatlens-shield.netlify.app`

> ⚠️ **Render Free Tier:** The service spins down after inactivity. The first request after idle may take 50–60 seconds to respond. Subsequent requests are fast.

> ⚠️ **Model file:** The trained `.joblib` model is excluded from Git (large file). For Render deployment, the model must be retrained or hosted separately.

---

## 🎬 Demo Flow

| Step | Action | Expected Result |
|---|---|---|
| 1 | Open https://threatlens-shield.netlify.app | Frontend loads with scanner |
| 2 | Scan `https://github.com` | Low risk score, SAFE or SUSPICIOUS verdict |
| 3 | Scan `http://paypal-secure-login.example.com` | Score 85+, DANGEROUS verdict |
| 4 | Read reasons | "No HTTPS", "Brand impersonation", "Credential keywords" |
| 5 | Read explainability | Feature importances: url_entropy, path_length |
| 6 | Load extension → browse to GitHub | Popup shows low risk, badge shows ✓ |
| 7 | Navigate to a suspicious URL | Full-page overlay: ⚠ THREATLENS WARNING |

---

## ⚠️ Known Limitations

1. **Render cold start:** Free tier spins down after 15 min of inactivity — first scan is slow
2. **Short domain bias:** The training dataset causes the model to give higher risk scores to very short URLs (e.g., `github.com`). This is a known dataset artifact, not a code bug
3. **Lexical only:** All 34 features are extracted from the URL string. No DOM analysis, no WHOIS, no live threat intelligence
4. **Extension requires local backend:** The extension currently needs the Flask server running locally
5. **Model not in Git:** The `.joblib` model file is excluded from version control — must be trained locally

---

## 📁 Project Structure

```
phishing_3/
├── index.html                    # Frontend (single-page)
├── netlify.toml                  # Netlify config
├── render.yaml                   # Render deployment config
├── README.md
├── extension/                    # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js             # Service worker + API calls
│   ├── content.js                # DOM analysis + prevention overlay
│   ├── popup.html / popup.js     # Extension popup UI
│   └── styles.css
└── backend/
    ├── app.py                    # Flask application factory
    ├── requirements.txt
    ├── Procfile                  # Gunicorn start command
    ├── .env.example              # Environment variable template
    ├── ml/
    │   ├── feature_extractor.py  # 34-feature URL analysis engine
    │   ├── train_model.py        # Training pipeline
    │   └── explain.py            # Risk engine + explainability
    ├── model/
    │   ├── phishing_model.joblib # Trained model (git-ignored)
    │   └── feature_metadata.json # Training provenance + metrics
    └── tests/
        ├── test_api.py           # 22 API endpoint tests
        ├── test_features.py      # 92 feature extractor tests
        └── test_model.py         # 21 model integrity tests
```

---

## 👥 Team

**SIH 2026 — PS #100**  
Real-Time AI/ML-Based Phishing Detection and Prevention System

---

*ThreatLens — See through phishing before it sees you.*
