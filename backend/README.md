# ThreatLens — Backend

> **SIH #100 — Real-Time AI/ML-Based Phishing Detection and Prevention System**

This directory contains the Python/Flask backend for ThreatLens.

---

## Architecture

```
Browser / Chrome Extension
        │
        │  POST /scan  { "url": "..." }
        ▼
┌─────────────────────────────────────────┐
│           Flask API  (app.py)           │
│  • /ping  — health check                │
│  • /scan  — phishing risk assessment    │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│    Feature Extraction  (ml/)            │
│  Lexical, structural & network signals  │
│  ~30 features extracted per URL         │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│    ML Model  (model/)                   │
│  XGBoost gradient-boosted classifier    │
│  Trained on labeled phishing datasets   │
│  Outputs a 0–100 risk score             │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│    Risk Engine                          │
│  SAFE (<40) / SUSPICIOUS (40–69)        │
│  HIGH RISK (70–89) / DANGEROUS (90+)    │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│    Explainability  (ml/explainer.py)    │
│  SHAP TreeExplainer attribution         │
│  Converts feature weights → plain text  │
└────────────────┬────────────────────────┘
                 │
                 ▼
         JSON response to frontend
```

---

## Directory Structure

```
backend/
├── app.py              ← Flask entrypoint
├── requirements.txt    ← Python dependencies
├── ml/
│   ├── __init__.py
│   ├── feature_extractor.py   [Phase 2]
│   ├── predictor.py           [Phase 3]
│   └── explainer.py           [Phase 5]
├── model/
│   └── model.joblib           [Phase 3 — git-ignored]
├── data/
│   └── (training datasets)    [Phase 3 — git-ignored]
└── tests/
    ├── __init__.py
    ├── test_api.py            [Phase 2]
    ├── test_features.py       [Phase 2]
    └── test_predictor.py      [Phase 3]
```

---

## Build Phase Roadmap

| Phase | Focus                         | Status          |
|-------|-------------------------------|-----------------|
| 1     | Repo audit + scaffold         | ✅ **Complete**  |
| 2     | Feature extraction pipeline   | 🔲 Not started  |
| 3     | Dataset + XGBoost training    | 🔲 Not started  |
| 4     | Live threat intelligence      | 🔲 Not started  |
| 5     | SHAP explainability           | 🔲 Not started  |
| 6     | Frontend ↔ backend wiring     | 🔲 Not started  |
| 7     | Chrome extension (MV3)        | 🔲 Not started  |
| 8     | QR-code scanning module       | 🔲 Not started  |
| 9     | Performance + security audit  | 🔲 Not started  |
| 10    | Production deployment         | 🔲 Not started  |

---

## Setup (Local Development)

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the development server
python app.py
# → http://localhost:5000

# 4. Test the health check
curl http://localhost:5000/ping
# → {"status": "ok", "service": "ThreatLens API", "phase": 1}
```

---

## API Reference

### `GET /ping`

Liveness check. Returns `200 OK` when the server is running.

```json
{ "status": "ok", "service": "ThreatLens API", "phase": 1 }
```

### `POST /scan`

Submit a URL for phishing analysis.

**Request**
```json
{ "url": "https://paypa1-secure-login.com/verify" }
```

**Response (Phase 1 — stub)**
```json
{
  "url":     "https://paypa1-secure-login.com/verify",
  "score":   null,
  "verdict": "STUB",
  "reasons": ["Phase 1 scaffold — ML model not yet trained or loaded."],
  "phase":   1
}
```

Real scores and verdicts are implemented in **Phase 3**.

---

## Phase 1 Audit Notes

### What exists in the frontend (`index.html`)

| Element | Reality |
|---|---|
| Live URL scanner | ✅ Works — **client-side heuristic demo only** |
| Risk score (0–100) | ⚠️ Calculated by simple lexical rules in JavaScript — **not ML** |
| SHAP bar chart | ❌ **Static HTML mock** — no SHAP computation |
| "XGBoost model" claim | ❌ No model exists yet |
| Stats (4200 sites, 96.8% precision) | ❌ **Hardcoded placeholder numbers** |
| Chrome extension | ❌ Extension files do not exist yet |

### What is real in Phase 1

- ✅ Polished, fully functional frontend UI (preserved untouched)
- ✅ Client-side demo scanner (works as a frontend demo)
- ✅ Flask API scaffold (`/ping`, `/scan` stub)
- ✅ Backend directory structure
- ✅ `.gitignore` excluding secrets, model files, large datasets
- ✅ This architecture document

---

> **Do not claim ML, SHAP, or live threat intelligence are implemented until Phase 3, 5, and 4 respectively.**
