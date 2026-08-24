# ThreatLens

**SIH #100 — Real-Time AI/ML-Based Phishing Detection and Prevention System**

> See through phishing before it sees you.

Live frontend: [threatlens1.netlify.app](https://threatlens1.netlify.app)

---

## Project Status — Phase 1 Complete

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

## Structure

```
phishing_3/
├── index.html          ← Frontend (ThreatLens SPA — demo scanner)
├── .gitignore
├── README.md
└── backend/
    ├── app.py          ← Flask API (Phase 1 scaffold)
    ├── requirements.txt
    ├── README.md       ← Architecture + API reference
    ├── ml/             ← Feature extraction + model + explainability
    ├── model/          ← Trained model artifacts (git-ignored)
    ├── data/           ← Datasets (git-ignored)
    └── tests/          ← Pytest test suite
```

See [`backend/README.md`](backend/README.md) for the full architecture, API reference, and setup instructions.
