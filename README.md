# KITSUNE AI 🦊 — Outsmart Every Threat

AI/ML-based cybersecurity detection platform: six detection modules (phishing URL,
network intrusion, phishing email, malware risk, suspicious login, ransomware behavior),
a Django + DRF backend, a React Native Web (Expo) frontend, and a paid REST API for companies.

## Stack
Python 3.10, Django 5.2, DRF, scikit-learn, XGBoost, PostgreSQL (Supabase), Expo / React Native Web.

## Setup (Windows)
    py -3.10 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements-dev.txt
    copy .env.example .env   # then fill in values

## Status
Phase 0 (Initial Setup) complete. See plan.txt for the roadmap.

> Predictions are risk estimates, not proof of malicious activity.

## Phishing URL module — experimental

The current model uses hostname-derived lexical features.
It does not visit URLs or inspect webpage content.

The mixed-source stratified evaluation achieved:
- ROC-AUC: 0.797
- Phishing recall: 58.5%
- False-positive rate on legitimate URLs: approximately 12.6%

Cross-source evaluation was substantially weaker:
- Train on malicious_phish, test on PhiUSIIL:
  ROC-AUC 0.610; false-positive rate 36.4%.
- Train on PhiUSIIL, test on malicious_phish:
  ROC-AUC 0.558; false-positive rate 26.3%.

This module is an experimental research/demo component.
It is not validated for production protection or automatic blocking.
Its scores are uncalibrated model outputs, not verified threat probabilities.

Rule-based explanation signals are separate from model attributions.

## Network intrusion module — CIC-IDS2017

Binary benign/attack classifier (XGBoost) on CICFlowMeter flow features, with the destination port excluded.

| Evaluation | Attack recall | Benign flagged | ROC-AUC |
|---|---|---|---|
| Random 80/20 split | 99.96% | 0.10% | 0.99998 |
| Hold out Wednesday (DoS family) | 22.4% | 0.06% | 0.988 |
| Hold out PortScan | 0.4% | 0.56% | 0.860 |
| Hold out web attacks | 84.9% | 0.06% | 0.994 |

The model detects attack families seen during training very well, but largely misses families it has not seen.
CIC-IDS2017 is a lab benchmark, not a guarantee of performance on a real network.

## Phishing email module — experimental

TF-IDF + Logistic Regression trained on the Zenodo Phishing-Email-Detection-Dataset (body text only; spam, scam and phishing share one label; emails from 1998–2008).
Random stratified 80/20 split: accuracy 98.5%, precision 98.1%, recall 98.8%, false-positive rate 1.7%, ROC-AUC 0.9985.

Limitations: the model picked up some corpus artifacts (Enron and mailing-list vocabulary count as "legitimate"), and modern legitimate emails containing links (a GitHub notification and a shipping notice in our probes) were wrongly flagged (scores 0.86 and 0.74).
Treat results as weak risk hints, not verdicts.

## Malware risk module — EMBER2024 (Windows PE)

Static analysis of uploaded .exe files (never executed): EMBER2024 features (2,568 numbers per file, pefile based) and a LightGBM classifier, chosen over Random Forest and a linear SVM.
Trained on 8 weeks (2024-09-22 to 2024-11-16) of the Win32 split, validated on 2 weeks, tested once on the last 2 weeks (2024-12-01 to 2024-12-14); duplicates removed by sha256.

| Test metric | Value |
|---|---|
| Accuracy | 97.99% |
| Precision / recall | 98.42% / 97.55% |
| False-positive rate | 1.56% |
| ROC-AUC | 0.9979 |
| Detection at 1% false positives | 96.6% |

Limitations: only the Win32 test-split weeks were used (no official train split, challenge set not evaluated); the data is 50% malware, so at real-world prevalence precision will be much lower; labels are VirusTotal-based; other file types are not supported.

## Suspicious login module — experimental

Isolation Forest trained on causal login-behaviour features from the synthetic
CERT r4.2 dataset. Features use only earlier login events, including unusual
hours, computer familiarity, time since the previous login, and recent login
frequency.

The first 30 logins per user provide history and are not scored.
Inputs are a CSV upload or a JSON list of events containing sufficient history.
Single-event scoring with persistent user profiles is not implemented yet.

### Evaluation

Chronological split:
- Training: 131,156 logins before the first labeled attack.
- Validation: 108,568 logins, including 49 labeled suspicious logins.
- Test: 200,868 logins, including 50 labeled suspicious logins.

Selected model: Isolation Forest with max_samples=4096.

| Test metric | Value |
|---|---|
| ROC-AUC | 0.9693 |
| Average precision | 0.00675 |
| Recall at risk >= 0.995 | 8% |
| Precision at risk >= 0.995 | 0.495% |
| Flags per day at risk >= 0.995 | 3.51 |
| Recall at risk >= 0.98 | 56% |
| Precision at risk >= 0.98 | 0.777% |

### Limitations

- Anomaly scores are training-reference percentiles, not probabilities of compromise.
- Alert precision and recall are weak at the current threshold.
- The dataset is synthetic and contains very few labeled suspicious logins.
- Scenario 2 has no positive Logon labels in this evaluation.
- Failed-login features cannot be derived from CERT logon.csv.
- Incoming requests must include historical logins for each user.
- User/computer references are short hashes, not guaranteed anonymization.
- Do not use predictions to automatically deny access or disable accounts.

## Scan History & Alerts

Authenticated web endpoints:
- GET /api/web/history/ — paginated owned scans.
- GET /api/web/history/<scan_id>/ — owned scan result.
- GET /api/web/alerts/ — paginated owned alerts.
- PATCH /api/web/alerts/<id>/ — update is_read only.
- GET /api/web/dashboard/?days=30 — owned scan statistics.

History supports module, risk_level, source, date_from and date_to filters.
Alerts support severity and is_read filters.
Pagination defaults to 20 results and allows up to 100.

Users cannot access another user's scans or alerts.
Dashboard counts describe model outputs, not confirmed incidents.
A batch upload counts as one scan, not one scan per input row.

## Scan History & Alerts

Authenticated web endpoints:
- GET /api/web/history/ — paginated owned scans.
- GET /api/web/history/<scan_id>/ — one owned scan.
- GET /api/web/alerts/ — paginated owned alerts.
- PATCH /api/web/alerts/<id>/ — update is_read only.
- GET /api/web/dashboard/?days=30 — owned scan statistics.

History filters: module, risk_level, source, date_from, date_to.
Alert filters: severity, is_read.
Pagination defaults to 20 results, maximum 100.

Users cannot access another user's scans or alerts.
Dashboard counts describe model outputs, not confirmed incidents.
A batch upload counts as one scan.