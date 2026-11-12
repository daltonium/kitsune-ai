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