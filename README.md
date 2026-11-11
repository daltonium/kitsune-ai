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