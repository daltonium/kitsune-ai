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

## Paid API Infrastructure

Companies can use the five detection modules through Bearer-authenticated
REST endpoints. API keys are hashed with HMAC-SHA256 and are never stored in
plaintext. The raw key is shown once when created.

### API endpoints

- POST /api/v1/phishing-url/scan/
- POST /api/v1/network-intrusion/scan/
- POST /api/v1/phishing-email/scan/
- POST /api/v1/malware/scan/
- POST /api/v1/suspicious-login/analyze/

Send the key as `Authorization: Bearer <api_key>`.
Successful scans return HTTP 201 and include `X-Quota-Limit` and
`X-Quota-Remaining`.

### Company management

Session-authenticated endpoints under `/api/web/company/`:
- GET plans/ — active plans.
- POST register/ — create a company and start the Free plan.
- GET company/ — company and subscription profile.
- POST subscription/ — change plan; payments are simulated.
- GET keys/ and POST keys/ — list or create API keys.
- POST keys/<id>/revoke/ — revoke a key.
- GET usage/?days=30 — usage, quota and daily request data.

### Limits and errors

- Quota counts successful (2xx) API requests in the billing period.
- Failed requests do not consume quota.
- Monthly plans stop at the quota; pay-as-you-go plans may exceed it only
  when the plan permits it.
- Each key is limited by its plan's requests-per-minute rate.
- Quota and rate-limit failures return HTTP 429 with `Retry-After`.
- Invalid input returns HTTP 400; unavailable models return HTTP 503.
- Users cannot access another company's keys, scans or usage data.

## Backend Security

KITSUNE AI separates web authentication from paid API authentication.

- Web history, alerts, dashboard and company-management endpoints require a
  Django session login.
- Company-management endpoints use Django CSRF protection for state-changing
  requests.
- Paid API endpoints under `/api/v1/` accept only `Authorization: Bearer`
  API keys; browser session cookies are rejected.
- API keys are stored only as HMAC-SHA256 hashes using `API_KEY_PEPPER`.
- The raw API key is shown once when created and is never stored in plaintext.
- Revoked and expired keys are rejected.
- Scan history, alerts, company profiles, API keys and usage reports are
  scoped to the signed-in owner.
- One company cannot access another company's keys, scans or usage data.
- API scans belong to the company owner's user account.

### Input and upload safety

- Invalid URLs, emails, JSON, CSV rows, login events and uploads are rejected
  before a scan is created.
- Uploaded Windows executables are parsed in memory only.
- Uploaded files are never executed, installed, opened as programs, or written
  to disk.
- Phishing URLs are analyzed from their text only; KITSUNE AI does not fetch
  or visit submitted URLs.
- Phishing-email links are counted but never fetched or visited.

### Error handling and headers

- API errors use a consistent JSON structure:
  `{"error": {"code": "...", "message": "..."}}`.
- Detector validation errors return HTTP 400.
- Unavailable models return HTTP 503.
- Quota and rate-limit failures return HTTP 429 with `Retry-After`.
- Responses do not expose raw API keys, key hashes, usernames, company names,
  raw user/computer identifiers, model paths, or stack traces.
- Security headers include `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and `Referrer-Policy: same-origin`.

### Production requirements

- `DJANGO_DEBUG` must be false in production.
- The PostgreSQL connection must require SSL.
- `API_KEY_PEPPER` must be set to a long, unique secret.
- `CORS_ALLOW_ALL_ORIGINS` is for local development only and must not be
  enabled in production.

  ## Frontend Foundation — Phase 13

The frontend lives in `frontend/` within the Django monorepo. It uses Expo,
React Native, React Native Web and TypeScript.

### Stack

Initial scaffold:
- Expo SDK 58
- React 19.3
- React Native 0.88.1
- React Native Web
- TypeScript with strict type checking
- React Navigation 7

Use `frontend/package.json` and `frontend/package-lock.json` as the source
of truth for installed dependency versions.

### Application structure

```text
frontend/
  App.tsx
  index.ts
  app.json
  package.json
  package-lock.json
  tsconfig.json
  .env.example
  assets/
  src/
    api/
      client.ts
    components/
      Button.tsx
      Card.tsx
      Screen.tsx
      Typography.tsx
    constants/
      modules.ts
    navigation/
      AppNavigator.tsx
      types.ts
    screens/
      DashboardScreen.tsx
      ScansScreen.tsx
      ModuleScreen.tsx
      HistoryScreen.tsx
      CompanyScreen.tsx
    theme/
      colors.ts
      ThemeContext.tsx
```

### Theme and navigation

- Uses the KITSUNE AI black, crimson, white and gold brand palette.
- Starts in dark mode and supports switching to light mode.
- Theme selection is held in memory and resets when the app reloads.
- Provides Dashboard, Scans, History and Company tabs.
- Provides a typed module-detail route for the five detection modules.
- History, Company and module-detail screens are placeholders at this stage.
- The module list is local metadata, not a live detector-readiness response.
- The navigation shell does not yet configure web deep links.

### Backend connectivity

The Dashboard calls the public Django health endpoint:

GET /api/health/

The API client:
- Reads the backend address from EXPO_PUBLIC_API_URL.
- Falls back to http://127.0.0.1:8000 for local development.
- Applies an eight-second request timeout.
- Converts HTTP, network and timeout failures into ApiError instances.
- Supports a manual health-check retry.

The Dashboard displays loading, connected and error states. A successful
health response proves connectivity only; it does not verify authentication,
database availability, model readiness or detection accuracy.

No company API key is embedded in the frontend. This phase does not
implement authenticated session requests or CSRF-token handling.

### Local setup

Run from the frontend directory:

```powershell
npm ci
Copy-Item .env.example .env.local
```

Do not overwrite an existing `.env.local` containing local configuration.

Example frontend environment:

```env
EXPO_PUBLIC_API_URL=http://127.0.0.1:8000
```

EXPO_PUBLIC variables are included in client code. Never put Django secrets,
database credentials, API key peppers, session cookies or private API keys
in them.

The default backend address is intended for web development on the same
computer as Django. A physical device needs a separately configured
reachable backend address.

### Run locally

Start Django from the repository root with the Python virtual environment
active:

```powershell
python manage.py runserver
```

Start Expo from `frontend/` in another terminal:

```powershell
npx expo start --web --host localhost
```

Open the web address printed by Expo.

### Verification

Run from `frontend/`:

```powershell
npx tsc --noEmit
npx expo-doctor
npx expo export --platform web
```

Phase 13 verification:
- TypeScript completed without errors.
- Expo Doctor passed 20/20 checks.
- Web export completed successfully.
- The exported JavaScript bundle was approximately 825 KB.
- The browser displayed the connected backend-health state.
- The browser displayed a controlled error state when Django was unavailable.

These are compilation, compatibility, build and manual connectivity checks.
They are not a frontend automated-test suite or native-device validation.

Generated dependencies, Expo state, local environment files and exported
web output are ignored by Git. Commit the npm lockfile.

### Known dependency advisory

The setup-time npm audit reported three moderate findings associated with:

minimatch -> @expo/fingerprint -> expo

npm proposed a forced downgrade to Expo 52. Do not apply that downgrade to
the SDK 58 project. The advisory remains unresolved and must be reviewed
against compatible dependency updates before deployment. A successful build
or Expo Doctor result does not establish that an advisory is harmless.

### Next phases

- Phase 14: authentication, registration and authenticated dashboard data.
- Phase 15: detection forms and result interfaces for all five modules.
- Phase 16: history, company portal, remaining integration and deployment.

The frontend currently uses the template icon and favicon. Custom KITSUNE AI
branding will be integrated separately.