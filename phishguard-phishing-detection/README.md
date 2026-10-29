# PhishGuard — Capstone Website

**Project title:** Real-Time Phishing Email Detection and Secure Email Authentication Using Machine Learning, Digital Signatures, and Cryptographic Hashing

PhishGuard is a locally runnable full-stack capstone demonstration. It includes an email scanner, an ML text classifier, URL/rule indicators, SHA-256 fingerprints, RSA digital signature tools, manually supplied SPF/DKIM/DMARC results, a final deliver/quarantine/reject policy, a dashboard, SQLite audit history, and CSV export.

## Quick start

### Windows
1. Install Python 3.10 or newer.
2. Extract the project folder.
3. Double-click `run_windows.bat` (or run it from PowerShell).
4. Wait for dependencies to install and the server to start.
5. Open **http://127.0.0.1:8000** in your browser.

### macOS / Linux
1. Install Python 3.10 or newer.
2. Open a terminal in the extracted project folder.
3. Run `./run_mac_linux.sh`.
4. Open **http://127.0.0.1:8000** in your browser.

To start manually after installing dependencies:
```bash
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

API documentation is available at **http://127.0.0.1:8000/docs**.

## Features implemented

1. **Email input and preprocessing:** sender, recipient, subject, body, URL extraction and normalization.
2. **Machine-learning detection:** a demo TF-IDF + Logistic Regression classifier trained at startup on a small, illustrative in-code sample set; additional heuristic signals inspect urgency, credential requests, and URL patterns.
3. **Cryptographic integrity:** SHA-256 content digest and RSA-2048 / RSA-PSS signatures using a locally generated demo key pair.
4. **Authentication signals:** SPF, DKIM and DMARC pass/fail/unknown values can be supplied from a mail gateway or set manually for the demo.
5. **Decision policy:** combined risk score maps to DELIVER, QUARANTINE or REJECT; a failed signature or a supplied failed mail-authentication result raises the handling severity.
6. **Dashboard:** scan totals, flagged totals, delivery counts, flag rate, decision distribution and recent activity.
7. **Audit trail:** persistent SQLite scan history, search/filter, record detail view, CSV export and clear-history action.
8. **Demo scenarios:** load a phishing sample and a legitimate sample from the scanner page.

## Important scope and security notes

- This is a capstone prototype, **not a production mail gateway**. It does not automatically fetch a real mailbox through IMAP/POP3, intercept SMTP traffic, or block delivery in Gmail/Outlook.
- SPF/DKIM/DMARC are **manual/demo inputs** in this build; the app does not perform DNS lookups or validate live DKIM headers.
- The classifier is trained on a small illustrative sample embedded in `backend/main.py`, not on a benchmark dataset. Its confidence/risk scores are for demonstration and must not be represented as production-grade model accuracy.
- The generated RSA key pair is a local demonstration key with no protected private-key storage. Do not use it to authenticate real emails.
- Email signatures are checked against the exact canonical message string produced by the app. Any changed sender, recipient, subject, URLs or body should make the signature fail.
- For a real deployment, add a vetted dataset, train/evaluate on held-out data, add rate limiting and authentication, secure key storage, trusted key distribution, real DNS/mail-server integrations, attachment sandboxing, privacy controls and a reviewable threat policy.

## Architecture

Browser UI (HTML/CSS/JS) → FastAPI REST API → preprocessing and ML/rule scoring + SHA-256/RSA verification → decision policy → SQLite audit log → dashboard and CSV report.

## Key endpoints

- `GET /api/health` — engine status
- `POST /api/analyze` — analyse an email and store the result
- `GET /api/stats` — dashboard metrics
- `GET /api/logs` — recent scan records
- `POST /api/sign` — sign an exact message with the local demo key
- `POST /api/verify` — verify a signature
- `GET /api/public-key` — retrieve the demo public key
- `GET /api/export.csv` — download audit history
- `DELETE /api/logs` — clear saved scan history
