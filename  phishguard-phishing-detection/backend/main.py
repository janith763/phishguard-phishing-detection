from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
import hashlib, json, re, sqlite3, io, csv, base64, os

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "phishguard.db"
KEY_DIR = DATA_DIR / "keys"
KEY_DIR.mkdir(exist_ok=True)
PRIVATE_KEY_PATH = KEY_DIR / "demo_private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "demo_public_key.pem"

app = FastAPI(title="PhishGuard Capstone API", version="1.0.0", description="Phishing detection and email integrity demonstration")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")

class EmailInput(BaseModel):
    sender: str = Field(default="", max_length=320)
    recipient: str = Field(default="", max_length=320)
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=100000)
    urls: str = Field(default="", max_length=10000)
    signature: str = Field(default="", max_length=10000)
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"

class SignInput(BaseModel):
    message: str = Field(min_length=1, max_length=100000)

class VerifyInput(BaseModel):
    message: str = Field(min_length=1, max_length=100000)
    signature: str = Field(min_length=1, max_length=10000)

SAMPLES = [
    ("Your account has been suspended. Verify your password immediately at http://secure-account-login.example.com", 1),
    ("Congratulations you won a prize claim now click this link and enter your bank details", 1),
    ("Urgent action required: your mailbox will be deleted unless you sign in now", 1),
    ("Your package is held. Pay a small delivery fee using this link", 1),
    ("Payroll update: open this attachment and enable macros to view your salary", 1),
    ("We detected unusual activity. Confirm your credentials to avoid account closure", 1),
    ("Your invoice is overdue. Download the attached file and enable content", 1),
    ("Reset your password now to prevent permanent account suspension", 1),
    ("Click here to claim your refund and provide your card number", 1),
    ("Security alert: login from unknown device, verify identity immediately", 1),
    ("Please review the meeting agenda before tomorrow's project meeting", 0),
    ("Hi team, the quarterly report is attached for your review", 0),
    ("Your appointment is confirmed for Tuesday at 10 AM", 0),
    ("Thanks for your help. I have updated the project tracker", 0),
    ("Here are the notes from today's discussion and next steps", 0),
    ("The invoice has been paid. Please find the receipt attached", 0),
    ("Can we schedule a call to discuss the new release timeline", 0),
    ("Welcome to the company. Your onboarding schedule is attached", 0),
    ("Please approve the draft when you have a chance", 0),
    ("The weekly team update is available in the shared workspace", 0),
    ("The conference starts at 9 AM. Please arrive fifteen minutes early", 0),
    ("I have shared the requested documents through the company portal", 0),
]
MODEL = None
if SKLEARN_AVAILABLE:
    MODEL = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, sublinear_tf=True)), ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))])
    MODEL.fit([x[0] for x in SAMPLES], [x[1] for x in SAMPLES])


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, sender TEXT, recipient TEXT,
            subject TEXT, verdict TEXT, risk_score INTEGER, ml_score INTEGER, hash_sha256 TEXT,
            signature_status TEXT, auth_status TEXT, reasons TEXT, body_preview TEXT
        )''')
        conn.commit()

def ensure_keys():
    if not CRYPTO_AVAILABLE or (PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists()): return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIVATE_KEY_PATH.write_bytes(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    PUBLIC_KEY_PATH.write_bytes(private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

def canonical_message(sender, recipient, subject, body, urls=""):
    return "\n".join([f"From: {sender.strip()}", f"To: {recipient.strip()}", f"Subject: {subject.strip()}", f"URLs: {urls.strip()}", "", body.strip()])

def get_hash(message):
    return hashlib.sha256(message.encode("utf-8")).hexdigest()

def sign_text(message):
    if not CRYPTO_AVAILABLE: raise HTTPException(503, "Cryptography dependency unavailable. Install requirements.txt")
    ensure_keys()
    private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
    signature = private_key.sign(message.encode("utf-8"), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")

def verify_text(message, signature):
    if not CRYPTO_AVAILABLE: return False, "Cryptography dependency unavailable"
    try:
        ensure_keys()
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        public_key.verify(base64.b64decode(signature, validate=True), message.encode("utf-8"), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True, "Valid signature: content matches the demo public key"
    except (InvalidSignature, ValueError, TypeError):
        return False, "Signature invalid: content or signature was changed"
    except Exception:
        return False, "Signature could not be verified"

def extract_urls(text):
    found = re.findall(r"https?://[^\s<>\]\[)]+|www\.[^\s<>\]\[)]+", text or "", flags=re.I)
    return list(dict.fromkeys([u.rstrip('.,;!') for u in found]))

def url_features(urls):
    suspicious, reasons = 0, []
    for raw in urls:
        u = raw if raw.startswith(("http://", "https://")) else "http://" + raw
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http":
            suspicious += 1; reasons.append("URL uses unencrypted HTTP")
        if re.match(r"\d{1,3}(\.\d{1,3}){3}$", host):
            suspicious += 2; reasons.append("URL uses an IP address instead of a domain")
        if len(host) > 35 or host.count("-") >= 3:
            suspicious += 1; reasons.append("URL has an unusually long or hyphen-heavy domain")
        if any(word in host for word in ["verify", "secure", "login", "account", "update", "password"]):
            suspicious += 1; reasons.append("URL contains a sensitive-account keyword")
        if host.count(".") >= 4:
            suspicious += 1; reasons.append("URL has many subdomains")
    return suspicious, list(dict.fromkeys(reasons))

def analyze_email(payload: EmailInput):
    full = canonical_message(payload.sender, payload.recipient, payload.subject, payload.body, payload.urls)
    all_text = f"{payload.subject}\n{payload.body}\n{payload.urls}"
    urls = list(dict.fromkeys(extract_urls(all_text) + [u.strip() for u in re.split(r"[\s,]+", payload.urls) if u.strip()]))
    reasons = []
    if MODEL:
        ml_score = int(round(float(MODEL.predict_proba([all_text])[0][1]) * 100))
    else:
        ml_score = 25
    lower = all_text.lower()
    rule_points = 0
    patterns = [
        (r"\b(verify|confirm|reset)\b.{0,35}\b(password|credentials|account|identity)\b", 22, "Requests sensitive account verification"),
        (r"\b(urgent|immediately|within 24 hours|suspended|permanently deleted)\b", 14, "Uses urgency or threat language"),
        (r"\b(bank details|credit card|social security|one-time password|\botp\b)\b", 25, "Mentions sensitive financial or authentication information"),
        (r"\b(click here|claim your prize|you have won|enable macros)\b", 18, "Contains a common phishing call to action"),
    ]
    for pattern, points, reason in patterns:
        if re.search(pattern, lower): rule_points += points; reasons.append(reason)
    url_points, url_reasons = url_features(urls)
    rule_points += min(35, url_points * 9)
    reasons.extend(url_reasons)
    if payload.sender and re.search(r"\.(ru|top|xyz|click|zip)$", payload.sender.split("@")[-1].lower()):
        rule_points += 8; reasons.append("Sender domain uses a higher-risk or uncommon top-level domain")
    risk = int(max(0, min(100, round(0.55 * ml_score + 0.45 * min(100, rule_points)))))
    if risk >= 70: verdict = "REJECT"
    elif risk >= 40: verdict = "QUARANTINE"
    else: verdict = "DELIVER"
    sig_status = "Not provided"
    if payload.signature.strip():
        valid, message = verify_text(full, payload.signature.strip())
        sig_status = "Verified" if valid else "Failed"
        if not valid: reasons.append("Digital signature verification failed")
    auth_values = [payload.spf.lower(), payload.dkim.lower(), payload.dmarc.lower()]
    known = [x for x in auth_values if x in ("pass", "fail")]
    auth_status = "Not checked" if not known else ("Pass" if all(x == "pass" for x in known) and len(known) == 3 else ("Fail" if "fail" in known else "Partial"))
    if auth_status == "Fail": reasons.append("At least one SPF/DKIM/DMARC check was marked as failed")
    if sig_status == "Failed" or auth_status == "Fail":
        if verdict == "DELIVER": verdict = "QUARANTINE"
        elif verdict == "QUARANTINE": verdict = "REJECT"
    if not reasons: reasons.append("No strong phishing indicators were found in this message")
    digest = get_hash(full)
    with db() as conn:
        cur = conn.execute("INSERT INTO scans (created_at,sender,recipient,subject,verdict,risk_score,ml_score,hash_sha256,signature_status,auth_status,reasons,body_preview) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (datetime.now(timezone.utc).isoformat(), payload.sender, payload.recipient, payload.subject, verdict, risk, ml_score, digest, sig_status, auth_status, json.dumps(list(dict.fromkeys(reasons))), payload.body[:240]))
        scan_id = cur.lastrowid
        conn.commit()
    return {"id": scan_id, "verdict": verdict, "risk_score": risk, "ml_score": ml_score, "hash_sha256": digest, "signature_status": sig_status, "auth_status": auth_status, "urls_found": urls, "reasons": list(dict.fromkeys(reasons)), "decision_note": {"DELIVER":"Low combined risk: deliver in this demo policy.","QUARANTINE":"Review needed: hold for human inspection.","REJECT":"High combined risk: block in this demo policy."}[verdict], "model_type": "TF-IDF + Logistic Regression with heuristic risk signals" if MODEL else "Rule-based fallback"}

init_db()
ensure_keys()

@app.get("/")
def home(): return FileResponse(FRONTEND / "index.html")
@app.get("/api/health")
def health(): return {"status":"ok", "model":"TF-IDF + Logistic Regression" if MODEL else "rule-based fallback", "cryptography":CRYPTO_AVAILABLE, "database":"SQLite"}
@app.post("/api/analyze")
def analyze(payload: EmailInput):
    if not (payload.subject.strip() or payload.body.strip()): raise HTTPException(400, "Enter an email subject or body before scanning.")
    return analyze_email(payload)
@app.get("/api/stats")
def stats():
    with db() as conn:
        rows = conn.execute("SELECT verdict, COUNT(*) AS n FROM scans GROUP BY verdict").fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        recent = conn.execute("SELECT created_at, verdict, risk_score FROM scans ORDER BY id DESC LIMIT 7").fetchall()
        domains = conn.execute("SELECT sender, COUNT(*) AS n FROM scans WHERE verdict != 'DELIVER' AND sender != '' GROUP BY sender ORDER BY n DESC LIMIT 5").fetchall()
    counts = {r["verdict"]:r["n"] for r in rows}
    return {"total_scanned":total,"phishing_flagged":counts.get("REJECT",0)+counts.get("QUARANTINE",0),"delivered":counts.get("DELIVER",0),"quarantined":counts.get("QUARANTINE",0),"rejected":counts.get("REJECT",0),"detection_rate":round((counts.get("REJECT",0)+counts.get("QUARANTINE",0))*100/total) if total else 0,"recent":[dict(r) for r in recent],"top_senders":[dict(r) for r in domains]}
@app.get("/api/logs")
def logs(limit: int = 50):
    limit = max(1, min(200, limit))
    with db() as conn: rows = conn.execute("SELECT id,created_at,sender,recipient,subject,verdict,risk_score,ml_score,hash_sha256,signature_status,auth_status,reasons,body_preview FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) | {"reasons":json.loads(r["reasons"] or "[]")} for r in rows]
@app.post("/api/sign")
def sign(payload: SignInput):
    signature = sign_text(payload.message)
    return {"signature":signature,"sha256":get_hash(payload.message),"algorithm":"RSA-2048 + RSA-PSS + SHA-256","note":"Demo key pair stored locally. Do not use this demo key for production email signing."}
@app.post("/api/verify")
def verify(payload: VerifyInput):
    valid, message = verify_text(payload.message, payload.signature)
    return {"valid":valid,"message":message,"sha256":get_hash(payload.message),"algorithm":"RSA-PSS + SHA-256"}
@app.get("/api/public-key")
def public_key():
    if not CRYPTO_AVAILABLE: raise HTTPException(503,"Cryptography dependency unavailable")
    ensure_keys()
    return {"public_key":PUBLIC_KEY_PATH.read_text(),"algorithm":"RSA-2048"}
@app.get("/api/export.csv")
def export_csv():
    with db() as conn: rows = conn.execute("SELECT id,created_at,sender,recipient,subject,verdict,risk_score,ml_score,hash_sha256,signature_status,auth_status,reasons FROM scans ORDER BY id DESC").fetchall()
    out = io.StringIO(); writer = csv.writer(out)
    writer.writerow(["ID","Created UTC","Sender","Recipient","Subject","Decision","Risk score","ML score","SHA-256","Signature","SPF/DKIM/DMARC","Reasons"])
    for r in rows: writer.writerow(list(r))
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=phishguard_audit_log.csv"})
@app.delete("/api/logs")
def clear_logs():
    with db() as conn: conn.execute("DELETE FROM scans"); conn.commit()
    return {"ok":True,"message":"Audit log cleared"}
