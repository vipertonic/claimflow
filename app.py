import anthropic
import os
import json
import re
import sqlite3
import httpx
import secrets
import stripe
import time
from collections import defaultdict
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import uvicorn
import bcrypt
import jwt

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_VERIFY_SID = os.getenv("TWILIO_VERIFY_SID", "")

STRIPE_PRICES = {
    "starter":      "price_1T9GYcBXkAMRnMo2fy8ihwKE",
    "professional": "price_1T9GvoBXkAMRnMo2LFZkP8pS",
    "practice":     "price_1T9Gy3BXkAMRnMo2uYqGaBnC",
    "enterprise":   "price_1T9H6TBXkAMRnMo2t1Wvb7q5",
}

DB_PATH = '/data/claims.db' if os.path.exists('/data') else 'claims.db'

app = FastAPI()

# --- RATE LIMITER ---
rate_limit_store = defaultdict(list)
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX    = 5    # max attempts per window

def check_rate_limit(ip: str, action: str = "login"):
    key = f"{ip}:{action}"
    now = time.time()
    attempts = rate_limit_store[key]
    # purge old attempts
    rate_limit_store[key] = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_store[key]) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait 60 seconds and try again.")
    rate_limit_store[key].append(now)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- JWT BLOCKLIST (logout invalidation) ---
token_blocklist = set()

# --- SECURITY HEADERS MIDDLEWARE ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
JWT_SECRET = os.getenv("JWT_SECRET", "claimflow-super-secret-key-2026")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
APP_URL = os.getenv("APP_URL", "https://app.claimflowpay.com")
security = HTTPBearer()


def send_reset_email(to_email: str, reset_token: str):
    reset_link = f"{APP_URL}/reset-password?token={reset_token}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;background:#04080f;color:#eef2ff;padding:40px;border-radius:12px;">
      <div style="margin-bottom:32px;">
        <span style="background:#00e87b;color:#000;font-weight:800;font-size:14px;padding:6px 14px;border-radius:6px;">CLAIMFLOW</span>
      </div>
      <h1 style="font-size:24px;font-weight:700;margin-bottom:12px;color:#eef2ff;">Reset your password</h1>
      <p style="color:#8fa3c4;line-height:1.7;margin-bottom:32px;">
        We received a request to reset the password for your Claimflow account. 
        Click the button below to choose a new password. This link expires in <strong style="color:#eef2ff;">1 hour</strong>.
      </p>
      <a href="{reset_link}" style="display:inline-block;background:#00e87b;color:#000;font-weight:700;font-size:15px;padding:14px 28px;border-radius:10px;text-decoration:none;margin-bottom:32px;">
        Reset Password →
      </a>
      <p style="color:#5a7299;font-size:13px;line-height:1.6;">
        If you didn't request a password reset, you can safely ignore this email — your password will not change.
      </p>
      <hr style="border:none;border-top:1px solid #13203a;margin:28px 0;"/>
      <p style="color:#5a7299;font-size:12px;">Claimflow · HIPAA Compliant · claimflowpay.us</p>
    </div>
    """
    try:
        response = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": "Claimflow <noreply@claimflowpay.com>", "to": [to_email],
                  "subject": "Reset your Claimflow password", "html": html},
            timeout=10
        )
        return response.status_code == 200
    except Exception:
        return False

NPPES_API = "https://npiregistry.cms.hhs.gov/api/?version=2.1&number="
CO_LICENSE_PATTERN = re.compile(r'^[A-Z]{2}-\d{4,8}$')


def setup_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            practice_id INTEGER,
            patient_name TEXT,
            date_of_service TEXT,
            icd10_codes TEXT,
            cpt_codes TEXT,
            payer TEXT,
            prior_auth_required TEXT,
            prior_auth_status TEXT,
            claim_status TEXT,
            date_submitted TEXT,
            date_updated TEXT,
            notes TEXT,
            denial_reason TEXT,
            appeal_letter TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS practices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            practice_name TEXT NOT NULL,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            npi TEXT NOT NULL UNIQUE,
            npi_name TEXT,
            npi_type TEXT,
            license_number TEXT NOT NULL,
            address TEXT,
            city TEXT,
            state TEXT DEFAULT "CO",
            zip TEXT,
            plan TEXT DEFAULT "none",
            subscription_status TEXT DEFAULT "none",
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            created_at TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')
    # Migration: add stripe columns if they don't exist
    for col, coltype in [
        ("subscription_status", "TEXT DEFAULT 'none'"),
        ("stripe_customer_id", "TEXT"),
        ("stripe_subscription_id", "TEXT"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE practices ADD COLUMN {col} {coltype}")
        except Exception:
            pass
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS waitlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            state TEXT,
            state_code TEXT,
            created_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            practice_id INTEGER,
            identifier TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()


def audit(action: str, practice_id=None, identifier=None, ip=None, details=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO audit_log (timestamp, practice_id, identifier, action, ip_address, details) VALUES (?,?,?,?,?,?)",
            (datetime.utcnow().isoformat(), practice_id, identifier, action, ip, details)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def hash_password(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def verify_password(p, h):
    return bcrypt.checkpw(p.encode(), h.encode())

def create_token(practice_id, identifier, hours=2):
    payload = {"practice_id": practice_id, "identifier": identifier,
                "exp": datetime.utcnow() + timedelta(hours=hours)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token in token_blocklist:
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token. Please login again.")


def verify_npi(npi: str):
    if not npi or len(npi) != 10 or not npi.isdigit():
        return {"valid": False, "error": "NPI must be exactly 10 digits."}
    try:
        response = httpx.get(NPPES_API + npi, timeout=8)
        data = response.json()
        results = data.get("results", [])
        if not results:
            return {"valid": False, "error": "NPI not found in the national registry."}
        result = results[0]
        basic = result.get("basic", {})
        enumeration_type = result.get("enumeration_type", "")
        if enumeration_type == "NPI-1":
            first = basic.get("first_name", "")
            last = basic.get("last_name", "")
            credential = basic.get("credential", "")
            name = f"{first} {last}, {credential}".strip(", ")
            provider_type = "Individual Provider"
        else:
            name = basic.get("organization_name", "")
            provider_type = "Organization"
        addresses = result.get("addresses", [])
        state = ""
        for addr in addresses:
            if addr.get("address_purpose") == "LOCATION":
                state = addr.get("state", "")
                break
        if basic.get("status", "") != "A":
            return {"valid": False, "error": "This NPI is no longer active."}
        return {"valid": True, "name": name, "type": provider_type, "state": state, "error": None}
    except httpx.TimeoutException:
        return {"valid": False, "error": "NPI verification timed out. Please try again."}
    except Exception:
        return {"valid": False, "error": "NPI verification service unavailable."}


def extract_medical_codes(clinical_note):
    response = client.messages.create(
        model="claude-opus-4-5", max_tokens=1000,
        system='You are a certified medical coder (CPC). Extract ICD-10 and CPT codes. Return JSON only: {"icd10": ["E11.9"], "cpt": ["99213"]}',
        messages=[{"role": "user", "content": "Extract codes:\n\n" + clinical_note}]
    )
    text = response.content[0].text
    try:
        match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        return json.loads(match.group()) if match else {"icd10": [], "cpt": []}
    except:
        return {"icd10": re.findall(r'[A-Z]\d{2}\.?\d*', text), "cpt": re.findall(r'\b\d{5}\b', text)}

PRIOR_AUTH_MATRIX = {
    "UnitedHealthcare": {"99213": False, "99214": False, "70553": True, "27447": True, "83036": False, "93000": False, "29827": True, "73721": True},
    "Aetna":            {"99213": False, "99214": False, "70553": True, "27447": True, "83036": False, "93000": False, "29827": True, "73721": True},
    "BlueCross":        {"99213": False, "99214": False, "70553": True, "27447": True, "83036": False, "93000": False, "29827": True, "73721": True},
    "Cigna":            {"99213": False, "99214": False, "70553": True, "27447": True, "83036": False, "93000": False, "29827": True, "73721": True},
}

def check_prior_auth(cpt_codes, payer):
    rules = PRIOR_AUTH_MATRIX.get(payer, {})
    return [{"cpt_code": c, "payer": payer, "requires_prior_auth": rules.get(c, False),
             "status": "AUTH REQUIRED" if rules.get(c, False) else "NO AUTH NEEDED"} for c in cpt_codes]

DENIAL_REASONS = {
    "CO-4": "Procedure code inconsistent with modifier",
    "CO-11": "Diagnosis inconsistent with procedure",
    "CO-29": "Claim submitted past timely filing limit",
    "CO-50": "Non-covered service",
    "CO-97": "Service already adjudicated",
    "PR-1": "Deductible not met",
    "PR-2": "Coinsurance amount",
    "PR-96": "Prior authorization not obtained",
    "OA-23": "Payment adjusted due to prior authorization"
}

def categorize_denial(code):
    reason = DENIAL_REASONS.get(code, "Unknown denial reason")
    if code in ["PR-96", "OA-23"]:  cat, action = "PRIOR AUTH ISSUE", "Submit prior authorization request immediately"
    elif code in ["CO-4", "CO-11"]: cat, action = "CODING ERROR", "Review and correct procedure or diagnosis codes"
    elif code == "CO-29":           cat, action = "TIMELY FILING", "Submit proof of timely filing with appeal"
    elif code in ["PR-1", "PR-2"]:  cat, action = "PATIENT RESPONSIBILITY", "Bill patient for deductible or coinsurance"
    elif code == "CO-50":           cat, action = "NON-COVERED SERVICE", "Appeal with medical necessity documentation"
    else:                           cat, action = "OTHER", "Review denial and appeal with supporting documents"
    return {"denial_code": code, "reason": reason, "category": cat, "recommended_action": action}


class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class RegisterRequest(BaseModel):
    practice_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    password: str
    npi: str
    license_number: str
    address: Optional[str] = None
    city: Optional[str] = None
    zip: Optional[str] = None

class LoginRequest(BaseModel):
    identifier: str
    password: str
    stay_logged_in: Optional[bool] = False

class VerifyNPIRequest(BaseModel):
    npi: str

class WaitlistRequest(BaseModel):
    email: str
    state: Optional[str] = ""
    state_code: Optional[str] = ""

class ProcessClaimRequest(BaseModel):
    patient_name: str
    date_of_service: str
    payer: str
    clinical_note: str

class DenialRequest(BaseModel):
    claim_id: int
    denial_code: str

class UpdateStatusRequest(BaseModel):
    claim_id: int
    new_status: str
    notes: str = ""


@app.get("/")
def serve_login():
    p = os.path.join(os.path.dirname(__file__), "login.html")
    return FileResponse(p, media_type="text/html") if os.path.exists(p) else {"message": "Claimflow API running"}

@app.get("/dashboard")
def serve_dashboard():
    p = os.path.join(os.path.dirname(__file__), "dashboard.html")
    return FileResponse(p, media_type="text/html") if os.path.exists(p) else {"message": "Dashboard not found"}

@app.get("/reset-password")
def serve_reset_password():
    p = os.path.join(os.path.dirname(__file__), "reset-password.html")
    return FileResponse(p, media_type="text/html") if os.path.exists(p) else {"message": "Reset page not found"}

@app.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest):
    email = req.email.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM practices WHERE email = ?', (email,))
    practice = cursor.fetchone()
    # Always return success to prevent email enumeration
    if not practice:
        conn.close()
        return {"success": True, "message": "If that email exists, a reset link has been sent."}
    # Generate secure token
    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    # Invalidate old tokens for this email
    cursor.execute('UPDATE password_reset_tokens SET used=1 WHERE email=?', (email,))
    cursor.execute(
        'INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?,?,?)',
        (email, token, expires_at)
    )
    conn.commit()
    conn.close()
    # Send email
    sent = send_reset_email(email, token)
    return {"success": True, "message": "If that email exists, a reset link has been sent."}

@app.post("/reset-password")
def reset_password(req: ResetPasswordRequest):
    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT email, expires_at, used FROM password_reset_tokens WHERE token=?',
        (req.token,)
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired reset link.")
    email, expires_at, used = row
    if used:
        conn.close()
        raise HTTPException(status_code=400, detail="This reset link has already been used.")
    if datetime.now() > datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S"):
        conn.close()
        raise HTTPException(status_code=400, detail="This reset link has expired. Please request a new one.")
    # Update password
    new_hash = hash_password(req.new_password)
    cursor.execute('UPDATE practices SET password_hash=? WHERE email=?', (new_hash, email))
    cursor.execute('UPDATE password_reset_tokens SET used=1 WHERE token=?', (req.token,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Password updated successfully. You can now log in."}

@app.get("/health")
def health():
    return {"message": "Claimflow API is running!"}

@app.post("/verify-npi")
def verify_npi_endpoint(req: VerifyNPIRequest):
    return verify_npi(req.npi)

@app.post("/waitlist")
def join_waitlist(req: WaitlistRequest):
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email address is required.")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO waitlist (email, state, state_code, created_at) VALUES (?,?,?,?)",
            (email, req.state, req.state_code, datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
        conn.close()
        return {"success": True, "message": "You're on the waitlist!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/waitlist")
def get_waitlist(user=Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT email, state, state_code, created_at FROM waitlist ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"email": r[0], "state": r[1], "state_code": r[2], "signed_up": r[3]} for r in rows]

@app.post("/register")
def register(req: RegisterRequest, request: Request):
    ip = request.client.host
    check_rate_limit(ip, "register")
    if not req.email and not req.phone:
        raise HTTPException(status_code=400, detail="Email or phone number is required.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    npi_result = verify_npi(req.npi)
    if not npi_result["valid"]:
        raise HTTPException(status_code=400, detail=npi_result["error"])
    if not CO_LICENSE_PATTERN.match(req.license_number.upper()):
        raise HTTPException(status_code=400, detail="Invalid Colorado license format. Expected: DR-12345, NR-12345, or PA-12345")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if req.email:
        cursor.execute('SELECT id FROM practices WHERE email = ?', (req.email,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="An account with this email already exists.")
    if req.phone:
        cursor.execute('SELECT id FROM practices WHERE phone = ?', (req.phone,))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="An account with this phone number already exists.")
    cursor.execute('SELECT id FROM practices WHERE npi = ?', (req.npi,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="An account with this NPI already exists.")
    password_hash = hash_password(req.password)
    confirm_token = secrets.token_urlsafe(32)
    cursor.execute('''
        INSERT INTO practices
        (practice_name, email, phone, password_hash, npi, npi_name, npi_type,
         license_number, address, city, zip, created_at, email_confirm_token, email_verified)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        req.practice_name, req.email, req.phone, password_hash,
        req.npi, npi_result.get("name", ""), npi_result.get("type", ""),
        req.license_number.upper(), req.address, req.city, req.zip,
        datetime.now().strftime("%Y-%m-%d %H:%M"), confirm_token, 0
    ))
    practice_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Send confirmation email or SMS
    if req.email and RESEND_API_KEY:
        send_confirmation_email(req.email, req.practice_name, confirm_token)
    elif req.phone and TWILIO_ACCOUNT_SID:
        send_sms_verification(req.phone)

    identifier = req.email or req.phone
    token = create_token(practice_id, identifier)
    return {"message": "Account created successfully!", "token": token,
            "practice_name": req.practice_name, "identifier": identifier,
            "verified_provider": npi_result.get("name", "")}


def send_confirmation_email(email: str, practice_name: str, confirm_token: str):
    confirm_url = f"{APP_URL}/verify-email?token={confirm_token}"
    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="background:#0a0a0a;font-family:'DM Mono',monospace,sans-serif;padding:40px 24px;color:#e0e0e0">
      <div style="max-width:520px;margin:0 auto">
        <div style="font-size:1.1rem;font-weight:500;color:#00ff88;letter-spacing:3px;margin-bottom:32px">CLAIMFLOW</div>
        <h1 style="font-size:1.2rem;color:#e0e0e0;margin-bottom:16px;font-weight:500">Confirm your email address</h1>
        <p style="font-size:0.85rem;color:#888;line-height:1.7;margin-bottom:32px">
          Hi {practice_name},<br/><br/>
          Thanks for signing up for Claimflow. Click the button below to confirm your email and activate your account.
        </p>
        <a href="{confirm_url}" style="display:inline-block;background:#00ff88;color:#000;padding:12px 28px;border-radius:6px;font-size:0.85rem;font-weight:700;text-decoration:none;letter-spacing:1px">CONFIRM EMAIL →</a>
        <p style="font-size:0.72rem;color:#444;margin-top:32px;line-height:1.6">
          If you didn't create a Claimflow account, you can safely ignore this email.<br/>
          This link expires in 24 hours.
        </p>
        <div style="margin-top:40px;padding-top:24px;border-top:1px solid #1a1a1a;font-size:0.65rem;color:#333;letter-spacing:1px">
          CLAIMFLOW · AI MEDICAL BILLING · HIPAA COMPLIANT
        </div>
      </div>
    </body>
    </html>
    """
    try:
        import httpx as _httpx
        _httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": "Claimflow <noreply@claimflowpay.com>", "to": [email],
                  "subject": "Confirm your Claimflow account", "html": html},
            timeout=10
        )
    except Exception:
        pass  # Don't block registration if email fails


@app.get("/verify-email")
def verify_email(token: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM practices WHERE email_confirm_token=?", (token,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired confirmation link.")
    cursor.execute("UPDATE practices SET email_verified=1, email_confirm_token=NULL WHERE id=?", (row[0],))
    conn.commit()
    conn.close()
    # Redirect to billing page
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/billing?verified=1")

def send_sms_verification(phone: str):
    """Send SMS verification code via Twilio Verify"""
    try:
        import httpx as _httpx
        response = _httpx.post(
            f"https://verify.twilio.com/v2/Services/{TWILIO_VERIFY_SID}/Verifications",
            data={"To": phone, "Channel": "sms"},
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=10
        )
        return response.status_code == 201
    except Exception:
        return False

def check_sms_verification(phone: str, code: str) -> bool:
    """Check SMS verification code via Twilio Verify"""
    try:
        import httpx as _httpx
        response = _httpx.post(
            f"https://verify.twilio.com/v2/Services/{TWILIO_VERIFY_SID}/VerificationCheck",
            data={"To": phone, "Code": code},
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=10
        )
        data = response.json()
        return data.get("status") == "approved"
    except Exception:
        return False

class PhoneVerifyRequest(BaseModel):
    phone: str
    code: str

@app.post("/verify-phone")
def verify_phone(req: PhoneVerifyRequest):
    approved = check_sms_verification(req.phone, req.code)
    if not approved:
        raise HTTPException(status_code=400, detail="Invalid or expired code. Please try again.")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE practices SET email_verified=1 WHERE phone=?", (req.phone,))
    conn.commit()
    conn.close()
    return {"status": "verified"}

@app.post("/resend-sms")
def resend_sms(req: dict):
    phone = req.get("phone", "")
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number required.")
    sent = send_sms_verification(phone)
    if not sent:
        raise HTTPException(status_code=500, detail="Failed to send SMS. Please try again.")
    return {"status": "sent"}


@app.post("/login")
def login(req: LoginRequest, request: Request):
    ip = request.client.host
    check_rate_limit(ip, "login")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM practices WHERE email = ? OR phone = ?',
                   (req.identifier, req.identifier))
    practice = cursor.fetchone()
    conn.close()
    if not practice or not verify_password(req.password, practice[4]):
        audit("LOGIN_FAILED", identifier=req.identifier, ip=ip)
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    if not practice[15]:
        raise HTTPException(status_code=401, detail="Account is inactive.")
    identifier = practice[2] or practice[3]
    hours = 12 if req.stay_logged_in else 2
    token = create_token(practice[0], identifier, hours=hours)
    audit("LOGIN_SUCCESS", practice_id=practice[0], identifier=identifier, ip=ip)
    return {"message": "Login successful!", "token": token,
            "practice_name": practice[1], "identifier": identifier}

@app.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security), user=Depends(verify_token)):
    token_blocklist.add(credentials.credentials)
    audit("LOGOUT", practice_id=user.get("practice_id"), identifier=user.get("identifier"))
    return {"message": "Logged out successfully."}

@app.post("/process-claim")
def process_claim(req: ProcessClaimRequest, user=Depends(verify_token)):
    pid = user["practice_id"]
    codes = extract_medical_codes(req.clinical_note)
    auth_results = check_prior_auth(codes["cpt"], req.payer)
    needs_auth = [r["cpt_code"] for r in auth_results if r["requires_prior_auth"]]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO claims
        (practice_id, patient_name, date_of_service, icd10_codes, cpt_codes, payer,
         prior_auth_required, prior_auth_status, claim_status, date_submitted, date_updated, notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (pid, req.patient_name, req.date_of_service,
          json.dumps(codes["icd10"]), json.dumps(codes["cpt"]), req.payer,
          "YES" if needs_auth else "NO", "PENDING" if needs_auth else "NOT REQUIRED",
          "SUBMITTED", datetime.now().strftime("%Y-%m-%d %H:%M"),
          datetime.now().strftime("%Y-%m-%d %H:%M"),
          "Auth needed: " + str(needs_auth) if needs_auth else "No auth required"))
    claim_id = cursor.lastrowid
    conn.commit()
    conn.close()
    audit("CLAIM_CREATED", practice_id=pid, details=f"claim_id={claim_id} payer={req.payer}")
    return {"claim_id": claim_id, "icd10_codes": codes["icd10"], "cpt_codes": codes["cpt"],
            "auth_results": auth_results, "prior_auth_required": "YES" if needs_auth else "NO", "status": "SUBMITTED"}

@app.get("/claims")
def get_claims(user=Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims WHERE practice_id = ? ORDER BY id DESC', (user["practice_id"],))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "patient_name": r[2], "date_of_service": r[3],
             "icd10_codes": json.loads(r[4]) if r[4] else [], "cpt_codes": json.loads(r[5]) if r[5] else [],
             "payer": r[6], "prior_auth_required": r[7], "prior_auth_status": r[8],
             "claim_status": r[9], "date_submitted": r[10], "date_updated": r[11],
             "notes": r[12], "denial_reason": r[13], "appeal_letter": r[14]} for r in rows]

@app.get("/claim-summary/{claim_id}")
def claim_summary_pdf(claim_id: int, user=Depends(verify_token)):
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims WHERE id=? AND practice_id=?', (claim_id, user["practice_id"]))
    claim = cursor.fetchone()
    cursor.execute('SELECT practice_name, email, phone, npi, npi_name, address, city, state, zip FROM practices WHERE id=?', (user["practice_id"],))
    practice = cursor.fetchone()
    conn.close()

    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found")

    icd10 = json.loads(claim[4]) if claim[4] else []
    cpt   = json.loads(claim[5]) if claim[5] else []

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)

    # Colors — clean white/black
    black     = colors.HexColor("#111111")
    dark_gray = colors.HexColor("#444444")
    mid_gray  = colors.HexColor("#888888")
    light_gray= colors.HexColor("#f2f2f2")
    sec_gray  = colors.HexColor("#555555")
    border    = colors.HexColor("#cccccc")
    white     = colors.white

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    hdr_style  = S("hdr",  fontSize=22, textColor=black,     fontName="Helvetica-Bold", spaceAfter=0, leading=26)
    sub_style  = S("sub",  fontSize=9,  textColor=mid_gray,  fontName="Helvetica",      spaceAfter=14, spaceBefore=6)
    sec_style  = S("sec",  fontSize=8,  textColor=white,     fontName="Helvetica-Bold", spaceBefore=0, spaceAfter=0)
    lbl_style  = S("lbl",  fontSize=8,  textColor=dark_gray, fontName="Helvetica")
    val_style  = S("val",  fontSize=9,  textColor=black,     fontName="Helvetica-Bold")
    note_style = S("note", fontSize=9,  textColor=black,     fontName="Helvetica", leading=14)
    foot_style = S("foot", fontSize=7,  textColor=mid_gray,  fontName="Helvetica", alignment=TA_CENTER)

    story = []

    # Header — stacked, no overlap
    story.append(Paragraph("CLAIMFLOWPAY", hdr_style))
    story.append(Paragraph(
        f"Claim Summary  ·  CMS-1500 Reference Format  ·  Claim #{claim[0]}  ·  {datetime.utcnow().strftime('%B %d, %Y')}",
        sub_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"), spaceAfter=14))

    # Status row
    status_color = colors.HexColor("#1a7a40") if claim[9] == "APPROVED" \
        else colors.HexColor("#cc2200") if "DENIED" in str(claim[9]) \
        else colors.HexColor("#b07800")
    status_data = [[
        Paragraph("Claim Status", lbl_style),
        Paragraph(str(claim[9]), S("sv", fontSize=10, textColor=status_color, fontName="Helvetica-Bold", alignment=TA_RIGHT))
    ]]
    status_tbl = Table(status_data, colWidths=["50%","50%"])
    status_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), light_gray),
        ("BOX",           (0,0), (-1,-1), 0.5, border),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("RIGHTPADDING",  (0,0), (-1,-1), 12),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(status_tbl)
    story.append(Spacer(1, 14))

    # Section helper
    def section(title, rows):
        # Section header bar
        hdr = Table([[Paragraph(title, sec_style)]], colWidths=["100%"])
        hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), sec_gray),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        story.append(hdr)
        data = []
        for label, value in rows:
            data.append([
                Paragraph(label, lbl_style),
                Paragraph(str(value) if value else "—", val_style)
            ])
        t = Table(data, colWidths=[1.8*inch, 5.2*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), white),
            ("BACKGROUND",    (0,0), (0,-1),  light_gray),
            ("BOX",           (0,0), (-1,-1), 0.5, border),
            ("INNERGRID",     (0,0), (-1,-1), 0.5, border),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("RIGHTPADDING",  (0,0), (-1,-1), 10),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ]))
        story.append(t)

    section("PATIENT / INSURED INFORMATION", [
        ("Patient Name",        claim[2]),
        ("Date of Service",     claim[3]),
        ("Insurance Payer",     claim[6]),
        ("Prior Auth Required", claim[7]),
        ("Prior Auth Status",   claim[8]),
    ])

    if practice:
        story.append(Spacer(1, 10))
        section("BILLING PROVIDER INFORMATION", [
            ("Practice Name",  practice[0]),
            ("NPI",            practice[3]),
            ("Provider Name",  practice[4] or "—"),
            ("Email",          practice[1] or "—"),
            ("Phone",          practice[2] or "—"),
            ("Address",        f"{practice[5] or ''}, {practice[6] or ''}, {practice[7] or ''} {practice[8] or ''}".strip(", ")),
        ])

    # DIAGNOSIS CODES
    story.append(Spacer(1, 10))
    diag_hdr = Table([[Paragraph("DIAGNOSIS CODES  —  BOX 21 (ICD-10-CM)", sec_style)]], colWidths=["100%"])
    diag_hdr.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), sec_gray),
        ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
    ]))
    story.append(diag_hdr)
    if icd10:
        diag_data = [[
            Paragraph("#", S("th", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold")),
            Paragraph("ICD-10 Code", S("th2", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold")),
            Paragraph("Description", S("th3", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold")),
        ]]
        for i, code in enumerate(icd10):
            bg = white if i % 2 == 0 else light_gray
            if isinstance(code, dict):
                diag_data.append([str(i+1), code.get("code",""), code.get("description","See EHR")])
            else:
                diag_data.append([str(i+1), str(code), "See EHR for description"])
        diag_tbl = Table(diag_data, colWidths=[0.4*inch, 1.4*inch, 5.2*inch])
        diag_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  light_gray),
            ("TEXTCOLOR",     (0,0), (-1,-1), black),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("BOX",           (0,0), (-1,-1), 0.5, border),
            ("INNERGRID",     (0,0), (-1,-1), 0.5, border),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [white, light_gray]),
        ]))
        story.append(diag_tbl)
    else:
        story.append(Paragraph("No diagnosis codes recorded.", note_style))

    # PROCEDURE CODES
    story.append(Spacer(1, 10))
    proc_hdr = Table([[Paragraph("PROCEDURE CODES  —  BOX 24 (CPT/HCPCS)", sec_style)]], colWidths=["100%"])
    proc_hdr.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), sec_gray),
        ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
    ]))
    story.append(proc_hdr)
    if cpt:
        proc_data = [[
            Paragraph("#",           S("ph",  fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold")),
            Paragraph("CPT Code",    S("ph2", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold")),
            Paragraph("Description", S("ph3", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold")),
            Paragraph("Units",       S("ph4", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph("Charges",     S("ph5", fontSize=8, textColor=dark_gray, fontName="Helvetica-Bold", alignment=TA_RIGHT)),
        ]]
        for i, code in enumerate(cpt):
            if isinstance(code, dict):
                proc_data.append([str(i+1), code.get("code",""), code.get("description","See fee schedule"), "1", "$0.00"])
            else:
                proc_data.append([str(i+1), str(code), "See fee schedule", "1", "$0.00"])
        proc_tbl = Table(proc_data, colWidths=[0.4*inch, 1.1*inch, 3.8*inch, 0.7*inch, 1.0*inch])
        proc_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  light_gray),
            ("TEXTCOLOR",     (0,0), (-1,-1), black),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("BOX",           (0,0), (-1,-1), 0.5, border),
            ("INNERGRID",     (0,0), (-1,-1), 0.5, border),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("ALIGN",         (3,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [white, light_gray]),
        ]))
        story.append(proc_tbl)
    else:
        story.append(Paragraph("No procedure codes recorded.", note_style))

    # Notes
    if claim[12]:
        story.append(Spacer(1, 10))
        notes_hdr = Table([[Paragraph("NOTES", sec_style)]], colWidths=["100%"])
        notes_hdr.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), sec_gray),
            ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
        ]))
        story.append(notes_hdr)
        notes_tbl = Table([[Paragraph(claim[12], note_style)]], colWidths=["100%"])
        notes_tbl.setStyle(TableStyle([
            ("BOX", (0,0), (-1,-1), 0.5, border),
            ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10), ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ]))
        story.append(notes_tbl)

    if claim[13]:
        story.append(Spacer(1, 10))
        story.append(Paragraph("DENIAL REASON", sec_style))
        story.append(Paragraph(claim[13], note_style))

    # Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=border, spaceAfter=8))
    story.append(Paragraph(
        f"Generated by Claimflow  ·  {datetime.utcnow().strftime('%B %d, %Y  %H:%M UTC')}  ·  HIPAA Compliant  ·  claimflowpay.com",
        foot_style
    ))
    story.append(Paragraph(
        "For billing reference only. Complete charges per your practice fee schedule before submission.",
        foot_style
    ))

    doc.build(story)
    buf.seek(0)
    filename = f"claimflow_claim_{claim_id}_{claim[2].replace(' ','_')}.pdf"
    return StreamingResponse(buf, media_type="application/pdf",
                             headers={"Content-Disposition": f"attachment; filename={filename}"})

@app.post("/process-denial")
def process_denial(req: DenialRequest, user=Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims WHERE id = ? AND practice_id = ?', (req.claim_id, user["practice_id"]))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Claim not found")
    denial_info = categorize_denial(req.denial_code)
    response = client.messages.create(
        model="claude-opus-4-5", max_tokens=1500,
        system="You are an expert medical billing appeals specialist with 20 years of experience.",
        messages=[{"role": "user", "content":
            f"Write a formal appeal letter:\nPatient: {row[2]}\nInsurance: {row[6]}\n"
            f"Denial Code: {req.denial_code}\nReason: {denial_info['reason']}\n"
            f"ICD-10: {row[4]}\nCPT: {row[5]}"}]
    )
    appeal = response.content[0].text
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE claims SET claim_status=?, denial_reason=?, appeal_letter=?, date_updated=? WHERE id=?',
                   ("DENIED - APPEAL IN PROGRESS", denial_info["reason"], appeal,
                    datetime.now().strftime("%Y-%m-%d %H:%M"), req.claim_id))
    conn.commit()
    conn.close()
    return {"denial_info": denial_info, "appeal_letter": appeal}

@app.get("/run-migration")
def run_migration():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for col, coltype in [
        ("subscription_status", "TEXT DEFAULT 'none'"),
        ("stripe_customer_id", "TEXT"),
        ("stripe_subscription_id", "TEXT"),
        ("email_verified", "INTEGER DEFAULT 0"),
        ("email_confirm_token", "TEXT"),
    ]:
        try:
            cursor.execute(f"ALTER TABLE practices ADD COLUMN {col} {coltype}")
            conn.commit()
        except Exception:
            pass
    # Create audit log table if not exists
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            practice_id INTEGER,
            identifier TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()
    return {"status": "migration complete"}

@app.get("/audit-log")
def get_audit_log(user=Depends(verify_token)):
    """Returns last 200 audit events for this practice."""
    pid = user["practice_id"]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, action, ip_address, details FROM audit_log WHERE practice_id=? ORDER BY id DESC LIMIT 200",
        (pid,)
    )
    rows = cursor.fetchall()
    conn.close()
    return {"events": [{"timestamp": r[0], "action": r[1], "ip": r[2], "details": r[3]} for r in rows]}

@app.get("/stats")
def get_stats(user=Depends(verify_token)):
    pid = user["practice_id"]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM claims WHERE practice_id=?', (pid,))
    total = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE practice_id=? AND claim_status="SUBMITTED"', (pid,))
    submitted = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE practice_id=? AND claim_status="APPROVED"', (pid,))
    approved = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE practice_id=? AND claim_status LIKE "DENIED%"', (pid,))
    denied = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE practice_id=? AND prior_auth_required="YES"', (pid,))
    auth_req = cursor.fetchone()[0]
    conn.close()
    return {"total": total, "submitted": submitted, "approved": approved, "denied": denied, "auth_required": auth_req}


@app.get("/billing")
def serve_billing():
    p = os.path.join(os.path.dirname(__file__), "billing.html")
    return FileResponse(p, media_type="text/html") if os.path.exists(p) else {"message": "Not found"}

@app.get("/register")
def serve_register():
    p = os.path.join(os.path.dirname(__file__), "login.html")
    return FileResponse(p, media_type="text/html") if os.path.exists(p) else {"message": "Not found"}

@app.get("/login")
def serve_login_page():
    p = os.path.join(os.path.dirname(__file__), "login.html")
    return FileResponse(p, media_type="text/html") if os.path.exists(p) else {"message": "Not found"}

# ── STRIPE MODELS ─────────────────────────────────────────────────────────────
class CheckoutRequest(BaseModel):
    price_id: str
    plan_name: str

# ── STRIPE CHECKOUT SESSION ───────────────────────────────────────────────────
@app.post("/create-checkout-session")
def create_checkout_session(req: CheckoutRequest, user=Depends(verify_token)):
    if not stripe.api_key:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    # Get or create Stripe customer
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT stripe_customer_id, email FROM practices WHERE id=?", (user["practice_id"],))
    row = cursor.fetchone()
    conn.close()

    stripe_customer_id = row[0] if row else None
    email = row[1] if row else None

    if not stripe_customer_id:
        customer = stripe.Customer.create(email=email, metadata={"practice_id": str(user["practice_id"])})
        stripe_customer_id = customer.id
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE practices SET stripe_customer_id=? WHERE id=?", (stripe_customer_id, user["practice_id"]))
        conn.commit()
        conn.close()

    session = stripe.checkout.Session.create(
        customer=stripe_customer_id,
        payment_method_types=["card"],
        line_items=[{"price": req.price_id, "quantity": 1}],
        mode="subscription",
        subscription_data={"trial_period_days": 30},
        success_url="https://app.claimflowpay.com/dashboard?subscribed=1",
        cancel_url="https://app.claimflowpay.com/billing",
        metadata={"practice_id": str(user["practice_id"]), "plan_name": req.plan_name}
    )

    return {"checkout_url": session.url}

# ── STRIPE WEBHOOK ────────────────────────────────────────────────────────────
@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        practice_id = session.get("metadata", {}).get("practice_id")
        plan_name = session.get("metadata", {}).get("plan_name", "").lower()
        subscription_id = session.get("subscription")
        if practice_id:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE practices SET subscription_status='active', plan=?, stripe_subscription_id=? WHERE id=?",
                (plan_name, subscription_id, int(practice_id))
            )
            conn.commit()
            conn.close()

    elif event["type"] == "customer.subscription.deleted":
        sub = event["data"]["object"]
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE practices SET subscription_status='cancelled', plan='none' WHERE stripe_subscription_id=?",
            (sub["id"],)
        )
        conn.commit()
        conn.close()

    elif event["type"] in ("invoice.payment_failed", "invoice.payment_succeeded"):
        sub_id = event["data"]["object"].get("subscription")
        status = "active" if event["type"] == "invoice.payment_succeeded" else "past_due"
        if sub_id:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("UPDATE practices SET subscription_status=? WHERE stripe_subscription_id=?", (status, sub_id))
            conn.commit()
            conn.close()

    return {"status": "ok"}

# ── BILLING STATUS ─────────────────────────────────────────────────────────────
@app.get("/billing-status")
def billing_status(user=Depends(verify_token)):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT plan, subscription_status, stripe_subscription_id, stripe_customer_id FROM practices WHERE id=?", (user["practice_id"],))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {"plan": "none", "status": "none"}

    plan, status, sub_id, customer_id = row
    portal_url = None
    if customer_id and stripe.api_key:
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url="https://app.claimflowpay.com/dashboard"
            )
            portal_url = session.url
        except Exception:
            pass

    return {"plan": plan or "none", "status": status or "none", "portal_url": portal_url}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
