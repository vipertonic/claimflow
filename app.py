import anthropic
import os
import json
import re
import sqlite3
import httpx
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import uvicorn
import bcrypt
import jwt

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
JWT_SECRET = os.getenv("JWT_SECRET", "claimflow-super-secret-key-2026")
security = HTTPBearer()

NPPES_API = "https://npiregistry.cms.hhs.gov/api/?version=2.1&number="
CO_LICENSE_PATTERN = re.compile(r'^[A-Z]{2}-\d{4,8}$')


def setup_database():
    conn = sqlite3.connect('claims.db')
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
            plan TEXT DEFAULT "professional",
            created_at TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS waitlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            state TEXT,
            state_code TEXT,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

setup_database()


def hash_password(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()

def verify_password(p, h):
    return bcrypt.checkpw(p.encode(), h.encode())

def create_token(practice_id, identifier):
    payload = {"practice_id": practice_id, "identifier": identifier,
                "exp": datetime.utcnow() + timedelta(hours=8)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
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
        model="claude-opus-4-6", max_tokens=1000,
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
        conn = sqlite3.connect('claims.db')
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
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute("SELECT email, state, state_code, created_at FROM waitlist ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"email": r[0], "state": r[1], "state_code": r[2], "signed_up": r[3]} for r in rows]

@app.post("/register")
def register(req: RegisterRequest):
    if not req.email and not req.phone:
        raise HTTPException(status_code=400, detail="Email or phone number is required.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    npi_result = verify_npi(req.npi)
    if not npi_result["valid"]:
        raise HTTPException(status_code=400, detail=npi_result["error"])
    if not CO_LICENSE_PATTERN.match(req.license_number.upper()):
        raise HTTPException(status_code=400, detail="Invalid Colorado license format. Expected: DR-12345, NR-12345, or PA-12345")
    conn = sqlite3.connect('claims.db')
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
    cursor.execute('''
        INSERT INTO practices
        (practice_name, email, phone, password_hash, npi, npi_name, npi_type,
         license_number, address, city, zip, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        req.practice_name, req.email, req.phone, password_hash,
        req.npi, npi_result.get("name", ""), npi_result.get("type", ""),
        req.license_number.upper(), req.address, req.city, req.zip,
        datetime.now().strftime("%Y-%m-%d %H:%M")
    ))
    practice_id = cursor.lastrowid
    conn.commit()
    conn.close()
    identifier = req.email or req.phone
    token = create_token(practice_id, identifier)
    return {"message": "Account created successfully!", "token": token,
            "practice_name": req.practice_name, "identifier": identifier,
            "verified_provider": npi_result.get("name", "")}

@app.post("/login")
def login(req: LoginRequest):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM practices WHERE email = ? OR phone = ?',
                   (req.identifier, req.identifier))
    practice = cursor.fetchone()
    conn.close()
    if not practice or not verify_password(req.password, practice[4]):
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    if not practice[15]:
        raise HTTPException(status_code=401, detail="Account is inactive.")
    identifier = practice[2] or practice[3]
    token = create_token(practice[0], identifier)
    return {"message": "Login successful!", "token": token,
            "practice_name": practice[1], "identifier": identifier}

@app.post("/process-claim")
def process_claim(req: ProcessClaimRequest, user=Depends(verify_token)):
    pid = user["practice_id"]
    codes = extract_medical_codes(req.clinical_note)
    auth_results = check_prior_auth(codes["cpt"], req.payer)
    needs_auth = [r["cpt_code"] for r in auth_results if r["requires_prior_auth"]]
    conn = sqlite3.connect('claims.db')
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
    return {"claim_id": claim_id, "icd10_codes": codes["icd10"], "cpt_codes": codes["cpt"],
            "auth_results": auth_results, "prior_auth_required": "YES" if needs_auth else "NO", "status": "SUBMITTED"}

@app.get("/claims")
def get_claims(user=Depends(verify_token)):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims WHERE practice_id = ? ORDER BY id DESC', (user["practice_id"],))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "patient_name": r[2], "date_of_service": r[3],
             "icd10_codes": json.loads(r[4]) if r[4] else [], "cpt_codes": json.loads(r[5]) if r[5] else [],
             "payer": r[6], "prior_auth_required": r[7], "prior_auth_status": r[8],
             "claim_status": r[9], "date_submitted": r[10], "date_updated": r[11],
             "notes": r[12], "denial_reason": r[13], "appeal_letter": r[14]} for r in rows]

@app.post("/process-denial")
def process_denial(req: DenialRequest, user=Depends(verify_token)):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims WHERE id = ? AND practice_id = ?', (req.claim_id, user["practice_id"]))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Claim not found")
    denial_info = categorize_denial(req.denial_code)
    response = client.messages.create(
        model="claude-opus-4-6", max_tokens=1500,
        system="You are an expert medical billing appeals specialist with 20 years of experience.",
        messages=[{"role": "user", "content":
            f"Write a formal appeal letter:\nPatient: {row[2]}\nInsurance: {row[6]}\n"
            f"Denial Code: {req.denial_code}\nReason: {denial_info['reason']}\n"
            f"ICD-10: {row[4]}\nCPT: {row[5]}"}]
    )
    appeal = response.content[0].text
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE claims SET claim_status=?, denial_reason=?, appeal_letter=?, date_updated=? WHERE id=?',
                   ("DENIED - APPEAL IN PROGRESS", denial_info["reason"], appeal,
                    datetime.now().strftime("%Y-%m-%d %H:%M"), req.claim_id))
    conn.commit()
    conn.close()
    return {"denial_info": denial_info, "appeal_letter": appeal}

@app.get("/stats")
def get_stats(user=Depends(verify_token)):
    pid = user["practice_id"]
    conn = sqlite3.connect('claims.db')
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


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
