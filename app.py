import anthropic
import os
import json
import re
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def setup_database():
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    conn.commit()
    conn.close()

setup_database()


def extract_medical_codes(clinical_note):
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1000,
        system="You are a certified medical coder (CPC). Extract ICD-10 diagnosis codes and CPT procedure codes from clinical notes. Return JSON only. No extra text. Format: {\"icd10\": [\"E11.9\", \"I10\"], \"cpt\": [\"99213\", \"93000\"]} Follow official CMS coding guidelines strictly.",
        messages=[{"role": "user", "content": "Extract codes from this note:\n\n" + clinical_note}]
    )
    text = response.content[0].text
    try:
        match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
        return {"icd10": [], "cpt": []}
    except json.JSONDecodeError:
        icd10 = re.findall(r'[A-Z]\d{2}\.?\d*', text)
        cpt = re.findall(r'\b\d{5}\b', text)
        return {"icd10": icd10, "cpt": cpt}


PRIOR_AUTH_MATRIX = {
    "UnitedHealthcare": {
        "99213": False, "99214": False, "70553": True,
        "27447": True, "83036": False, "93000": False,
        "29827": True, "73721": True
    },
    "Aetna": {
        "99213": False, "99214": False, "70553": True,
        "27447": True, "83036": False, "93000": False,
        "29827": True, "73721": True
    },
    "BlueCross": {
        "99213": False, "99214": False, "70553": True,
        "27447": True, "83036": False, "93000": False,
        "29827": True, "73721": True
    },
    "Cigna": {
        "99213": False, "99214": False, "70553": True,
        "27447": True, "83036": False, "93000": False,
        "29827": True, "73721": True
    }
}


def check_prior_auth(cpt_codes, payer):
    results = []
    payer_rules = PRIOR_AUTH_MATRIX.get(payer, {})
    for code in cpt_codes:
        requires_auth = payer_rules.get(code, False)
        results.append({
            "cpt_code": code,
            "payer": payer,
            "requires_prior_auth": requires_auth,
            "status": "AUTH REQUIRED" if requires_auth else "NO AUTH NEEDED"
        })
    return results


DENIAL_REASONS = {
    "CO-4":  "Procedure code inconsistent with modifier",
    "CO-11": "Diagnosis inconsistent with procedure",
    "CO-22": "Coordination of benefits issue",
    "CO-29": "Claim submitted past timely filing limit",
    "CO-50": "Non-covered service",
    "CO-97": "Service already adjudicated",
    "PR-1":  "Deductible not met",
    "PR-2":  "Coinsurance amount",
    "PR-96": "Prior authorization not obtained",
    "OA-23": "Payment adjusted due to prior authorization"
}


def categorize_denial(denial_code):
    reason = DENIAL_REASONS.get(denial_code, "Unknown denial reason")
    if denial_code in ["PR-96", "OA-23"]:
        category = "PRIOR AUTH ISSUE"
        action = "Submit prior authorization request immediately"
    elif denial_code in ["CO-4", "CO-11"]:
        category = "CODING ERROR"
        action = "Review and correct procedure or diagnosis codes"
    elif denial_code in ["CO-29"]:
        category = "TIMELY FILING"
        action = "Submit proof of timely filing with appeal"
    elif denial_code in ["PR-1", "PR-2"]:
        category = "PATIENT RESPONSIBILITY"
        action = "Bill patient for deductible or coinsurance"
    elif denial_code in ["CO-50"]:
        category = "NON-COVERED SERVICE"
        action = "Appeal with medical necessity documentation"
    else:
        category = "OTHER"
        action = "Review denial and appeal with supporting documents"
    return {"denial_code": denial_code, "reason": reason, "category": category, "recommended_action": action}


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
def root():
    return {"message": "Medical Billing AI API is running!"}


@app.post("/process-claim")
def process_claim(request: ProcessClaimRequest):
    codes = extract_medical_codes(request.clinical_note)
    auth_results = check_prior_auth(codes["cpt"], request.payer)
    codes_needing_auth = [r["cpt_code"] for r in auth_results if r["requires_prior_auth"]]
    prior_auth_required = "YES" if codes_needing_auth else "NO"
    prior_auth_status = "PENDING" if codes_needing_auth else "NOT REQUIRED"

    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO claims (
            patient_name, date_of_service, icd10_codes,
            cpt_codes, payer, prior_auth_required,
            prior_auth_status, claim_status,
            date_submitted, date_updated, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        request.patient_name, request.date_of_service,
        json.dumps(codes["icd10"]), json.dumps(codes["cpt"]),
        request.payer, prior_auth_required, prior_auth_status,
        "SUBMITTED",
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        "Codes requiring auth: " + str(codes_needing_auth) if codes_needing_auth else "No auth required"
    ))
    claim_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "claim_id": claim_id,
        "icd10_codes": codes["icd10"],
        "cpt_codes": codes["cpt"],
        "auth_results": auth_results,
        "prior_auth_required": prior_auth_required,
        "status": "SUBMITTED"
    }


@app.get("/claims")
def get_all_claims():
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()

    claims = []
    for row in rows:
        claims.append({
            "id": row[0],
            "patient_name": row[1],
            "date_of_service": row[2],
            "icd10_codes": json.loads(row[3]) if row[3] else [],
            "cpt_codes": json.loads(row[4]) if row[4] else [],
            "payer": row[5],
            "prior_auth_required": row[6],
            "prior_auth_status": row[7],
            "claim_status": row[8],
            "date_submitted": row[9],
            "date_updated": row[10],
            "notes": row[11],
            "denial_reason": row[12],
            "appeal_letter": row[13]
        })
    return claims


@app.post("/process-denial")
def process_denial(request: DenialRequest):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims WHERE id = ?', (request.claim_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Claim not found")

    patient_name = row[1]
    payer = row[5]
    icd10_codes = json.loads(row[3]) if row[3] else []
    cpt_codes = json.loads(row[4]) if row[4] else []

    denial_info = categorize_denial(request.denial_code)

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1500,
        system="You are an expert medical billing appeals specialist with 20 years of experience. Write professional, persuasive appeal letters that successfully overturn insurance denials.",
        messages=[{
            "role": "user",
            "content": "Write a formal appeal letter for:\nPatient: " + patient_name +
                       "\nInsurance: " + payer +
                       "\nDenial Code: " + request.denial_code +
                       "\nDenial Reason: " + denial_info["reason"] +
                       "\nICD-10 Codes: " + str(icd10_codes) +
                       "\nCPT Codes: " + str(cpt_codes)
        }]
    )
    appeal_letter = response.content[0].text

    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE claims
        SET claim_status = ?, denial_reason = ?, appeal_letter = ?, date_updated = ?
        WHERE id = ?
    ''', (
        "DENIED - APPEAL IN PROGRESS",
        denial_info["reason"],
        appeal_letter,
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        request.claim_id
    ))
    conn.commit()
    conn.close()

    return {"denial_info": denial_info, "appeal_letter": appeal_letter}


@app.post("/update-status")
def update_status(request: UpdateStatusRequest):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE claims SET claim_status = ?, date_updated = ?, notes = ?
        WHERE id = ?
    ''', (
        request.new_status,
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        request.notes,
        request.claim_id
    ))
    conn.commit()
    conn.close()
    return {"message": "Claim #" + str(request.claim_id) + " updated to " + request.new_status}


@app.get("/stats")
def get_stats():
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM claims')
    total = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE claim_status = "SUBMITTED"')
    submitted = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE claim_status = "APPROVED"')
    approved = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE claim_status LIKE "DENIED%"')
    denied = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM claims WHERE prior_auth_required = "YES"')
    auth_required = cursor.fetchone()[0]
    conn.close()
    return {
        "total": total,
        "submitted": submitted,
        "approved": approved,
        "denied": denied,
        "auth_required": auth_required
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
