import anthropic
import os
import json
import re
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


# -----------------------------------------
# DATABASE SETUP
# -----------------------------------------
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
    print("Database ready!")


# -----------------------------------------
# MODULE 1 - AI Medical Code Extractor
# -----------------------------------------
def extract_medical_codes(clinical_note):
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1000,
        system="You are a certified medical coder (CPC). Extract ICD-10 diagnosis codes and CPT procedure codes from clinical notes. Return JSON only. No extra text. Format: {\"icd10\": [\"E11.9\", \"I10\"], \"cpt\": [\"99213\", \"93000\"]} Follow official CMS coding guidelines strictly.",
        messages=[
            {
                "role": "user",
                "content": "Extract codes from this note:\n\n" + clinical_note
            }
        ]
    )
    text = response.content[0].text
    try:
        match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if match:
            result = json.loads(match.group())
            return result
        else:
            return {"icd10": [], "cpt": []}
    except json.JSONDecodeError:
        icd10 = re.findall(r'[A-Z]\d{2}\.?\d*', text)
        cpt = re.findall(r'\b\d{5}\b', text)
        return {"icd10": icd10, "cpt": cpt}


# -----------------------------------------
# MODULE 2 - Prior Auth Decision Engine
# -----------------------------------------
PRIOR_AUTH_MATRIX = {
    "UnitedHealthcare": {
        "99213": False,
        "99214": False,
        "70553": True,
        "27447": True,
        "83036": False,
        "93000": False,
        "29827": True,
        "73721": True
    },
    "Aetna": {
        "99213": False,
        "99214": False,
        "70553": True,
        "27447": True,
        "83036": False,
        "93000": False,
        "29827": True,
        "73721": True
    },
    "BlueCross": {
        "99213": False,
        "99214": False,
        "70553": True,
        "27447": True,
        "83036": False,
        "93000": False,
        "29827": True,
        "73721": True
    },
    "Cigna": {
        "99213": False,
        "99214": False,
        "70553": True,
        "27447": True,
        "83036": False,
        "93000": False,
        "29827": True,
        "73721": True
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


# -----------------------------------------
# MODULE 3 - Claim Submission and Tracking
# -----------------------------------------
def submit_claim(patient_name, date_of_service, icd10_codes, cpt_codes, payer, auth_results):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()

    codes_needing_auth = [r["cpt_code"] for r in auth_results if r["requires_prior_auth"]]
    prior_auth_required = "YES" if codes_needing_auth else "NO"
    prior_auth_status = "PENDING" if codes_needing_auth else "NOT REQUIRED"

    cursor.execute('''
        INSERT INTO claims (
            patient_name, date_of_service, icd10_codes,
            cpt_codes, payer, prior_auth_required,
            prior_auth_status, claim_status,
            date_submitted, date_updated, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        patient_name,
        date_of_service,
        json.dumps(icd10_codes),
        json.dumps(cpt_codes),
        payer,
        prior_auth_required,
        prior_auth_status,
        "SUBMITTED",
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        "Codes requiring auth: " + str(codes_needing_auth) if codes_needing_auth else "No auth required"
    ))

    claim_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return claim_id


def view_all_claims():
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM claims')
    claims = cursor.fetchall()
    conn.close()

    if not claims:
        print("No claims found in database.")
        return

    print("\n" + "=" * 60)
    print("ALL CLAIMS DASHBOARD")
    print("=" * 60)

    for claim in claims:
        print("Claim ID:        #" + str(claim[0]))
        print("Patient:         " + str(claim[1]))
        print("Date of Service: " + str(claim[2]))
        print("Payer:           " + str(claim[5]))
        print("Prior Auth:      " + str(claim[6]) + " (" + str(claim[7]) + ")")
        print("Claim Status:    " + str(claim[8]))
        print("ICD-10 Codes:    " + str(claim[3]))
        print("CPT Codes:       " + str(claim[4]))
        print("Notes:           " + str(claim[11]))
        print("Denial Reason:   " + str(claim[12]))
        print("Submitted:       " + str(claim[9]))
        print("-" * 60)


def update_claim_status(claim_id, new_status, notes=""):
    conn = sqlite3.connect('claims.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE claims
        SET claim_status = ?, date_updated = ?, notes = ?
        WHERE id = ?
    ''', (
        new_status,
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        notes,
        claim_id
    ))
    conn.commit()
    conn.close()
    print("Claim #" + str(claim_id) + " updated to: " + new_status)


# -----------------------------------------
# MODULE 4 - Denial Detection and Appeals AI
# -----------------------------------------
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

    return {
        "denial_code": denial_code,
        "reason": reason,
        "category": category,
        "recommended_action": action
    }


def generate_appeal_letter(patient_name, payer, denial_code,
                           icd10_codes, cpt_codes, clinical_note):
    denial_info = categorize_denial(denial_code)

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1500,
        system="You are an expert medical billing appeals specialist with 20 years of experience. Write professional, persuasive appeal letters that successfully overturn insurance denials. Always cite medical necessity and relevant clinical documentation.",
        messages=[
            {
                "role": "user",
                "content": "Write a formal appeal letter for this denied claim:\n\n" +
                           "Patient: " + patient_name + "\n" +
                           "Insurance: " + payer + "\n" +
                           "Denial Code: " + denial_code + "\n" +
                           "Denial Reason: " + denial_info["reason"] + "\n" +
                           "ICD-10 Codes: " + str(icd10_codes) + "\n" +
                           "CPT Codes: " + str(cpt_codes) + "\n" +
                           "Clinical Notes: " + clinical_note + "\n\n" +
                           "Write a complete, professional appeal letter."
            }
        ]
    )
    return response.content[0].text


def process_denial(claim_id, denial_code, patient_name, payer,
                   icd10_codes, cpt_codes, clinical_note):
    print("\nAnalyzing denial reason...")
    denial_info = categorize_denial(denial_code)

    print("Denial Code:     " + denial_info["denial_code"])
    print("Reason:          " + denial_info["reason"])
    print("Category:        " + denial_info["category"])
    print("Action Required: " + denial_info["recommended_action"])

    print("\nGenerating appeal letter with AI...")
    appeal_letter = generate_appeal_letter(
        patient_name=patient_name,
        payer=payer,
        denial_code=denial_code,
        icd10_codes=icd10_codes,
        cpt_codes=cpt_codes,
        clinical_note=clinical_note
    )

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
        claim_id
    ))
    conn.commit()
    conn.close()

    return appeal_letter


# -----------------------------------------
# RUN ALL 4 MODULES TOGETHER
# -----------------------------------------
sample_note = """
Patient: John Doe, 58-year-old male
Insurance: Cigna
Date of Service: 2026-03-06
Chief Complaint: Follow-up for Type 2 Diabetes and hypertension.
Knee pain requiring MRI evaluation.

Assessment:
- Type 2 Diabetes Mellitus, uncontrolled
- Essential hypertension
- Ordered HbA1c lab work
- MRI of knee ordered to evaluate joint damage
- 15-minute office visit with established patient
"""

setup_database()

print("\n" + "=" * 50)
print("STEP 1 - EXTRACTING MEDICAL CODES...")
print("=" * 50)
codes = extract_medical_codes(sample_note)
print("ICD-10 Codes: " + str(codes["icd10"]))
print("CPT Codes:    " + str(codes["cpt"]))

print("\n" + "=" * 50)
print("STEP 2 - CHECKING PRIOR AUTHORIZATION...")
print("=" * 50)
auth_results = check_prior_auth(codes["cpt"], "Cigna")
for result in auth_results:
    print("CPT " + result["cpt_code"] + " -> " + result["status"])

print("\n" + "=" * 50)
print("STEP 3 - SUBMITTING AND TRACKING CLAIM...")
print("=" * 50)
claim_id = submit_claim(
    patient_name="John Doe",
    date_of_service="2026-03-06",
    icd10_codes=codes["icd10"],
    cpt_codes=codes["cpt"],
    payer="Cigna",
    auth_results=auth_results
)
print("Claim submitted! Claim ID: #" + str(claim_id))

print("\n" + "=" * 50)
print("STEP 4 - SIMULATING CLAIM DENIAL AND APPEAL...")
print("=" * 50)
appeal_letter = process_denial(
    claim_id=claim_id,
    denial_code="PR-96",
    patient_name="John Doe",
    payer="Cigna",
    icd10_codes=codes["icd10"],
    cpt_codes=codes["cpt"],
    clinical_note=sample_note
)

print("\n" + "=" * 50)
print("APPEAL LETTER GENERATED:")
print("=" * 50)
print(appeal_letter)

view_all_claims()