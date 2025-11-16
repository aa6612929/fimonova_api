"""
api_server_minimal.py

- FastAPI server minimal.
- يفترض وجود:
    - database.py  (يحتوي SessionLocal, engine, Base)
    - models.py    (يحتوي class Certificate(Base) معرفًا مسبقًا)
- حماية /add و /update: API Key + HMAC-SHA256 + X-Timestamp (لمنع replay).
- public endpoint: /gate (للتحقق من serial+random).
"""

import os
import time
import json
import hmac
import hashlib
from typing import Dict, Optional

from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session
from sqlalchemy import and_, select

from database import SessionLocal, engine
from models import Certificate

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import pathlib


# =======================================================
# 🔥 حماية /gate — Rate Limit + Block + Bot Protection + Logs
# =======================================================

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# attempt counters
FAILED_ATTEMPTS = {}
BLOCKED_IPS = {}

BLOCK_TIME = 600        # 10 دقائق
MAX_ATTEMPTS = 10        # بعد 10 محاولات block

# log file
os.makedirs("logs", exist_ok=True)
LOG_FILE = "logs/gate_attempts.log"

def log_attempt(ip, serial, random, status):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(
            f"{time.ctime()} | IP={ip} | serial={serial} | random={random} | status={status}\n"
        )

limiter = Limiter(key_func=get_remote_address)

# =======================================================


# --- إعدادات البيئة ---
API_KEY = os.getenv("FIMONOVA_API_KEY", "CHANGE_THIS_TO_A_SECRET")
HMAC_SECRET = os.getenv("FIMONOVA_HMAC_SECRET", "CHANGE_THIS_TOO")
TIMESTAMP_WINDOW = int(os.getenv("TIMESTAMP_WINDOW", "300"))


app = FastAPI(title="Fimonova Minimal API", version="0.1")
app.state.limiter = limiter


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# static folder
static_path = pathlib.Path(__file__).parent / "static"
static_path.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")



# =======================
#   Pydantic Models
# =======================
class CertInfo(BaseModel):
    serial_number: str = Field(..., min_length=1)
    random_code: str = Field(..., min_length=1)

class CertificatePayload(BaseModel):
    firstname: str = Field(..., min_length=1)
    lastname: str = Field(..., min_length=1)
    birthdate: str = Field(..., min_length=6)
    certificates: Dict[str, CertInfo]

    @validator("certificates")
    def non_empty_certificates(cls, v):
        if not v or len(v) == 0:
            raise ValueError("certificates must be a non-empty dict")
        return v



# =======================
# Helper Functions
# =======================
def canonical_json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

def verify_api_key(auth_header: Optional[str]):
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Missing or bad Authorization header")
    token = auth_header.split(" ", 1)[1].strip()
    if token != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True

def verify_hmac_and_timestamp(request_body: dict, x_timestamp: Optional[str], x_signature: Optional[str]):
    if x_timestamp is None or x_signature is None:
        raise HTTPException(status_code=400, detail="Missing X-Timestamp or X-Signature headers")

    try:
        ts = int(x_timestamp)
    except:
        raise HTTPException(status_code=400, detail="Bad X-Timestamp format")

    now = int(time.time())
    if abs(now - ts) > TIMESTAMP_WINDOW:
        raise HTTPException(status_code=408, detail="Timestamp outside acceptable window")

    message = f"{ts}.{canonical_json(request_body)}"
    computed = hmac.new(HMAC_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed, x_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")



# DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# =======================
# Middleware
# =======================
@app.middleware("http")
async def read_body_middleware(request: Request, call_next):
    try:
        raw = await request.body()
        if raw:
            try:
                request.state.json_body = json.loads(raw.decode())
            except:
                request.state.json_body = {}
        else:
            request.state.json_body = {}
    except:
        request.state.json_body = {}

    return await call_next(request)



# =======================
# Exception for RateLimit
# =======================
@app.exception_handler(RateLimitExceeded)
def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Limit überschritten — bitte versuchen Sie es in einer Minute erneut"
        }
    )




# =======================
# /add  (محمي)
# =======================
@app.post("/add")
def api_add(payload: CertificatePayload, request: Request,
            authorization: Optional[str] = Header(None),
            x_timestamp: Optional[str] = Header(None),
            x_signature: Optional[str] = Header(None),
            db: Session = Depends(get_db)):

    verify_api_key(authorization)
    verify_hmac_and_timestamp(request.state.json_body, x_timestamp, x_signature)

    added, skipped = 0, 0

    for cert_name, info in payload.certificates.items():
        stmt = select(Certificate).where(Certificate.serial_number == info.serial_number)
        existing = db.execute(stmt).scalars().first()

        if existing:
            skipped += 1
            continue

        cert = Certificate(
            firstname=payload.firstname.strip(),
            lastname=payload.lastname.strip(),
            birthdate=payload.birthdate.strip(),
            certificate_name=cert_name,
            serial_number=info.serial_number,
            random_code=info.random_code
        )
        db.add(cert)
        added += 1

    db.commit()
    return {"status": "added", "cert_added": added, "cert_skipped": skipped}



# =======================
# /update  (محمي)
# =======================
@app.post("/update")
def api_update(payload: CertificatePayload, request: Request,
               authorization: Optional[str] = Header(None),
               x_timestamp: Optional[str] = Header(None),
               x_signature: Optional[str] = Header(None),
               db: Session = Depends(get_db)):

    verify_api_key(authorization)
    verify_hmac_and_timestamp(request.state.json_body, x_timestamp, x_signature)

    processed = 0

    for cert_name, info in payload.certificates.items():

        stmt = select(Certificate).where(
            and_(
                Certificate.firstname == payload.firstname,
                Certificate.lastname == payload.lastname,
                Certificate.birthdate == payload.birthdate,
                Certificate.certificate_name == cert_name,
                Certificate.serial_number == info.serial_number
            )
        )
        existing = db.execute(stmt).scalars().first()

        if existing:
            processed += 1
            continue

        new_cert = Certificate(
            firstname=payload.firstname.strip(),
            lastname=payload.lastname.strip(),
            birthdate=payload.birthdate.strip(),
            certificate_name=cert_name,
            serial_number=info.serial_number,
            random_code=info.random_code
        )
        db.add(new_cert)
        processed += 1

    db.commit()
    return {"status": "updated", "processed": processed}



# =======================================================
#     🔥🔥 Endpoint /gate محمي بالكامل كما طلبت 🔥🔥
# =======================================================
@app.post("/gate")
@limiter.limit("1/minute")     # ← محاولة واحدة فقط كل دقيقة
async def gate_check(request: Request, payload: dict, db: Session = Depends(get_db)):

    ip = get_remote_address(request)
    now = time.time()

    serial = payload.get("serial_number", "").strip()
    random_code = payload.get("random_code", "").strip()

    if not serial or not random_code:
        log_attempt(ip, serial, random_code, "missing_fields")
        raise HTTPException(status_code=400, detail="serial_number and random_code required")

    # 1️⃣ Bot Protection
    ua = request.headers.get("User-Agent", "")
    if ua.strip() == "" or "python" in ua.lower() or "bot" in ua.lower():
        log_attempt(ip, serial, random_code, "blocked_bot")
        raise HTTPException(status_code=403, detail="Bot access blocked")

    # 2️⃣ هل IP محظور؟
    if ip in BLOCKED_IPS and now < BLOCKED_IPS[ip]:
        remaining = int(BLOCKED_IPS[ip] - now)
        log_attempt(ip, serial, random_code, f"blocked_{remaining}s")
        raise HTTPException(status_code=403, detail=f"محظور لمدة {remaining} ثانية")

    # 3️⃣ تسجيل المحاولة — B: كل محاولة تتحسب (نجاح/فشل)
    FAILED_ATTEMPTS[ip] = FAILED_ATTEMPTS.get(ip, 0) + 1
    log_attempt(ip, serial, random_code, "attempt")

    # 4️⃣ بلوك بعد 5 محاولات
    if FAILED_ATTEMPTS[ip] >= MAX_ATTEMPTS:
        BLOCKED_IPS[ip] = now + BLOCK_TIME
        FAILED_ATTEMPTS[ip] = 0
        log_attempt(ip, serial, random_code, "IP_BLOCKED")
        raise HTTPException(status_code=403, detail="تم حظرك لمدة 10 دقائق")

    # 5️⃣ عملية التحقق الأصلية
    stmt = select(Certificate).where(
        and_(
            Certificate.serial_number == serial,
            Certificate.random_code == random_code
        )
    )
    row = db.execute(stmt).scalars().first()

    if not row:
        log_attempt(ip, serial, random_code, "invalid")
        raise HTTPException(status_code=404, detail="Certificate not found or data mismatch")

    # 6️⃣ تم التحقق بنجاح
    log_attempt(ip, serial, random_code, "valid")

    return {
        "status": "valid",
        "student_name": f"{row.firstname} {row.lastname}",
        "birthdate": row.birthdate,
        "certificate": row.certificate_name
    }


# =======================
# /delete  (محمي)
# =======================
@app.post("/delete")
def delete_student(payload: dict,
                   authorization: Optional[str] = Header(None),
                   x_timestamp: Optional[str] = Header(None),
                   x_signature: Optional[str] = Header(None),
                   db: Session = Depends(get_db)):

    verify_api_key(authorization)
    verify_hmac_and_timestamp(payload, x_timestamp, x_signature)

    firstname = payload.get("firstname", "").strip()
    lastname = payload.get("lastname", "").strip()
    birthdate = payload.get("birthdate", "").strip()

    if not firstname or not lastname or not birthdate:
        raise HTTPException(status_code=400, detail="firstname, lastname, and birthdate required")

    stmt = select(Certificate).where(
        and_(
            Certificate.firstname == firstname,
            Certificate.lastname == lastname,
            Certificate.birthdate == birthdate
        )
    )

    rows = db.execute(stmt).scalars().all()
    if not rows:
        raise HTTPException(status_code=404, detail="No records found to delete")

    deleted = 0
    for row in rows:
        db.delete(row)
        deleted += 1

    db.commit()
    return {"status": "deleted", "deleted_count": deleted}



# =======================
# /search_app  (غير محمي)
# =======================
@app.post("/search_app")
def search_app(payload: dict, db: Session = Depends(get_db)):

    firstname = payload.get("firstname", "").strip()
    lastname = payload.get("lastname", "").strip()
    birthdate = payload.get("birthdate", "").strip()

    if not firstname or not lastname or not birthdate:
        raise HTTPException(status_code=400, detail="firstname, lastname, and birthdate required")

    stmt = select(Certificate).where(
        and_(
            Certificate.firstname == firstname,
            Certificate.lastname == lastname,
            Certificate.birthdate == birthdate
        )
    )

    rows = db.execute(stmt).scalars().all()

    if not rows:
        return {"found": False, "detail": "student not found"}

    certificates = [
        {
            "certificate_name": r.certificate_name,
            "serial_number": r.serial_number,
            "random_code": r.random_code
        }
        for r in rows
    ]

    return {
        "found": True,
        "firstname": firstname,
        "lastname": lastname,
        "birthdate": birthdate,
        "certificates": certificates
    }



# =======================
# /health
# =======================
@app.get("/health")
def health():
    return {"status": "ok", "db": str(engine.url)}
