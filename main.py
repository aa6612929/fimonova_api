# main.py
import os, time, hmac, hashlib, json, re
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr
import databases
import sqlalchemy
from dotenv import load_dotenv  
load_dotenv()

# ==========================
# CONFIG
# ==========================
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://...")

API_KEY      = os.getenv("API_KEY", "your_api_key_here")
HMAC_SECRET  = os.getenv("HMAC_SECRET", "your_hmac_secret_here")

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# جدول الطلاب بالشهادات
students = sqlalchemy.Table(
    "students", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("firstname", sqlalchemy.Text),
    sqlalchemy.Column("lastname", sqlalchemy.Text),
    sqlalchemy.Column("birthdate", sqlalchemy.Text),
    sqlalchemy.Column("gender", sqlalchemy.Text),
    sqlalchemy.Column("cert_name", sqlalchemy.Text),
    sqlalchemy.Column("cert_serial_sn", sqlalchemy.Text),
    sqlalchemy.Column("cert_random_code", sqlalchemy.Text)
)

app = FastAPI(title="Fimonova Remote API")

# ==========================
# CORS — فقط للفرونت إند
# ==========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://aa6612929.github.io",
        "https://aa6612929.github.io/checkZertifikate",
        "https://www.fimonova-kosmetik.de",
        "https://fimonova-kosmetik.de",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# MODELS
# ==========================
class SearchPayload(BaseModel):
    firstname: str
    lastname: str
    birthdate: str

class StudentPayload(BaseModel):
    firstname: str
    lastname: str
    birthdate: str
    gender: str
    cert_name: str
    cert_serial_sn: str
    cert_random_code: str

class VerifyPublicPayload(BaseModel): 
    serial_number: constr(strip_whitespace=True, min_length=3, max_length=50)
    random_code:   constr(strip_whitespace=True, min_length=3, max_length=50)

# ==========================
# HMAC / Signing (للنظام الأساسي)
# ==========================
def canonical_json(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

def verify_request_signature(body_obj, x_signature: str, x_timestamp: str, authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Authorization")
    token = authorization.split(" ", 1)[1]
    if token != API_KEY:
        raise HTTPException(401, "Invalid API Key")

    try:
        ts = int(x_timestamp)
    except:
        raise HTTPException(400, "Invalid timestamp")
    if abs(int(time.time()) - ts) > 300:
        raise HTTPException(400, "Timestamp out of range")

    message = f"{x_timestamp}.{canonical_json(body_obj)}"
    expected = hmac.new(HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "Invalid signature")

# ==========================
# DB HELPERS
# ==========================
async def upsert_student(payload: dict):
    row = await database.fetch_one(
        """
        SELECT id FROM students
         WHERE firstname      = :firstname
           AND lastname       = :lastname
           AND birthdate      = :birthdate
           AND cert_name      = :cert_name
           AND cert_serial_sn = :cert_serial_sn
        """,
        values=payload,
    )
    if row:
        await database.execute(
            """
            UPDATE students
               SET gender = :gender,
                   cert_random_code = :cert_random_code
             WHERE id = :id
            """,
            values={
                "id": row["id"],
                "gender": payload["gender"],
                "cert_random_code": payload["cert_random_code"],
            },
        )
        return {"status": "updated", "student_id": row["id"]}

    student_id = await database.execute(
        """
        INSERT INTO students
            (firstname, lastname, birthdate, gender, cert_name, cert_serial_sn, cert_random_code)
        VALUES
            (:firstname, :lastname, :birthdate, :gender, :cert_name, :cert_serial_sn, :cert_random_code)
        RETURNING id
        """,
        values=payload,
    )

    return {"status": "inserted", "student_id": student_id}

# ==========================
# RATE LIMIT FOR PUBLIC ENDPOINT
# ==========================
REQUESTS_WINDOW_SECONDS = 60
REQUESTS_MAX_PER_IP     = 40

rate_limiter = {}  
def rate_limit(ip: str):
    now = time.time()
    bucket = rate_limiter.get(ip)
    if not bucket:
        rate_limiter[ip] = {"start": now, "count": 1}
        return
    if now - bucket["start"] > REQUESTS_WINDOW_SECONDS:
        rate_limiter[ip] = {"start": now, "count": 1}
        return
    if bucket["count"] >= REQUESTS_MAX_PER_IP:
        raise HTTPException(429, "Zu viele Anfragen. Bitte später versuchen.")
    bucket["count"] += 1

# ==========================
# STARTUP / SHUTDOWN
# ==========================
@app.on_event("startup")
async def startup():
    await database.connect()
    engine = sqlalchemy.create_engine(DATABASE_URL)
    metadata.create_all(engine)

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# ==========================
# EXISTING ENDPOINTS (لا تعديل)
# ==========================
@app.post("/add")
async def add_student(payload: StudentPayload, request: Request,
                      x_signature: str = Header(None),
                      x_timestamp: str = Header(None),
                      authorization: str = Header(None)):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    res = await upsert_student(body)
    return {"result": "added", **res}

@app.post("/update")
async def update_student(payload: StudentPayload, request: Request,
                      x_signature: str = Header(None),
                      x_timestamp: str = Header(None),
                      authorization: str = Header(None)):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    res = await upsert_student(body)
    return {"result": "updated", **res}

@app.post("/delete")
async def delete_student(payload: StudentPayload, request: Request,
                      x_signature: str = Header(None),
                      x_timestamp: str = Header(None),
                      authorization: str = Header(None)):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    await database.execute(
        """
        DELETE FROM students
         WHERE firstname = :firstname
           AND lastname  = :lastname
           AND birthdate = :birthdate
        """,
        values=body,
    )
    return {"result": "deleted"}

@app.post("/search")
async def search_student(payload: SearchPayload, request: Request,
                      x_signature: str = Header(None),
                      x_timestamp: str = Header(None),
                      authorization: str = Header(None)):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)

    row = await database.fetch_one(
        """
        SELECT * FROM students
         WHERE firstname = :firstname
           AND lastname  = :lastname
           AND birthdate = :birthdate
        """,
        values=body,
    )
    if not row:
        return {"found": False}
    return {"found": True, "student": dict(row)}

@app.get("/verify")
async def verify_page(firstname: str, lastname: str, birthdate: str,
                      x_abi_key: str = Header(None),
                      x_signature: str = Header(None),
                      x_timestamp: str = Header(None)):
    if x_abi_key != API_KEY:
        raise HTTPException(401, "Unauthorized")
    body = {"firstname": firstname, "lastname": lastname, "birthdate": birthdate}
    verify_request_signature(body, x_signature, x_timestamp, f"Bearer {API_KEY}")
    row = await database.fetch_one(
        """
        SELECT * FROM students
         WHERE firstname = :firstname
           AND lastname  = :lastname
           AND birthdate = :birthdate
        """,
        values=body,
    )
    if not row:
        return {"found": False}
    return {"found": True, "student": dict(row)}

# ==========================
# PUBLIC ENDPOINT FOR WEBSITE
# ==========================
@app.post("/verify_public")
async def verify_public(request: Request, payload: VerifyPublicPayload):
    client_ip = request.client.host
    rate_limit(client_ip)

    serial  = payload.serial_number
    random  = payload.random_code

    # Regex حماية
    allowed = re.compile(r"^[A-Za-z0-9\-]+$")
    if not allowed.fullmatch(serial) or not allowed.fullmatch(random):
        raise HTTPException(400, "Ungültige Eingabe.")

    row = await database.fetch_one(
        """
        SELECT firstname, lastname, cert_name, birthdate
        FROM students
        WHERE cert_serial_sn = :sn
          AND cert_random_code = :rc
        """,
        values={"sn": serial, "rc": random},
    )

    if not row:
        return {"found": False}

    return {
        "found": True,
        "student": {
            "firstname": row["firstname"],
            "lastname": row["lastname"],
            "cert_name": row["cert_name"],
            "birthdate": row["birthdate"],
        },
    }

# ==========================
# WAKE ENDPOINT
# ==========================
@app.get("/wake")
async def wake():
    return {"status": "awake"}

@app.get("/")
async def root():
    return {"status": "ok", "service": "fimonova_api"}
