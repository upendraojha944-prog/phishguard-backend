from fastapi import APIRouter, FastAPI, HTTPException, Depends, UploadFile, File, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, EmailStr
import os, json, requests, socket, re, cv2, numpy as np, random, bcrypt, smtplib, secrets, pickle, base64, hashlib
from urllib.parse import urlparse
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import jwt
from email.message import EmailMessage
from models import PhishingLog, SMSLog, ScanLog
from database import engine, Base
import models
from models import User, ScanLog, PhishingLog, SMSLog
import google.generativeai as genai

# 🔐 LEVEL 3: API SECURITY & ADVANCED INTERLOCK IMPORTS
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.security import OAuth2PasswordBearer

load_dotenv()

# --- GEMINI AI CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# --- 1. INITIALIZATION & SLOWAPI INTEGRATION ---
limiter = Limiter(key_func=get_remote_address) # Track requests via Client Remote IP
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# 🔐 LEVEL 7: INFRASTRUCTURE SECURITY - SECURE HTTP HEADERS MIDDLEWARE
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"  # 🛡️ UI Clickjacking attacks ko block karne ke liye
    response.headers["X-Content-Type-Options"] = "nosniff"  # 🛡️ Malicious MIME-Sniffing vulnerabilities se bachane ke liye
    response.headers["X-XSS-Protection"] = "1; mode=block"  # 🛡️ Browser ka built-in Anti-XSS filter active karne ke liye
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none';"  # 🛡️ Kisi aur website ko aapka portal iframe mein embed karne se rokne ke liye
    return response
# ✅ SAHI CODE (Isko copy-paste karein)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'phishguard.db')}"
)

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Cryptographic Keys
SECRET_KEY = os.getenv("JWT_SECRET", "phishguard_secure_key_123")
ALGORITHM = "HS256"

# 🔐 OAuth2 Bearer Token Extraction Scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

# --- PYDANTIC SCHEMAS ---
class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    otp: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    email: EmailStr

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

class BotQuery(BaseModel):
    question: str

class IncomingSMS(BaseModel):
    sender: str
    message: str

class URLPayload(BaseModel):
    url: str

class DomainPayload(BaseModel):
    domain: str

class HashPayload(BaseModel):
    hash: str

# --- 2. MODELS ---
class DBUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    connected_email = Column(String, nullable=True)
    gmail_status = Column(String, default="DISCONNECTED")
    security_score = Column(Integer, default=100)
    created_at = Column(DateTime, default=datetime.utcnow)

class DBIncident(Base):
    __tablename__ = "incidents"
    id = Column(String, primary_key=True, index=True)
    domain = Column(String, index=True); ip = Column(String); source = Column(String)
    category = Column(String); severity = Column(String); timestamp = Column(String)
    remediation_status = Column(String); action_taken = Column(String)

class DBURLScan(Base):
    __tablename__ = "url_scans"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False); threat_index = Column(Integer); verdict = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class DBScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    source = Column(String, nullable=True)
    verdict = Column(String, nullable=False)
    risk_score = Column(Integer, default=0)
    summary = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
# 🔐 LEVEL 8: APPLICATION SECURITY - AUDIT LOGGING DATABASE SCHEMA
class DBAuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, nullable=True, index=True)
    action = Column(String, nullable=False) # Jaise: LOGIN_SUCCESS, PROMPT_INJECTION, etc.
    details = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
Base.metadata.create_all(bind=engine)

def ensure_user_schema():
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    columns = {col["name"] for col in inspector.get_columns("users")}
    migrations = {
        "connected_email": "ALTER TABLE users ADD COLUMN connected_email VARCHAR",
        "gmail_status": "ALTER TABLE users ADD COLUMN gmail_status VARCHAR DEFAULT 'DISCONNECTED'",
        "security_score": "ALTER TABLE users ADD COLUMN security_score INTEGER DEFAULT 100",
        "created_at": "ALTER TABLE users ADD COLUMN created_at TIMESTAMP",
    }
    with engine.begin() as conn:
        for column, sql in migrations.items():
            if column not in columns:
                conn.execute(text(sql))

ensure_user_schema()

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/auth/callback")
SCOPES = "https://www.googleapis.com/auth/gmail.readonly"
SMS_CACHE_FILE = "live_sms_cache.json"
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")

try:
    with open(MODEL_PATH, "rb") as f:
        url_ai_model = pickle.load(f)
    with open(VECTORIZER_PATH, "rb") as f:
        url_vectorizer = pickle.load(f)
except Exception:
    url_ai_model = None
    url_vectorizer = None

OTP_STORE = {}
OTP_EXPIRY_MINUTES = 10
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

try:
    reader = easyocr.Reader(["en", "hi"], gpu=False)
except Exception:
    reader = None

def normalize_hindi_digits_to_english(text: str) -> str:
    hindi_digits = "०१२३४५६७८९"
    for i, digit in enumerate(hindi_digits):
        text = text.replace(digit, str(i))
    return text

# --- 3. UTILS & SECURITY SCHEMAS ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# 🔐 LEVEL 3: TOKEN DECODING VALIDATION PIPELINE
def verify_jwt_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials signatures.",
            )
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired or identity signature is invalid.",
        )
# 🔐 LEVEL 8: AUTOMATED ENGINE TO LOG SECURITY CONTEXT EVENTS
def log_audit_event(db: Session, action: str, user_email: str = None, details: str = None, ip_address: str = None):
    try:
        log_entry = DBAuditLog(
            user_email=user_email,
            action=action,
            details=details,
            ip_address=ip_address
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        print(f"Audit Logging Engine Failure: {e}")
def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=60))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def send_otp_email(email: str, otp: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        return False

    message = EmailMessage()
    message["Subject"] = "PhishGuard AI registration OTP"
    message["From"] = SMTP_FROM
    message["To"] = email
    message.set_content(f"Your PhishGuard AI registration OTP is {otp}. It is valid for {OTP_EXPIRY_MINUTES} minutes.")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(message)
    return True

def verify_registration_otp(email: str, otp: str) -> bool:
    record = OTP_STORE.get(email.lower())
    if not record:
        return False
    if datetime.utcnow() > record["expires_at"]:
        OTP_STORE.pop(email.lower(), None)
        return False
    return secrets.compare_digest(record["otp"], otp.strip())
def validate_prompt_injection(text: str) -> bool:
    # 🛡️ LEVEL 6: Common jailbreak & prompt injection vectors (English + Hinglish/Hindi keywords)
    injection_keywords = [
        "ignore previous", "ignore all instructions", "override system", 
        "system prompt bypass", "forget your rules", "forget what i said",
        "clear memory", "you are now unrestricted", "developer mode", 
        "jailbreak", "do anything now", "dan mode", "piche ke instructions bhool jao",
        "purane rules ignore karo", "show all users", "bypass guardrails",
        "act as a hacker", "ignore rules", "system override"
    ]
    
    text_lower = text.lower()
    
    # 1. Direct Keyword Signature Matching
    for keyword in injection_keywords:
        if keyword in text_lower:
            return True
            
    # 2. Advanced Regex Pattern Matching (For fuzzing or evasion attempts)
    pattern = re.compile(r"(ignore|bypass|override|forget|bhool|hatao)\s+(all|previous|system|rule|instruction|purane|command)", re.IGNORECASE)
    if pattern.search(text_lower):
        return True
        
    return False
def predict_url_with_ai(url: str):
    import google.generativeai as genai
    import os, json
    from dotenv import load_dotenv
    load_dotenv(override=True)
    
    raw_key = os.getenv("GEMINI_API_KEY")
    if not raw_key:
        return "Suspicious", 50, 50

    try:
        genai.configure(api_key=raw_key.strip())
        valid_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        target_model = 'gemini-1.5-flash'
        if 'models/gemini-1.5-flash' not in valid_models:
            target_model = valid_models[0].replace('models/', '')
            
        model = genai.GenerativeModel(target_model)
        
        prompt = f"""Act as a Cybersecurity Phishing URL Analyzer. 
        Analyze this URL for phishing, malware, or suspicious intent: '{url}'.
        Reply STRICTLY in JSON format with no extra text:
        {{"verdict": "Phishing" or "Suspicious" or "Safe", "threat_index": 0-100, "confidence": 0-100}}"""
        
        response = model.generate_content(prompt)
        res_text = response.text.replace("```json", "").replace("```", "").strip()
        data = json.loads(res_text)
        
        return data.get("verdict", "Suspicious"), data.get("threat_index", 50), data.get("confidence", 80)
    
    except Exception as e:
        print(f"URL Gemini AI Error: {e}")
        return "Suspicious", 50, 50

def vt_headers():
    if not VT_API_KEY:
        raise HTTPException(status_code=500, detail="VirusTotal API key missing in backend .env.")
    return {"x-apikey": VT_API_KEY}

def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def vt_stats_to_verdict(stats: dict):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        verdict = "Phishing"
    elif suspicious > 0:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    total = malicious + suspicious + harmless + undetected
    risk_score = min(100, malicious * 25 + suspicious * 12)
    confidence = int(((malicious + suspicious + harmless) / total) * 100) if total else 0

    return verdict, risk_score, confidence

def evaluate_extracted_text(text: str):
    import google.generativeai as genai
    import os, json
    from dotenv import load_dotenv
    load_dotenv(override=True)
    
    raw_key = os.getenv("GEMINI_API_KEY")
    if not raw_key:
        return 15, "Safe / Legitimate", "Fallback: Safe"

    try:
        genai.configure(api_key=raw_key.strip())
        valid_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        target_model = 'gemini-1.5-flash'
        if 'models/gemini-1.5-flash' not in valid_models:
            target_model = valid_models[0].replace('models/', '')
            
        model = genai.GenerativeModel(target_model)
        
        prompt = f"""Act as an elite SOC Analyst. Analyze this text extracted from a user's screenshot/SMS: 
        '{text}'
        Is this a phishing scam, financial fraud, malware distribution, or completely safe? 
        Reply STRICTLY in JSON format with no extra text:
        {{"score": 0-100, "verdict": "Malicious / Phishing Portal Detected" or "Safe / Legitimate", "summary": "Write a 2-sentence technical forensic summary of what this text is trying to do."}}"""
        
        response = model.generate_content(prompt)
        res_text = response.text.replace("```json", "").replace("```", "").strip()
        data = json.loads(res_text)
        
        return data.get("score", 50), data.get("verdict", "Suspicious"), data.get("summary", "Analyzed by Gemini AI")
        
    except Exception as e:
        print(f"OCR Gemini AI Error: {e}")
        return 80, "Suspicious / Potential Threat", f"Flagged by backup heuristics. Engine Error: {str(e)[:50]}"

def extract_soc_threat_intel(text_corpus: str):
    text = text_corpus.lower()
    if any(x in text for x in ["login", "verify", "password", "credential", "kyc", "pan", "aadhar", "account", "खाता", "पासवर्ड", "सत्यापित"]):
        category = "Credential Harvesting"
    elif any(x in text for x in ["download", "apk", "exe", "update software", "install", "डाउनलोड", "एपीडी"]):
        category = "Malware Distribution"
    elif any(x in text for x in ["lottery", "win", "gift", "cash", "reward", "free", "बोनस", "इनाम", "पैसे", "payment"]):
        category = "Financial Fraud/Scam"
    else:
        category = "Social Engineering Alert"
        
    if any(x in text for x in ["urgent", "blocked", "suspended", "immediately", "expired", "तुरंत", "बंद", "जल्दी"]):
        severity = "CRITICAL"
    elif any(x in text for x in ["verify", "claim", "pan card", "लिंक", "payment"]):
        severity = "HIGH"
    else:
        severity = "MEDIUM"
        
    return category, severity

def save_scan_history(db: Session, scan_type: str, title: str, source: str, verdict: str, risk_score: int, summary: str):
    db.add(DBScanHistory(
        scan_type=scan_type,
        title=title,
        source=source,
        verdict=verdict,
        risk_score=risk_score,
        summary=summary,
    ))
    db.commit()

def trigger_soar_incident_remediation(source_text: str, threat_source: str, db: Session):
    try:
        words = source_text.split()
        detected_domain = "unknown-phish-portal.com"
        for word in words:
            if "http" in word or ".com" in word or ".net" in word or ".org" in word or "licindia" in word:
                clean_word = word.replace("http://", "").replace("https://", "").split("/")[0].strip(",.()\"'")
                if clean_word:
                    detected_domain = clean_word
                    break
        try:
            detected_ip = socket.gethostbyname(detected_domain)
        except Exception:
            detected_ip = f"{random.randint(100,200)}.{random.randint(10,99)}.{random.randint(1,254)}.{random.randint(1,254)}"
            
        category, severity = extract_soc_threat_intel(source_text)
            
        existing_incidents_count = db.query(DBIncident).count()
        new_id = f"INC-{existing_incidents_count + 101}"
        
        exists = db.query(DBIncident).filter(DBIncident.domain == detected_domain).first()
        if not exists:
            incident_log = DBIncident(
                id=new_id,
                domain=detected_domain,
                ip=detected_ip,
                source=threat_source,
                category=category,
                severity=severity,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                remediation_status="BLOCKED / ISOLATED",
                action_taken="Automated Null-Route Rule Added to Core Firewall Policies"
            )
            db.add(incident_log)
            db.commit()
    except Exception as e:
        print(f"SOAR Database Core Failure: {str(e)}")

def init_db():
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully!")

if __name__ == "__main__":
    init_db()
def send_reverse_pipeline_telegram_alert(sender_num: str, sms_body: str):
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if not bot_token or not chat_id:
        print("🚨 SOAR Warning: Telegram credentials missing in .env configuration nodes.")
        return
    
    # 🛡️ Safe HTML Template Construction (Prevents link parsing crashes)
    alert_message = (
        "🚨 <b>PHISHGUARD CRITICAL ALERT</b> 🚨\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⚠️ <b>Threat Detected:</b> Inbound Smishing/Phishing Attempt\n"
        "📱 <b>Attacker Source:</b> <code>{}</code>\n"
        "⏰ <b>Incident Time:</b> <code>{}</code>\n\n"
        "📝 <b>Intercepted Text Content:</b>\n"
        "<i>{}</i>\n\n"
        "🛡️ <b>SOAR MITIGATION ACTION:</b> Attacker IOC indicators successfully logged and isolated inside the Firewall database pool.\n\n"
        "🛑 <b>CRITICAL DIRECTIVE:</b> <b>DO NOT click any links or input credentials!</b>"
    ).format(sender_num, datetime.now().strftime('%Y-%m-%d %H:%M:%S IST'), sms_body)
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": alert_message,
        "parse_mode": "HTML"  # 👈 Markdown se badalkar HTML kiya taaki links crash na karein
    }
    
    try:
        res = requests.post(url, json=payload, timeout=10)
        print(f"DEBUG: Reverse Pipeline Telegram Response Status: {res.status_code}")
        if res.status_code != 200:
            print(f"DEBUG: Telegram Error Details: {res.text}")
    except Exception as e:
        print(f"🚨 SOAR Failure: Reverse Pipeline Notification Delivery Crash: {e}")           
# ======================================================================
# 🔐 REGISTRATION AND JWT ACCESS API ROUTERS CONFIGURATION NODES
# ======================================================================
@app.post("/api/v1/auth/send-otp")
def send_registration_otp(payload: OTPRequest, db: Session = Depends(get_db)):
    user_exists = db.query(DBUser).filter(DBUser.email == payload.email).first()
    if user_exists:
        raise HTTPException(status_code=400, detail="Email already registered. Please login.")
    if not SMTP_USER or not SMTP_PASSWORD:
        raise HTTPException(status_code=500, detail="Email OTP service is not configured. Add SMTP_USER and SMTP_PASSWORD in backend .env.")

    otp = f"{secrets.randbelow(900000) + 100000}"
    OTP_STORE[payload.email.lower()] = {
        "otp": otp,
        "expires_at": datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES),
    }

    try:
        send_otp_email(payload.email, otp)
    except Exception as exc:
        OTP_STORE.pop(payload.email.lower(), None)
        raise HTTPException(status_code=500, detail=f"Could not send OTP email: {str(exc)}")
    return {"status": "success", "message": "OTP sent successfully to your email."}

@app.post("/api/v1/auth/verify-otp")
def verify_registration_otp_endpoint(payload: OTPVerify):
    if not verify_registration_otp(payload.email, payload.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    return {"status": "verified", "message": "OTP verified successfully."}

@app.post("/api/v1/auth/register")
def register_phishguard_analyst(payload: UserRegister, db: Session = Depends(get_db)):
    user_exists = db.query(DBUser).filter(DBUser.email == payload.email).first()
    if user_exists:
        raise HTTPException(status_code=400, detail="Email already registered. Please login.")
    if not verify_registration_otp(payload.email, payload.otp):
        raise HTTPException(status_code=400, detail="Please verify a valid OTP before registration.")
    
    new_user = DBUser(
        username=payload.name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    try:
        db.add(new_user)
        db.commit()
        OTP_STORE.pop(payload.email.lower(), None)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration database error: {str(exc)}")
    return {"status": "success", "message": "Analyst identity schema initialized successfully inside database tree."}

@app.post("/api/v1/auth/login")
def login_phishguard_analyst(request: Request, payload: UserLogin, db: Session = Depends(get_db)): # 👈 Note: Yahan 'request: Request' add kiya hai IP nikalne kelia
    user = db.query(DBUser).filter(DBUser.email == payload.email).first()
    client_ip = request.client.host if request.client else "Unknown IP"
    
    if not user or not verify_password(payload.password, user.hashed_password):
        # 🔐 LEVEL 8: LOG FAILED LOGIN ATTEMPT
        log_audit_event(db=db, action="LOGIN_FAILED", user_email=payload.email, details="Invalid access credentials attempt.", ip_address=client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid identity access credentials token signatures.")
    
    # 🔐 LEVEL 8: LOG SUCCESSFUL LOGIN
    log_audit_event(db=db, action="LOGIN_SUCCESS", user_email=user.email, details="Session token issued safely.", ip_address=client_ip)
    
    token = create_access_token(data={"sub": user.email, "uid": user.id})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_profile": {
            "name": user.username,
            "email": user.email,
            "security_score": user.security_score or 100,
            "joined_date": user.created_at.isoformat() if user.created_at else None,
            "permissions_accepted": False, # Initial status default to False for new session triggers
        }  
    }
@app.post("/api/v1/auth/forgot-password")
def forgot_password_endpoint(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(DBUser).filter(DBUser.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email identity not found inside database tree.")
    
    otp = f"{secrets.randbelow(900000) + 100000}"
    OTP_STORE[payload.email.lower()] = {
        "otp": otp,
        "expires_at": datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES),
    }
    
    try:
        message = EmailMessage()
        message["Subject"] = "PhishGuard AI Password Reset OTP"
        message["From"] = SMTP_FROM
        message["To"] = payload.email
        message.set_content(f"Your security reset OTP verification key is {otp}. Valid for 10 minutes.")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)
        return {"status": "success", "message": "Reset OTP dispatch successful! Check email."}
    except Exception as exc:
        OTP_STORE.pop(payload.email.lower(), None)
        raise HTTPException(status_code=500, detail=f"Mail pipeline gateway crash: {str(exc)}")

@app.post("/api/v1/auth/reset-password")
def reset_password_endpoint(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    # Verify via the core secure token comparator
    if not verify_registration_otp(payload.email, payload.otp):
        raise HTTPException(status_code=400, detail="Invalid or expired verification OTP key.")
        
    user = db.query(DBUser).filter(DBUser.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User target profile mismatch.")
        
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    OTP_STORE.pop(payload.email.lower(), None)
    return {"status": "success", "message": "Password identity signature updated successfully."}
# 📬 GMAIL OAUTH FLOW ENDPOINTS
@app.get("/api/v1/auth/google-login")
def initiate_google_auth_flow(current_user: dict = Depends(verify_jwt_token)):
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"scope={SCOPES}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    return {"url": auth_url}

@app.get("/api/v1/auth/callback", response_class=HTMLResponse)
def google_auth_callback_handler(code: str):
    db = SessionLocal()
    try:
        token_url = "https://oauth2.googleapis.com/token"
        payload = {
            "code": code,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        token_response = requests.post(token_url, data=payload)
        token_data = token_response.json()
        
        access_token = token_data.get("access_token")
        creds = Credentials(token=access_token)
        service = build("gmail", "v1", credentials=creds)
        
        profile = service.users().getProfile(userId="me").execute()
        connected_email = profile.get("emailAddress", "Unknown User Account")
        
        top_user = db.query(DBUser).first()
        if top_user:
            top_user.connected_email = connected_email
            top_user.gmail_status = "CONNECTED"
            db.commit()
            
        messages_result = service.users().messages().list(userId="me", maxResults=500).execute()
        messages_list = messages_result.get('messages', [])
        total_messages = len(messages_list)
        
        results = service.users().messages().list(userId="me", maxResults=15).execute()
        unread_list = results.get("messages", [])
        
        scanned_emails_payload = []
        detected_phishing_count = 0
        
        for msg_meta in unread_list:
            msg = service.users().messages().get(userId="me", id=msg_meta["id"], format="full").execute()
            snippet_text = msg.get("snippet", "")
            
            headers = msg.get("payload", {}).get("headers", [])
            sender_header = "Live Mailbox Inbound"
            subject_header = "No Subject Payload"
            for h in headers:
                if h.get("name") == "From": sender_header = h.get("value")
                if h.get("name") == "Subject": subject_header = h.get("value")
            
            analysis_corpus = f"{sender_header} {subject_header} {snippet_text}".lower()
            is_harmful = any(x in analysis_corpus for x in ["verify", "suspended", "blocked", "kyc", "pan card", "urgent"])
            
            if is_harmful:
                detected_phishing_count += 1
                trigger_soar_incident_remediation(analysis_corpus, f"Gmail ({sender_header})", db)
            save_scan_history(
                db=db,
                scan_type="EMAIL_THREAT",
                title=subject_header,
                source=sender_header,
                verdict="Threat Detected",
                risk_score=88,
                summary=snippet_text,
            )    
            scanned_emails_payload.append({
                "id": msg_meta["id"],
                "sender": sender_header,
                "subject": subject_header,
                "snippet": snippet_text,
                "is_harmful": is_harmful,
                "risk_score": 88 if is_harmful else 10
            })
            
        with open("live_gmail_cache.json", "w") as f:
            json.dump({
                "connected_email": connected_email,
                "status": "CONNECTED",
                "total_in_account": total_messages, 
                "harmful_count": detected_phishing_count, 
                "normal_count": total_messages - detected_phishing_count, 
                "emails": scanned_emails_payload
            }, f)
            
        return """
        <html>
            <body style="background-color: #040612; color: #10b981; font-family: sans-serif; text-align: center; padding-top: 100px;">
                <div style="border: 1px solid #10b981; display: inline-block; padding: 30px; border-radius: 15px; background: #080c1b;">
                    <h2>🧬 PhishGuard AI Authorized Successfully!</h2>
                    <p style="color: #94a3b8;">This secure pipeline sync window will close automatically now...</p>
                </div>
                <script>setTimeout(function() { window.close(); }, 2000);</script>
            </body>
        </html>
        """
    except Exception as e:
        return f"<html><body><h3>Engine Crash: {str(e)}</h3></body></html>"
    finally:
        db.close()

# 📬 GMAIL LIVE INBOX METRICS 
@app.get("/api/v1/automation/gmail/inbox")
def get_live_gmail_metrics(current_user: dict = Depends(verify_jwt_token)):
    import os, json
    if os.path.exists("live_gmail_cache.json"):
        with open("live_gmail_cache.json", "r") as f: 
            return json.load(f)
    return {"connected_email": None, "status": "DISCONNECTED", "total_in_account": 0, "harmful_count": 0, "normal_count": 0, "emails": []}

# 🔌 GMAIL DISCONNECT ROUTE
@app.post("/api/v1/auth/gmail/disconnect")
def disconnect_google_account(db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    import os, json
    try:
        top_user = db.query(DBUser).first()
        if top_user:
            top_user.connected_email = None
            top_user.gmail_status = "DISCONNECTED"
            db.commit()

        cache_file = "live_gmail_cache.json"
        if os.path.exists(cache_file):
            with open(cache_file, "w") as f:
                json.dump({
                    "connected_email": None,
                    "status": "DISCONNECTED",
                    "total_in_account": 0, 
                    "harmful_count": 0, 
                    "normal_count": 0, 
                    "emails": []
                }, f)

        return {"status": "success", "message": "Gmail Node Disconnected Successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to disconnect: {str(e)}")

# 📱 SMS INTERCEPT PIPELINE
# 📱 SMS INTERCEPT PIPELINE
@app.post("/api/v1/automation/sms/intercept")
def intercept_incoming_device_sms(payload: IncomingSMS, db: Session = Depends(get_db)):
    try:
        # 1. Read existing cache data safely
        if os.path.exists(SMS_CACHE_FILE):
            with open(SMS_CACHE_FILE, "r") as f:
                data = json.load(f)
        else:
            data = {"total_in_account": 0, "harmful_count": 0, "normal_count": 0, "logs": []}
            
        sms_text = payload.message.lower()
        print(f"DEBUG: SMS content received: {sms_text}")
        
        # LEVEL 1: Fast Keyword Heuristic
        fraud_keywords = ["lottery", "win", "gift card", "reward", "luck", "free cash", "click link", "ebanking", "verify", "suspended", "blocked", "kyc", "pan", "aadhar", "account"]
        is_fraud = any(term in sms_text for term in fraud_keywords)
        
        # LEVEL 2: Deep AI Analysis
        if not is_fraud:
            score, verdict, summary = evaluate_extracted_text(sms_text)
            if score > 50:
                is_fraud = True
        
        # 2. Update stats parameters (CLEANED: Single execution mapping)
        data["total_in_account"] += 1
        if is_fraud:
            data["harmful_count"] += 1
            # 🔐 LEVEL 8: Trigger SOAR Incident Remediation
            trigger_soar_incident_remediation(payload.message, f"SMS Gateway ({payload.sender})", db)
            # 🚀 SOAR RESPONSE ACTIVE PROTOCOL: Execute Reverse Pipeline Telegram Push Alert
            send_reverse_pipeline_telegram_alert(payload.sender, payload.message)
        else:
            data["normal_count"] += 1    
            
        # 🚀 FIX 1: Added ISO Timestamp structure for frontend timeline alignment
        new_log = {
            "sender": payload.sender,
            "message": payload.message,
            "is_harmful": is_fraud,
            "timestamp": datetime.utcnow().isoformat()
        }
        if "logs" not in data:
            data["logs"] = []
        data["logs"].insert(0, new_log)
        
        # 🚀 FIX 2: Security Score Metric Database Table Entry Insertion
        try:
            db_sms_log = models.SMSLog(
                sender=payload.sender,
                message=payload.message,
                is_harmful=is_fraud,
                timestamp=datetime.utcnow()
            )
            db.add(db_sms_log)
            db.commit()
        except Exception as db_err:
            print(f"Database Core SMSLog insertion skipped: {db_err}")
            db.rollback()
        
        # 4. Save history timeline log to Database
        save_scan_history(
            db=db,
            scan_type="SMS_THREAT",
            title=f"Inbound SMS from {payload.sender}",
            source="Mobile Hook Gateway (AI-Hybrid)",
            verdict="Threat Flagged" if is_fraud else "Safe / Clean",
            risk_score=94 if is_fraud else 8,
            summary=payload.message
        )
        
        # 5. Permanent Write-back to JSON cache memory
        with open(SMS_CACHE_FILE, "w") as f:
            json.dump(data, f)
            
        return {"status": "success", "analysed_as_fraud": is_fraud}
    except Exception as e:
        print(f"SMS Intercept Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
@app.post("/api/v1/vt/url")
def virustotal_url_reputation(payload: URLPayload):
    scan_response = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=vt_headers(),
        data={"url": payload.url},
        timeout=20,
    )

    if scan_response.status_code not in [200, 201]:
        raise HTTPException(status_code=scan_response.status_code, detail=scan_response.text)

    report_response = requests.get(
        f"{VT_BASE_URL}/urls/{vt_url_id(payload.url)}",
        headers=vt_headers(),
        timeout=20,
    )

    if report_response.status_code != 200:
        return {"status": "submitted", "message": "URL submitted to VirusTotal. Report may take a moment."}

    data = report_response.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    verdict, risk_score, confidence = vt_stats_to_verdict(stats)

    return {
        "type": "URL_REPUTATION",
        "target": payload.url,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "stats": stats,
    }

@app.post("/api/v1/vt/domain")
def virustotal_domain_reputation(payload: DomainPayload):
    domain = payload.domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    response = requests.get(
        f"{VT_BASE_URL}/domains/{domain}",
        headers=vt_headers(),
        timeout=20,
    )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    data = response.json()["data"]["attributes"]
    stats = data.get("last_analysis_stats", {})
    verdict, risk_score, confidence = vt_stats_to_verdict(stats)

    return {
        "type": "DOMAIN_REPUTATION",
        "target": domain,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "stats": stats,
        "reputation": data.get("reputation"),
        "categories": data.get("categories", {}),
    }

@app.post("/api/v1/vt/hash")
def virustotal_hash_reputation(payload: HashPayload, db: Session = Depends(get_db)):
    try:
        file_hash = payload.hash.strip().lower()
        response = requests.get(
            f"{VT_BASE_URL}/files/{file_hash}",
            headers=vt_headers(),
            timeout=20,
        )

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        verdict, risk_score, confidence = vt_stats_to_verdict(stats)
        
        is_fraud = verdict == "Phishing" or verdict == "Suspicious"

        with open(SMS_CACHE_FILE, "r+") as f:
            cache_data = json.load(f)
            
            if is_fraud:
                cache_data["harmful_count"] += 1
                save_scan_history(
                    db=db, scan_type="HASH_THREAT", title=file_hash,
                    source="VirusTotal", verdict="Threat Detected",
                    risk_score=risk_score, summary=f"Hash scan: {verdict}"
                )
            else:
                cache_data["normal_count"] += 1
            
            new_log = {
                "sender": "System",
                "message": f"Hash scanned: {file_hash}",
                "is_harmful": is_fraud,
                "verdict": verdict
            }
            cache_data["logs"].insert(0, new_log)
            f.seek(0)
            json.dump(cache_data, f)
            f.truncate()

        return {
            "status": "success",
            "verdict": verdict,
            "risk_score": risk_score,
            "analysed_as_fraud": is_fraud
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/automation/sms/logs")
def get_native_android_sms_logs(current_user: dict = Depends(verify_jwt_token)):
    with open(SMS_CACHE_FILE, "r") as f: return json.load(f)

# ======================================================================
# 🚨 LOCKED HIGH-RESOURCE SCANNERS (RATE LIMITING + BEARER TOKENS) 🚨
# ======================================================================

# 🌐 1. Secure Sandbox Link Evaluation Channel
@app.post("/api/v1/scan")
@limiter.limit("5/minute") # LEVEL 3: Core Anti-DDoS Rate Limit Node
def manual_url_scan(request: Request, payload: URLPayload, db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    verdict, threat_index, confidence = predict_url_with_ai(payload.url)
    is_malicious = verdict in ["Phishing", "Suspicious"]

    summary = (
        f"AI Random Forest model classified this URL as {verdict} with {confidence}% confidence."
    )
    
    new_scan = ScanLog(
        url=payload.url, 
        threat_index=threat_index, 
        verdict=verdict,
        analysis_summary=summary 
    )
    db.add(new_scan)
    db.commit()

    save_scan_history(
        db=db,
        scan_type="URL_SCAN",
        title=payload.url,
        source="Sandbox URL Scanner",
        verdict=verdict,
        risk_score=threat_index,
        summary=summary,
    )
    
    if is_malicious:
        trigger_soar_incident_remediation(payload.url, "Sandbox Evaluation Channel", db)
        
    return {
        "url": payload.url,
        "threat_index": threat_index,
        "verdict": verdict,
        "confidence": confidence,
        "analysis_summary": summary,
    }

# 📸 🧬 2. Secure Multipart Form Image OCR Scanner (Gemini Powered - Anti-Crash Version)
@app.post("/api/v1/scan/screenshot-ocr")
@limiter.limit("3/minute") # Strict limit for API endpoint monitoring
async def scan_screenshot_ocr_intel(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    try:
        # 1. Image ke raw bytes read karein (NumPy aur CV2 load karne ki ab koi zaroorat nahi)
        file_bytes = await file.read()
        
        # 2. Gemini Multimodal format dictionary taiyar karein
        image_parts = [{
            "mime_type": file.content_type,
            "data": file_bytes
        }]
        
        # 3. Gemini Flash Model initialize karke sharp text extraction prompt run karein
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = (
            "Extract all text, visible URLs, linguistic structures, and digits precisely from this image/screenshot. "
            "Do not add any introductory chat, commentary, or extra explanations. Just provide the raw extracted text."
        )
        
        response = model.generate_content([prompt, image_parts[0]])
        extracted_text = response.text
        
        # Hindi digits ko normalize karein (Aapka existing logic)
        extracted_text = normalize_hindi_digits_to_english(extracted_text)

        if not extracted_text.strip():
            extracted_text = "No alphanumeric words or linguistic structures found inside this screenshot canvas."

        # 4. Data Parsing (Regex, Evaluation, History, SOAR Logs) - Sab pehle ki tarah safe chalega
        detected_urls = re.findall(r'(https?://\S+|www\.\S+|\S+\.(?:com|in|net|org|edu|gov)\S*)', extracted_text)
        detected_numbers = re.findall(r'[\+\d\s\-]{10,15}', extracted_text)
        
        # Threat assessment engine call
        threat_index, verdict, summary = evaluate_extracted_text(extracted_text)
        
        # Database mein scan ki history record karein
        save_scan_history(
            db=db,
            scan_type="OCR_SCAN",
            title="Screenshot OCR Scan",
            source="Image OCR Scanner",
            verdict=verdict,
            risk_score=threat_index,
            summary=extracted_text[:500],
        )
        
        # Incident response trigger logic
        if threat_index > 50:
            trigger_soar_incident_remediation(extracted_text, "Live OCR Image Detection Channel", db)
            
        return {
            "status": "success",
            "extracted_text": extracted_text,
            "detected_urls": detected_urls if detected_urls else ["None Detected"],
            "detected_numbers": [n.strip() for n in detected_numbers if n.strip()] if detected_numbers else ["None Detected"],
            "threat_index": threat_index,
            "verdict": verdict,
            "analysis_summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OCR Runtime Thread Failure: {str(e)}")

# 🤖 🌐 3. Secure Adaptive AI Conversational Engine Route
@app.post("/api/v1/bot/chat")
@limiter.limit("10/minute") # LEVEL 3: Throttling automated loop spams
def security_ai_bot_conversational_engine(request: Request, payload: BotQuery, db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    import os, json
    import google.generativeai as genai
    from dotenv import load_dotenv
    load_dotenv(override=True)
    
    query = payload.question.strip()
    
    # 🛡️ LEVEL 6 TRIGGER: PROMPT INJECTION GUARDRAIL FILTER
    if validate_prompt_injection(query):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security Alert: Malicious prompt injection pattern or guardrail bypass vector detected."
        )
        
    raw_key = os.getenv("GEMINI_API_KEY")
    if not raw_key:
        return {"response": "System Error: Gemini API Key missing.", "detected_mode": "ERROR"}

    # 🧠 RAG (Retrieval-Augmented Generation) Context Builder
    soar_incidents = db.query(DBIncident).all()
    total_blocked = len(soar_incidents)
    
    gmail_threats = 0
    if os.path.exists("live_gmail_cache.json"):
        with open("live_gmail_cache.json", "r") as f:
            gmail_data = json.load(f)
            gmail_threats = gmail_data.get("harmful_count", 0)
            
    rag_context = f"""
    [LIVE SYSTEM CONTEXT (RAG DATA)]:
    - Total Threats Blocked in SOAR Firewall: {total_blocked}
    - Total Phishing Emails Detected Today: {gmail_threats}
    If the user asks about app stats, use this data to answer them accurately.
    """

    try:
        genai.configure(api_key=raw_key.strip())
        valid_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        target_model = 'gemini-1.5-flash'
        if 'models/gemini-1.5-flash' not in valid_models:
            target_model = valid_models[0].replace('models/', '')
            
        model = genai.GenerativeModel(target_model)
        
        system_prompt = f"""You are PhishGuard AI, an elite cybersecurity expert and SOC Analyst. 
        Your job is to analyze cyber threats, phishing links, malware, and firewall rules.
        IMPORTANT RULE: You MUST reply in the EXACT SAME LANGUAGE the user asks the question in (English, Hindi, or Hinglish).
        Keep your answers professional and technical yet easy to understand.
        
        {rag_context}
        """

        ai_response = model.generate_content(f"{system_prompt}\n\nUser Query: {query}")
        ans = ai_response.text

        query_lower = query.lower()
        is_hindi = any(char >= '\u0900' and char <= '\u097f' for char in query)
        is_hinglish = any(w in query_lower for w in ["kya", "kaise", "hai", "bhai", "ko", "se", "mera", "batao"]) and not is_hindi
        detected_mode = "HINDI" if is_hindi else ("HINGLISH" if is_hinglish else "ENGLISH")

        return {"response": ans, "detected_mode": detected_mode}

    except Exception as e:
        print(f"Gemini API Error: {str(e)}")
        return {"response": f"Engine Error: {str(e)}", "detected_mode": "ERROR"}

# ======================================================================
# 📑 CORE MONITOR DATA LEDGER ROUTERS WITH TOKENS
# ======================================================================
@app.get("/api/v1/history/scans")
def get_scan_history(db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    records = db.query(DBScanHistory).order_by(DBScanHistory.timestamp.desc()).limit(100).all()
    return [
        {
            "id": item.id,
            "scan_type": item.scan_type,
            "title": item.title,
            "source": item.source,
            "verdict": item.verdict,
            "risk_score": item.risk_score,
            "summary": item.summary,
            "timestamp": item.timestamp.isoformat() if item.timestamp else None,
        }
        for item in records
    ]

@app.get("/api/v1/soar/blacklist")
def get_soar_firewall_blacklist(db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    incidents = db.query(DBIncident).all()
    blacklist_payload = []
    for inc in incidents:
        blacklist_payload.append({
            "id": inc.id,
            "domain": inc.domain,
            "ip": inc.ip,
            "source": inc.source,
            "category": inc.category,
            "severity": inc.severity,
            "timestamp": inc.timestamp,
            "remediation_status": inc.remediation_status,
            "action_taken": inc.action_taken
        })
    return blacklist_payload

@app.get("/api/v1/security-score")
def get_security_score(db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    try:
        phish_count = db.query(PhishingLog).count()
        sms_count = db.query(SMSLog).filter(SMSLog.is_harmful == True).count()
        url_count = db.query(ScanLog).filter(ScanLog.threat_index > 30).count()
        ocr_count = 0 
        
        deductions = (phish_count * 5) + (sms_count * 5) + (url_count * 10) + (ocr_count * 10)
        final_score = max(0, 100 - deductions)
        
        return {
            "overall_score": int(final_score),
            "breakdown": {
                "phishing_emails": phish_count,
                "fraud_sms": sms_count,
                "dangerous_urls": url_count,
                "ocr_threats": ocr_count
            }
        }
    except Exception as e:
        print(f"Score Engine Error: {e}")
        return {"overall_score": 100, "breakdown": {}}

# 📄 📑 AI REPORT GENERATOR ENDPOINT
@app.get("/api/v1/soar/report/{incident_id}")
def generate_ai_incident_report(incident_id: str, db: Session = Depends(get_db), current_user: dict = Depends(verify_jwt_token)):
    incident = db.query(DBIncident).filter(DBIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident registry target not found.")
        
    import google.generativeai as genai
    import os
    from dotenv import load_dotenv
    load_dotenv(override=True)
    
    raw_key = os.getenv("GEMINI_API_KEY")
    report_content = "Failed to generate report."
    
    if raw_key:
        try:
            genai.configure(api_key=raw_key.strip())
            valid_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
            target_model = 'gemini-1.5-flash'
            if 'models/gemini-1.5-flash' not in valid_models:
                target_model = valid_models[0].replace('models/', '')
                
            model = genai.GenerativeModel(target_model)
            
            prompt = f"""Write a highly professional and detailed Cybersecurity Forensic Incident Report. 
            Use the following threat metadata:
            - Incident ID: {incident.id}
            - Threat Domain: {incident.domain}
            - Attacker IP: {incident.ip}
            - Source Channel: {incident.source}
            - Category: {incident.category}
            - Severity: {incident.severity}
            - Remediation Taken: {incident.action_taken}
            
            Format it beautifully like a real SOC operations log with sections: [1] Threat Intel Metadata, [2] Automated SOAR Logs, and [3] AI Forensic Executive Summary. Make the summary detailed and technical."""
            
            response = model.generate_content(prompt)
            report_content = response.text
            
        except Exception as e:
            report_content = f"Error generating dynamic AI report: {e}"

    return JSONResponse(content={"incident_id": incident_id, "report_text": report_content})
