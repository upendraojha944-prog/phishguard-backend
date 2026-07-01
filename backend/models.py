from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean 
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base # Ensure 'database.py' file exists

# 👤 USER REGISTRATION PROFILE TABLE SCHEMA
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    otp_code = Column(String, nullable=True)
    otp_verified = Column(Boolean, default=False)
    
    # SECURITY SCORE field yahan hona chahiye
    security_score = Column(Integer, default=100) 

    scans = relationship("ScanLog", back_populates="owner")

# 🗄️ THREAT DETECTION SYSTEM LEDGER TABLE SCHEMA
class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String, index=True, nullable=False)
    threat_index = Column(Integer, nullable=False)
    verdict = Column(String, nullable=False)
    analysis_summary = Column(String, nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    owner = relationship("User", back_populates="scans")

class PhishingLog(Base):
    __tablename__ = "phishing_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    verdict = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

class SMSLog(Base):
    __tablename__ = "sms_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, nullable=False)
    message_body = Column(String, nullable=False)
    is_harmful = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)