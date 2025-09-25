import os
import json
import time
import hashlib
import socket
import random
import redis
import requests
from datetime import datetime, timedelta
from typing import Optional, List

from pydantic import BaseModel
from sqlmodel import SQLModel, Field, create_engine
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jose import jwt
from passlib.context import CryptContext

try:
    from river import anomaly
    RIVER_OK = True
except ImportError:
    RIVER_OK = False

try:
    import geoip2.database
    GEO_OK = True
except ImportError:
    GEO_OK = False

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 12 * 60
DB_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'secure_logs.db')}")
FERNET_KEY_PATH = os.path.join("./fernet.key")
ED25519_PRIV_PATH = os.path.join("ed25519_private.key")
ED25519_PUB_PATH = os.path.join("./ed25519_public.key")
GEOLITE_DB = os.path.join("./GeoLite2-City.mmdb")
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

with open(FERNET_KEY_PATH, "rb") as f: FERNET = Fernet(f.read())
with open(ED25519_PRIV_PATH, "rb") as f: PRIV_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open(ED25519_PUB_PATH, "rb") as f: PUB_KEY = serialization.load_pem_public_key(f.read())

GEO_READER = None
if GEO_OK and os.path.exists(GEOLITE_DB):
    try: GEO_READER = geoip2.database.Reader(GEOLITE_DB)
    except Exception: GEO_READER = None

HST = anomaly.HalfSpaceTrees(seed=42) if RIVER_OK else None
SRC_HITS = {}
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Block(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    index: int; timestamp: str; previous_hash: str; hash: str; signature_hex: str;
    src_ip: str; dst_ip: str; size: int; severity: str; attack_type: str;
    detected_by: str; ml_confidence: float; hostname: Optional[str] = None;
    country: Optional[str] = None; city: Optional[str] = None; isp: Optional[str] = None;
    enc_data: bytes; abuse_score: Optional[int] = None; ip_report_count: Optional[int] = None;

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str

class LogsResponse(BaseModel):
    items: List[dict]; page: int; pages: int; total: int;

def hash_password(p: str) -> str: return pwd_context.hash(p)
def verify_password(p: str, h: str) -> bool: return pwd_context.verify(p, h)
def create_access_token(data: dict, exp_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (exp_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)

def get_current_user():
    from fastapi import Depends, HTTPException, Request; from jose import JWTError
    async def inner(request: Request):
        auth: str = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "): raise HTTPException(status_code=401, detail="Missing bearer token")
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            sub: str = payload.get("sub")
            if not sub: raise HTTPException(status_code=401, detail="Invalid token")
            return sub
        except JWTError: raise HTTPException(status_code=401, detail="Invalid or expired token")
    return inner

def calculate_hash(i: int, ts: str, dt: str, ph: str) -> str: return hashlib.sha256(f"{i}{ts}{dt}{ph}".encode()).hexdigest()
def sign_bytes(b: bytes) -> str: return PRIV_KEY.sign(b).hex()
def verify_signature(b: bytes, sig_hex: str) -> bool:
    try: PUB_KEY.verify(bytes.fromhex(sig_hex), b); return True
    except Exception: return False
def encrypt_json(d: dict) -> bytes: return FERNET.encrypt(json.dumps(d).encode())
def hostname_of(ip: str) -> Optional[str]:
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return None

def geo_of(ip: str):
    private_ranges = ("10.", "192.168.", "172.16.", "127.", "0.", "169.254.")
    if ip.startswith(private_ranges) or not GEO_READER: return None, None, None
    try: r = GEO_READER.city(ip); return r.country.name, r.city.name, None
    except geoip2.errors.AddressNotFoundError: return None, None, None

def push_rate():
    now = time.time()
    key = f"rate:{int(now)}"
    redis_client.incr(key)
    redis_client.expire(key, 60)

def current_rate():
    now = int(time.time())
    keys = [f"rate:{ts}" for ts in range(now - 30, now)]
    if not keys: return 0.0
    values = redis_client.mget(keys)
    total_packets = sum(int(v) for v in values if v)
    return total_packets / 30.0

def rate_history():
    now, buckets, hist, window = int(time.time()), 10, [], 30
    width = window / buckets
    all_keys = [f"rate:{ts}" for ts in range(now - window, now)]
    if not all_keys: return []
    all_values = redis_client.mget(all_keys)
    counts_by_ts = {(now - window + i): (int(v) if v else 0) for i, v in enumerate(all_values)}
    for i in range(buckets):
        start_ts = (now - window) + int(i * width)
        end_ts = start_ts + int(width)
        count = sum(counts_by_ts.get(ts, 0) for ts in range(start_ts, end_ts))
        hist.append({"ts": start_ts, "count": count})
    return hist

def ml_anomaly_score(x: dict) -> float:
    if not HST: return 0.0
    try:
        score = HST.score_one(x); HST.learn_one(x)
        return max(0.0, min(1.0, 1 - (1 / (1 + max(0, score)))))
    except Exception: return 0.0

def severity_and_attack(packet: dict, ml_score: float, ip_counts: dict):
    size, src = packet["size"], packet["src_ip"]; hits = ip_counts.get(src, 0)
    attack = "Normal"
    if size > 1200: attack = "Possible DDoS"
    elif hits >= 5: attack = "Suspicious Host"
    elif ml_score >= 0.75: attack = "AI Flagged Anomaly"
    sev = "Normal"
    if attack == "Possible DDoS" or ml_score >= 0.9: sev = "High"
    elif attack == "Suspicious Host" or ml_score >= 0.75: sev = "Medium"
    elif ml_score >= 0.6: sev = "Low"
    return sev, attack

def get_ip_reputation(ip: str, api_key: Optional[str] = None):
    private_ranges = ("10.", "192.168.", "172.16.", "127.", "0.", "169.254.")
    if ip.startswith(private_ranges): return (0, 0)
    if not api_key:
        if random.randint(1, 10) == 1: return (random.randint(75, 100), random.randint(5, 100))
        return (0, 0)
    try:
        res = requests.get('https://api.abuseipdb.com/api/v2/check', headers={'Accept': 'application/json', 'Key': api_key}, params={'ipAddress': ip, 'maxAgeInDays': '90'})
        if res.status_code == 200:
            data = res.json()['data']
            return (data.get('abuseConfidenceScore'), data.get('totalReports'))
    except Exception: pass
    return (None, None)
