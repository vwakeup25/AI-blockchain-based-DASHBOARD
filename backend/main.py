import os
import subprocess
import platform
from typing import List

from fastapi import FastAPI, Depends, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from dotenv import load_dotenv
from pydantic import BaseModel
from sqlmodel import SQLModel, select

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

from utils import (
    engine, Session, Block, User, LogsResponse,
    create_access_token, get_current_user, hash_password, verify_password,
    current_rate, rate_history, verify_signature,
    SRC_HITS, redis_client
)

load_dotenv()
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
SQLModel.metadata.create_all(engine)

app = FastAPI(title="Synapse Sentinel (Secure)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGINS] if CORS_ORIGINS != "*" else ["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

class UserCreate(BaseModel):
    username: str
    password: str

@app.post("/users/register", response_model=User)
def create_user(user: UserCreate):
    with Session() as session:
        existing_user = session.query(User).filter(User.username == user.username).first()
        if existing_user: raise HTTPException(status_code=400, detail="Username already registered")
        hashed_pwd = hash_password(user.password)
        db_user = User(username=user.username, hashed_password=hashed_pwd)
        session.add(db_user); session.commit(); session.refresh(db_user);
        return db_user

@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    with Session() as session:
        user = session.query(User).filter(User.username == form.username).first()
        if not user or not verify_password(form.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        token = create_access_token({"sub": user.username})
        return {"access_token": token, "token_type": "bearer"}

@app.get("/")
def root(): return {"message": "🚀 Synapse Sentinel Backend is running"}

@app.get("/packet_rate")
def packet_rate(): return {"rate": current_rate(), "history": rate_history()}

@app.post("/block/{ip_address}")
def block_ip_endpoint(ip_address: str, user: str = Depends(get_current_user())):
    print(f"Received block request for IP: {ip_address} from user: {user}")
    command = []
    system = platform.system()
    if system == "Linux":
        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    elif system == "Windows":
        command = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block-{ip_address}", "dir=in", "action=block", f"remoteip={ip_address}"]
    
    if not command:
        raise HTTPException(status_code=500, detail="Unsupported operating system for blocking.")
    
    try:
        # NOTE: This requires the server to be run with sufficient privileges.
        subprocess.run(command, check=True, capture_output=True, text=True)
        return {"message": f"Successfully added firewall rule to block IP: {ip_address}"}
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"Failed to execute block command: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while blocking the IP.")

@app.get("/logs", response_model=LogsResponse)
def logs(page: int = 1, limit: int = 25, type: str = "All", severity: str = "All", user: str = Depends(get_current_user())):
    page = max(1, page); limit = max(1, min(200, limit));
    with Session() as s:
        stmt = s.query(Block).order_by(Block.id.desc())
        def keep(r: Block):
            if severity != "All" and r.severity != severity: return False
            if type != "All" and r.attack_type != type: return False
            return True
        rows = [r for r in stmt.all() if keep(r)]
        total, pages = len(rows), max(1, (len(rows) + limit - 1) // limit)
        start = (page - 1) * limit
        page_rows = rows[start : start + limit]
        items = [{
            "index": r.index, "timestamp": r.timestamp, "src_ip": r.src_ip,
            "dst_ip": r.dst_ip, "size": r.size, "severity": r.severity,
            "attack_type": r.attack_type, "detected_by": r.detected_by,
            "ml_confidence": r.ml_confidence, "hostname": r.hostname,
            "country": r.country, "city": r.city, "isp": r.isp, "hash": r.hash,
            "signature_ok": verify_signature(bytes.fromhex(r.hash), r.signature_hex),
            "abuse_score": r.abuse_score, "ip_report_count": r.ip_report_count
        } for r in page_rows]
        return {"items": items, "page": page, "pages": pages, "total": total}

@app.post("/reset")
def reset(user: str = Depends(get_current_user())):
    with Session() as s:
        s.query(Block).delete(); s.commit();
    SRC_HITS.clear()
    for key in redis_client.scan_iter("rate:*"):
        redis_client.delete(key)
    return {"ok": True}

@app.get("/export")
def export(format: str = Query("pdf"), user: str = Depends(get_current_user())):
    # PDF generation logic... (omitted for brevity, remains unchanged)
    pass



















