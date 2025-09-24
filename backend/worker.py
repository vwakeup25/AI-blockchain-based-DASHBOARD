import json
from datetime import datetime
import redis
import sys
import os
import time

# --- Adds project folder to Python's path to prevent import errors ---
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Import logic from utils.py ---
from backend.utils import (
    engine, Session, Block, User, SQLModel,
    ml_anomaly_score, severity_and_attack, hostname_of, geo_of,
    calculate_hash, sign_bytes, encrypt_json,
    SRC_HITS, push_rate, get_ip_reputation
)

# --- This is critical for the worker to run independently ---
print("--- Initializing Database Tables (if needed) ---")
SQLModel.metadata.create_all(engine)
print("--- Database Initialized ---")

# --- Configuration ---
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_CHANNEL = 'packet_stream'
ABUSEIPDB_API_KEY = "5b4c4bcf51c6f6729a8096c0cc1c80d1be132116eed7efcd5420a132053c5510c9cb85b65b05ffb3" # TODO: Replace with your key: "YOUR_KEY_HERE"
print("--- Starting Analysis Worker Service (Detection Only) ---")
r_pubsub = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
p = r_pubsub.pubsub(ignore_subscribe_messages=True)
p.subscribe(REDIS_CHANNEL)
print(f"Subscribed to Redis channel '{REDIS_CHANNEL}'")

def process_packet(packet_data: dict):
    """Analyzes each packet and saves it to the database."""
    SRC_HITS[packet_data["src_ip"]] = SRC_HITS.get(packet_data["src_ip"], 0) + 1
    
    abuse_score, report_count = get_ip_reputation(packet_data["src_ip"], ABUSEIPDB_API_KEY)
    
    features = {"size": float(packet_data["size"]), "src_tail": float(int(packet_data["src_ip"].split(".")[-1]))}
    ml_score = ml_anomaly_score(features)
    detected_by = "ML" if ml_score >= 0.6 else "Rule"
    severity, attack_type = severity_and_attack(packet_data, ml_score, SRC_HITS)
    
    if abuse_score and abuse_score > 80:
        if severity != "High":
            severity = "High"
            attack_type = f"High-Risk IP ({report_count} reports)"
            detected_by = "Threat Intel"
        
    host = hostname_of(packet_data["src_ip"])
    country, city, isp = geo_of(packet_data["src_ip"])

    flat = {**packet_data, "severity": severity, "attack_type": attack_type, "detected_by": detected_by, "ml_confidence": ml_score, "hostname": host, "country": country, "city": city, "isp": isp, "abuse_score": abuse_score, "ip_report_count": report_count}

    with Session() as s:
        last = s.query(Block).order_by(Block.id.desc()).first()
        index = (last.index + 1) if last else 0
        ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        prev_hash = last.hash if last else "0"
        data_text = json.dumps(flat, sort_keys=True)
        this_hash = calculate_hash(index, ts_str, data_text, prev_hash)
        sig_hex = sign_bytes(bytes.fromhex(this_hash))
        enc = encrypt_json(packet_data)
        row = Block(
            index=index, timestamp=ts_str, previous_hash=prev_hash, hash=this_hash, 
            signature_hex=sig_hex, src_ip=packet_data["src_ip"], dst_ip=packet_data["dst_ip"], 
            size=packet_data["size"], severity=severity, attack_type=attack_type, 
            detected_by=detected_by, ml_confidence=ml_score, hostname=host, 
            country=country, city=city, isp=isp, enc_data=enc,
            abuse_score=abuse_score, ip_report_count=report_count
        )
        s.add(row)
        s.commit()
    
    push_rate()
    print(f"Processed packet {index}: {packet_data['src_ip']} -> Severity: {severity}")

if __name__ == '__main__':
    print("Listening for packets from Redis...")
    for message in p.listen():
        try:
            packet = json.loads(message['data'])
            process_packet(packet)
        except Exception as e:
            print(f"!!! Error processing message: {e}")
