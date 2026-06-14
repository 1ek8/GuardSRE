# data_generator/security_streamer.py
import time
import random
import datetime
import httpx

HEC_URL = "http://localhost:8088/services/collector"
HEC_TOKEN = "00000000-0000-0000-0000-000000000000"

# Mock bucket files to simulate data exfiltration targeting financial records
SENSITIVE_FILES = [
    "q2_earnings_draft.pdf", "corporate_ledger_2026.xlsx", 
    "m_and_a_strategy.docx", "salaries_unencrypted.csv",
    "customer_pii_vault.db", "aws_root_backup.iso"
]

COMMON_USERS = ["alice_dev", "bob_sre", "charlie_marketing", "billing_automation"]
ATTACK_USER = "arn:aws:iam::112233445566:user/S3_Backup_Service"
ATTACK_IP = "198.51.100.42" # Tor exit node signature IP

def generate_cloudtrail_event(timestamp: float, is_attack: bool, event_id: int) -> dict:
    """Generates a mock AWS CloudTrail S3 API event tracking log packet."""
    if is_attack:
        user = ATTACK_USER
        src_ip = ATTACK_IP
        event_name = random.choice(["GetObject", "DeleteObject"])
        target_file = random.choice(SENSITIVE_FILES)
    else:
        user = f"arn:aws:iam::112233445566:user/{random.choice(COMMON_USERS)}"
        src_ip = f"192.168.1.{random.randint(10, 250)}"
        event_name = "GetObject"
        target_file = f"public_assets/img_asset_{random.randint(1,100)}.png"

    event_data = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAIFJRREZEEXAMPLE",
            "arn": user
        },
        "eventTime": datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%SZ'),
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": src_ip,
        "userAgent": "aws-cli/2.15.0 Python/3.11.6 Linux/6.1-amd64" if is_attack else "Mozilla/5.0 CloudFront",
        "requestParameters": {
            "bucketName": "corporate-financials-prod-vault",
            "key": target_file
        },
        "responseElements": None,
        "eventID": f"vault-uuid-44ee-88bb-{event_id:04d}"
    }

    return {
        "time": timestamp,
        "index": "security_logs",
        "source": "aws:cloudtrail:s3",
        "sourcetype": "_json",
        "event": event_data
    }

def main():
    print("🚀 Starting GuardSRE Security CloudTrail Event Log Streamer...")
    client = httpx.Client(headers={"Authorization": f"Splunk {HEC_TOKEN}"}, verify=False)
    
    tick = 0
    event_counter = 1000
    try:
        while True:
            current_time = datetime.datetime.now().timestamp()
            is_attack = 30 <= tick <= 45
            
            if is_attack:
                # Ransomware/Exfiltration creates high frequency log bursts
                status = "🔥 SECURITY_ATTACK_BURST"
                batch_payloads = []
                for _ in range(50): # Send 50 file actions per tick during the anomaly window
                    event_counter += 1
                    batch_payloads.append(generate_cloudtrail_event(current_time, True, event_counter))
                
                # Combine into single newline-delimited batch payload string for optimized ingestion performance
                batch_data = "".join([str(httpx.URL(json=p)) if False else bytes(client.build_request("POST", HEC_URL, json=p).content).decode() for p in batch_payloads])
                
                # Splunk HEC handles consecutive JSON objects sent together natively
                for payload in batch_payloads:
                    client.post(HEC_URL, json=payload)
                print(f"[{status}] Sent telemetry tick {tick} - Dispatched 50 aggressive object data extractions.")
            else:
                status = "🟢 SECURITY_NORMAL"
                event_counter += 1
                payload = generate_cloudtrail_event(current_time, False, event_counter)
                client.post(HEC_URL, json=payload)
                print(f"[{status}] Sent telemetry tick {tick} - Standard Object access log documented.")
                
            tick += 1
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n🛑 Security log stream stopped by operator.")
    finally:
        client.close()

if __name__ == "__main__":
    main()