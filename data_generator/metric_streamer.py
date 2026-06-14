# data_generator/metric_streamer.py
import time
import random
import datetime
import httpx

HEC_URL = "http://localhost:8088/services/collector"
HEC_TOKEN = "00000000-0000-0000-0000-000000000000"

def generate_metric_payload(timestamp: float, is_attack: bool) -> dict:
    """Generates a multi-metric payload adhering to Splunk HEC standards."""
    if is_attack:
        # Ransomware encryption behavior: Pegged CPU, massive I/O read/write spikes, fast network egress
        cpu = random.uniform(92.0, 99.8)
        iops_read = random.uniform(12000.0, 15000.0)
        iops_write = random.uniform(8000.0, 11000.0)
        egress = random.uniform(450.0, 600.0)
    else:
        # Baseline enterprise behavior: low, variable background noise
        cpu = random.uniform(15.0, 35.0)
        iops_read = random.uniform(100.0, 400.0)
        iops_write = random.uniform(50.0, 200.0)
        egress = random.uniform(1.0, 8.0)

    return {
        "time": timestamp,
        "index": "infra_metrics",
        "source": "vault_sensor_agent",
        "sourcetype": "metric_json",
        "event": "metric",
        "fields": {
            "metric_name:cpu_percent": round(cpu, 2),
            "metric_name:iops_read": round(iops_read, 2),
            "metric_name:iops_write": round(iops_write, 2),
            "metric_name:network_egress_mbps": round(egress, 2),
            "storage_cluster": "vault-01a",
            "host": "storage-node-prod-01"
        }
    }

def main():
    print("🚀 Starting GuardSRE Infrastructure Metric Streamer...")
    client = httpx.Client(headers={"Authorization": f"Splunk {HEC_TOKEN}"}, verify=False)
    
    tick = 0
    try:
        while True:
            current_time = datetime.datetime.now().timestamp()
            # Trigger attack window between ticks 30 and 45 for live visualization
            is_attack = 30 <= tick <= 45
            
            payload = generate_metric_payload(current_time, is_attack)
            
            try:
                response = client.post(HEC_URL, json=payload)
                if response.status_code == 200:
                    status = "🔥 ATTACK_PHASE" if is_attack else "🟢 NORMAL"
                    print(f"[{status}] Sent telemetry tick {tick} - IOPS Read: {payload['fields']['metric_name:iops_read']}")
                else:
                    print(f"❌ Ingestion Failed: {response.text}")
            except Exception as e:
                print(f"⚠️ Connection Error: {e}")
                
            tick += 1
            time.sleep(2) # Stream every 2 seconds to keep data tight and real-time
    except KeyboardInterrupt:
        print("\n🛑 Stream stopped by operator.")
    finally:
        client.close()

if __name__ == "__main__":
    main()