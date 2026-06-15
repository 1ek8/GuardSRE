# agent_core/triage_agent.py
import os
import time
from datetime import datetime
import httpx
from dotenv import load_dotenv
import splunklib.client as client
import splunklib.results as results

# Force the script to read fresh variables from .env on every execution loop
load_dotenv(override=True)

def connect_to_splunk():
    """Establishes an administrative management context loop with local Splunk Enterprise."""
    return client.connect(
        host=os.getenv("SPLUNK_HOST", "localhost"),
        port=int(os.getenv("SPLUNK_PORT", 8089)),
        username=os.getenv("SPLUNK_USERNAME", "admin"),
        password=os.getenv("SPLUNK_PASSWORD"),
        app="GuardSRE",      # Force session into the custom application namespace
        owner="nobody"       # Direct routing to look for shared default configs
    )

def fetch_recent_anomalies(service):
    """Queries Splunk using the declarative 3-Sigma search definition to catch metric outliers."""
    saved_search = service.saved_searches["sre_storage_iops_anomaly"]
    job = saved_search.dispatch()
    
    while not job.is_ready():
        time.sleep(0.5)
        
    search_results = job.results(output_mode="json")
    reader = results.JSONResultsReader(search_results)
    return [record for record in reader if isinstance(record, dict)]

def query_security_context(service, earliest_time):
    """Pulls correlating S3 CloudTrail security events matching the anomaly timeline via MCP framework context."""
    try:
        dt_obj = datetime.fromisoformat(str(earliest_time))
        # ◄ OPTIMIZATION: Subtract 60 seconds from the epoch timestamp to create a small execution drift buffer
        epoch_time = int(dt_obj.timestamp()) - 60
        print(f"⏰ Expanding security search window back to Epoch: {epoch_time}")
    except ValueError:
        epoch_time = earliest_time

    query = f"search index=security_logs earliest={epoch_time} | stats count by userIdentity.arn, eventName, sourceIPAddress, requestParameters.key | sort - count"
    job = service.jobs.create(query, earliest_time="-5m", latest_time="now")
    
    while not job.is_ready():
        time.sleep(0.5)
        
    search_results = job.results(output_mode="json")
    reader = results.JSONResultsReader(search_results)
    return [record for record in reader if isinstance(record, dict)]

def evaluate_with_foundation_sec(telemetry_summary):
    """Routes the dataset into the local Foundation-Sec model using the structured Chat API endpoint."""
    base_url = os.getenv("GCP_LLM_ENDPOINT", "http://127.0.0.1:11434").strip()
    ollama_chat_url = f"{base_url}/api/chat"  # ◄ Switched to the modern structured chat API
    
    print(f"🔗 Outbound API Request Target: {ollama_chat_url}")
    
    # Structure the payload with explicit message role separations to enforce tokenizer boundaries
    payload = {
        "model": "foundation-sec",
        "messages": [
            {
                "role": "user",
                "content": f"""An automated SRE observability threshold anomaly was confirmed. Review the corresponding data elements:
                
                {telemetry_summary}
                
                Provide an engineering evaluation summarizing:
                1. Threat Classification (Is this a benign scheduled SRE backup routine or an active Ransomware/Data Exfiltration exploit?)
                2. Telemetry Evidence (Reference specific numbers, user identities, and source IPs from the payload)
                3. Actionable Next Move (Provide a clear, brief human-in-the-loop recommendation)"""
            }
        ],
        "stream": False
    }
    
    response = httpx.post(ollama_chat_url, json=payload, timeout=60.0)
    # Extract response text using the standardized chat message JSON layout
    return response.json().get("message", {}).get("content", "").strip()

def main():
    print("🛡️ GuardSRE Core Incident Triager Agent Initiated...")
    splunk_service = connect_to_splunk()
    
    # State tracking variable to prevent duplicate processing loops on the same dataset
    last_triaged_timestamp = None
    
    while True:
        try:
            print("🔍 Scanning local Splunk metrics telemetry engine for 3-Sigma anomalies...")
            anomalies = fetch_recent_anomalies(splunk_service)
            
            if anomalies:
                current_anomaly_time = anomalies[0].get("_time")
                
                # Deduplication Gatekeeper Check
                if current_anomaly_time == last_triaged_timestamp:
                    print("🟢 System normal. Active anomalies have already been triaged. Standing by...")
                    time.sleep(10)
                    continue
                
                print(f"🚨 ALERT! Detected {len(anomalies)} structural infrastructure metric outliers.")
                
                print("🔄 Correlating cross-domain data: Fetching active CloudTrail access vectors...")
                security_records = query_security_context(splunk_service, current_anomaly_time)
                
                data_summary = f"OBSERVABILITY METRICS OUTLIERS:\n{anomalies[:3]}\n\nSECURITY API LOG ENTRIES:\n{security_records[:5]}"
                
                print("🧠 Dispatching aggregated payload to local Foundation-Sec model engine...")
                evaluation_report = evaluate_with_foundation_sec(data_summary)
                
                print("\n================================================================================")
                print("📋 GUARD_SRE AUTOMATED INCIDENT RESPONSE REPORT")
                print("================================================================================")
                print(evaluation_report if evaluation_report else "⚠️ Model returned an empty response layer. Check prompt constraints.")
                print("================================================================================\n")
                
                # Update state variable to lock this specific incident timeframe from double triage
                last_triaged_timestamp = current_anomaly_time
            else:
                print("🟢 System normal. No active infrastructure performance anomalies identified.")
                
        except Exception as e:
            print(f"⚠️ Agent Loop Exception Encountered: {e}")
            
        time.sleep(10)

if __name__ == "__main__":
    main()