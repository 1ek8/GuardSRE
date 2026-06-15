# agent_core/triage_agent.py
import os
import time
import httpx
from dotenv import load_dotenv
import splunklib.client as client
import splunklib.results as results

# Load our secured environment variables layout configuration
load_dotenv()

def connect_to_splunk():
    """Establishes an administrative management context loop with local Splunk Enterprise."""
    return client.connect(
        host=os.getenv("SPLUNK_HOST", "localhost"),
        port=int(os.getenv("SPLUNK_PORT", 8089)),
        username=os.getenv("SPLUNK_USERNAME", "admin"),
        password=os.getenv("SPLUNK_PASSWORD"),
        app="GuardSRE",      # ◄ Force session into the custom application namespace
        owner="nobody"       # ◄ Direct routing to look for shared default configs
    )

def fetch_recent_anomalies(service):
    """Queries Splunk using the declarative 3-Sigma search definition to catch metric outliers."""
    # Directly invoke the saved search job object defined in savedsearches.conf
    saved_search = service.saved_searches["sre_storage_iops_anomaly"]
    job = saved_search.dispatch()
    
    while not job.is_ready():
        time.sleep(0.5)
        
    search_results = job.results(output_mode="json")
    reader = results.JSONResultsReader(search_results)
    return [record for record in reader if isinstance(record, dict)]

def query_security_context(service, earliest_time):
    """Pulls correlating S3 CloudTrail security events matching the anomaly timeline via MCP framework context."""
    query = f"search index=security_logs earliest={earliest_time} | stats count by userIdentity.arn, eventName, sourceIPAddress, requestParameters.key | sort - count"
    job = service.jobs.create(query, earliest_time="-5m", latest_time="now")
    
    while not job.is_ready():
        time.sleep(0.5)
        
    search_results = job.results(output_mode="json")
    reader = results.JSONResultsReader(search_results)
    return [record for record in reader if isinstance(record, dict)]

def evaluate_with_foundation_sec(telemetry_summary):
    """Routes the cross-domain aggregated telemetry dataset into the local Foundation-Sec model for classification."""
    ollama_url = f"{os.getenv('GCP_LLM_ENDPOINT')}/api/generate"
    
    prompt = f"""
    [CRITICAL EVENT TRIAGE PAYLOAD]
    An automated SRE observability threshold anomaly was confirmed. Review the corresponding data elements:
    
    {telemetry_summary}
    
    Provide an engineering evaluation summarizing:
    1. Threat Classification (Is this a benign scheduled SRE backup routine or an active Ransomware/Data Exfiltration exploit?)
    2. Telemetry Evidence (Reference specific numbers, user identities, and source IPs from the payload)
    3. Actionable Next Move (Provide a clear, brief human-in-the-loop recommendation)
    """
    
    payload = {
        "model": "foundation-sec",
        "prompt": prompt,
        "stream": False
    }
    
    response = httpx.post(ollama_url, json=payload, timeout=60.0)
    return response.json().get("response")

def main():
    print("🛡️ GuardSRE Core Incident Triager Agent Initiated...")
    splunk_service = connect_to_splunk()
    
    while True:
        try:
            print("🔍 Scanning local Splunk metrics telemetry engine for 3-Sigma anomalies...")
            anomalies = fetch_recent_anomalies(splunk_service)
            
            if anomalies:
                print(f"🚨 ALERT! Detected {len(anomalies)} structural infrastructure metric outliers.")
                # Isolate the timeframe to fetch correlating log files
                earliest_stamp = anomalies[0].get("_time", "-2m")
                
                print("🔄 Correlating cross-domain data: Fetching active CloudTrail access vectors...")
                security_records = query_security_context(splunk_service, earliest_stamp)
                
                # Format aggregated findings into structured text block for the LLM context window
                data_summary = f"OBSERVABILITY METRICS OUTLIERS:\n{anomalies[:3]}\n\nSECURITY API LOG ENTRIES:\n{security_records[:5]}"
                
                print("🧠 Dispatching aggregated payload to local Foundation-Sec model engine...")
                evaluation_report = evaluate_with_foundation_sec(data_summary)
                
                print("\n================================================================================")
                print("📋 GUARD_SRE AUTOMATED INCIDENT RESPONSE REPORT")
                print("================================================================================")
                print(evaluation_report)
                print("================================================================================\n")
            else:
                print("🟢 System normal. No active infrastructure performance anomalies identified.")
                
        except Exception as e:
            print(f"⚠️ Agent Loop Exception Encountered: {e}")
            
        time.sleep(10) # Run investigation scans every 10 seconds

if __name__ == "__main__":
    main()