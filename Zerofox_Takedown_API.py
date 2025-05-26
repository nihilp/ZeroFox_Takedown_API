import argparse
import requests
import sys

# Constants
API_URL = "https://api.zerofox.com/2.0/threat_submit/"
TOKEN = ""  # Replace with actual token
ENTITY_LOOKUP_URL = "https://api.zerofox.com/1.0/entities/"

# Proxy settings - Update as needed
PROXY_SERVER = ""
PROXIES = {
    "http": PROXY_SERVER,
    "https": PROXY_SERVER
}

# Valid options
VALID_TYPES = {"ip", "domain", "url", "phone", "mail_exchange", "page_content", "account", "email"}
VALID_VIOLATIONS = {"phishing", "malware", "rogue_app", "impersonation", "trademark", "private_data", "fraud"}

def get_entities(): 
    """Fetch and print all available entity IDs from ZeroFox."""
    headers = {"Authorization": f"Token {TOKEN}"}
    response = requests.get(ENTITY_LOOKUP_URL, headers=headers, timeout=15, proxies=PROXIES)
    if response.status_code == 200:
        entities = response.json().get("entities", [])
        print("Available Entities:")
        for entity in entities:
            print(f"ID: {entity['id']}, Name: {entity['name']}")
    else:
        print(f"Error fetching entities (HTTP {response.status_code}):", response.text)

def submit_takedown(source, takedown_type, violation, entity_id, notes):
    """Submit a takedown request to ZeroFox."""
    headers = {
        "Authorization": f"Token {TOKEN}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "source": source,
        "alert_type": takedown_type,
        "violation": violation,
        "notes": notes,
        "request_takedown" : True
    }
    
    if entity_id:
        payload["entity_id"] = entity_id
    
    response = requests.post(API_URL, json=payload, headers=headers, timeout=10, proxies=PROXIES)
    
    if response.status_code == 201:
        print("Takedown request submitted successfully.")
        print("Response:", response.json())  # Print full API response for debugging
    else:
        print(f"Error submitting takedown request (HTTP {response.status_code}):", response.text)

def main():
    parser = argparse.ArgumentParser(description="Submit a takedown request to ZeroFox.")
    parser.add_argument("-s", "--source", required=True, help="The source URL, domain, or entity.")
    parser.add_argument("-t", "--type", required=True, choices=[
        "ip", "domain", "url", "phone", "mail_exchange", "page_content", "account", "email"], help="Takedown type.")
    parser.add_argument("-v", "--violation", required=True, choices=[
        "phishing", "malware", "rogue_app", "impersonation", "trademark", "private_data", "fraud"], help="Violation type.")
    parser.add_argument("-id", "--entity_id", required=False, help="Entity ID (if submitting a new indicator).")
    parser.add_argument("-n", "--notes", required=False, default="", help="Additional notes.")
    parser.add_argument("--list-entities", action="store_true", help="List all available entities.")
    
    args = parser.parse_args()
    
    if args.list_entities:
        get_entities()
        sys.exit()
    
    submit_takedown(args.source, args.type, args.violation, args.entity_id, args.notes)

if __name__ == "__main__":
    main()
