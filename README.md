# ZeroFox_Takedown_API
A script to automate the takedown process by utilizing the ZeroFox API with Python.

## Usage
- "-s", "--source", required=True, help="The source URL, domain, or entity."
- "-t", "--type", required=True, choices=["ip", "domain", "url", "phone", "mail_exchange", "page_content", "account", "email"], help="Takedown type."
- "-v", "--violation", required=True, choices=["phishing", "malware", "rogue_app", "impersonation", "trademark", "private_data", "fraud"], help="Violation type."
- "-id", "--entity_id", required=False, help="Entity ID (if submitting a new indicator)."
- "-n", "--notes", required=False, default="", help="Additional notes."
- "--list-entities", action="store_true", help="List all available entities."

## Examples
### Request Takedown of URL
```bash
py Zerofox_Takedown_API.py -s example.domain.com -t domain -v phishing -id "example ID" -n "Example comment."
```

## API Documentation
- https://api.zerofox.com/1.0/docs/
- https://ask.zerofox.com/hc/en-us/articles/14143470473115-Threat-Submission-Tool-API
